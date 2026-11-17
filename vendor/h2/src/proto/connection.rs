use crate::codec::UserError;
use crate::frame::{Reason, StreamId};
use crate::{client, server};

use crate::frame::DEFAULT_INITIAL_WINDOW_SIZE;
use crate::proto::*;

use bytes::Bytes;
use futures_core::Stream;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncRead;

/// An H2 connection
#[derive(Debug)]
pub(crate) struct Connection<T, P, B: Buf = Bytes>
where
    P: Peer,
{
    /// Read / write frame values
    codec: Codec<T, Prioritized<B>>,

    inner: ConnectionInner<P, B>,
}

// Extracted part of `Connection` which does not depend on `T`. Reduces the amount of duplicated
// method instantiations.
#[derive(Debug)]
struct ConnectionInner<P, B: Buf = Bytes>
where
    P: Peer,
{
    /// Tracks the connection level state transitions.
    state: State,

    /// An error to report back once complete.
    ///
    /// This exists separately from State in order to support
    /// graceful shutdown.
    error: Option<frame::GoAway>,

    /// Pending GOAWAY frames to write.
    go_away: GoAway,

    /// A refused stream to reset before receiving another frame.
    pending_refusal: Option<StreamId>,

    /// Ping/pong handler
    ping_pong: PingPong,

    /// Connection settings
    settings: Settings,

    /// Stream state handler
    streams: Streams<B, P>,

    /// A `tracing` span tracking the lifetime of the connection.
    span: tracing::Span,

    /// Client or server
    _phantom: PhantomData<P>,
}

struct DynConnection<'a, B: Buf = Bytes> {
    state: &'a mut State,

    go_away: &'a mut GoAway,

    streams: DynStreams<'a, B>,

    error: &'a mut Option<frame::GoAway>,

    ping_pong: &'a mut PingPong,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub next_stream_id: StreamId,
    pub initial_max_send_streams: usize,
    pub max_send_buffer_size: usize,
    pub reset_stream_duration: Duration,
    pub reset_stream_max: usize,
    pub remote_reset_stream_max: usize,
    pub local_error_reset_streams_max: Option<usize>,
    pub settings: frame::Settings,
    pub data_frame_budget: DataFrameBudget,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DataFrameBudget {
    Auto,
    Configured(usize),
}

impl DataFrameBudget {
    pub(crate) fn resolve(self, connection_window: Option<WindowSize>) -> usize {
        match self {
            Self::Configured(budget) => budget,
            Self::Auto => {
                let window = connection_window.unwrap_or(DEFAULT_INITIAL_WINDOW_SIZE);
                let budget = window as usize / 2;

                budget.max(DEFAULT_DATA_FRAME_BUDGET)
            }
        }
    }

    pub(crate) fn is_auto(self) -> bool {
        matches!(self, Self::Auto)
    }
}

#[derive(Debug)]
enum State {
    /// Currently open in a sane state
    Open,

    /// The codec must be flushed
    Closing(Reason, Initiator),

    /// In a closed state
    Closed(Reason, Initiator),
}

impl<T, P, B> Connection<T, P, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    P: Peer,
    B: Buf,
{
    pub fn new(codec: Codec<T, Prioritized<B>>, config: Config) -> Connection<T, P, B> {
        fn streams_config(config: &Config) -> streams::Config {
            streams::Config {
                initial_max_send_streams: config.initial_max_send_streams,
                local_max_buffer_size: config.max_send_buffer_size,
                local_next_stream_id: config.next_stream_id,
                local_push_enabled: config.settings.is_push_enabled().unwrap_or(true),
                extended_connect_protocol_enabled: config
                    .settings
                    .is_extended_connect_protocol_enabled()
                    .unwrap_or(false),
                local_reset_duration: config.reset_stream_duration,
                local_reset_max: config.reset_stream_max,
                remote_reset_max: config.remote_reset_stream_max,
                remote_init_window_sz: DEFAULT_INITIAL_WINDOW_SIZE,
                remote_max_initiated: config
                    .settings
                    .max_concurrent_streams()
                    .map(|max| max as usize),
                local_max_error_reset_streams: config.local_error_reset_streams_max,
                data_frame_budget: config.data_frame_budget,
            }
        }
        let streams = Streams::new(streams_config(&config));
        let span = tracing::debug_span!(parent: None, "Connection", peer = %P::NAME);
        span.follows_from(tracing::Span::current());
        Connection {
            codec,
            inner: ConnectionInner {
                state: State::Open,
                error: None,
                go_away: GoAway::new(),
                pending_refusal: None,
                ping_pong: PingPong::new(),
                settings: Settings::new(config.settings),
                streams,
                span,
                _phantom: PhantomData,
            },
        }
    }

    /// connection flow control
    pub(crate) fn set_target_window_size(&mut self, size: WindowSize) {
        let _res = self.inner.streams.set_target_connection_window_size(size);
        // TODO: proper error handling
        debug_assert!(_res.is_ok());
    }

    /// Send a new SETTINGS frame with an updated initial window size.
    pub(crate) fn set_initial_window_size(&mut self, size: WindowSize) -> Result<(), UserError> {
        let mut settings = frame::Settings::default();
        settings.set_initial_window_size(Some(size));
        self.inner.settings.send_settings(settings)
    }

    /// Send a new SETTINGS frame with extended CONNECT protocol enabled.
    pub(crate) fn set_enable_connect_protocol(&mut self) -> Result<(), UserError> {
        let mut settings = frame::Settings::default();
        settings.set_enable_connect_protocol(Some(1));
        self.inner.settings.send_settings(settings)
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by this peer.
    pub(crate) fn max_send_streams(&self) -> usize {
        self.inner.streams.max_send_streams()
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by the remote peer.
    pub(crate) fn max_recv_streams(&self) -> usize {
        self.inner.streams.max_recv_streams()
    }

    #[cfg(feature = "unstable")]
    pub fn num_wired_streams(&self) -> usize {
        self.inner.streams.num_wired_streams()
    }

    /// Returns `Ready` when the connection is ready to receive a frame.
    ///
    /// Returns `Error` as this may raise errors that are caused by delayed
    /// processing of received frames.
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        let _e = self.inner.span.enter();
        let span = tracing::trace_span!("poll_ready");
        let _e = span.enter();
        // The order of these calls don't really matter too much
        ready!(self.inner.ping_pong.send_pending_pong(cx, &mut self.codec))?;
        ready!(self.inner.ping_pong.send_pending_ping(cx, &mut self.codec))?;
        ready!(self
            .inner
            .settings
            .poll_send(cx, &mut self.codec, &mut self.inner.streams))?;
        if let Some(id) = self.inner.pending_refusal {
            // Keep the refusal pending if making room requires socket progress.
            ready!(self.codec.poll_ready(cx))?;
            self.inner.streams.count_pending_refusal()?;
            self.codec
                .buffer(frame::Reset::new(id, Reason::REFUSED_STREAM).into())
                .expect("invalid RST_STREAM frame");
            self.inner.pending_refusal = None;
        }

        Poll::Ready(Ok(()))
    }

    /// Send any pending GOAWAY frames.
    ///
    /// This will return `Some(reason)` if the connection should be closed
    /// afterwards. If this is a graceful shutdown, this returns `None`.
    fn poll_go_away(&mut self, cx: &mut Context) -> Poll<Option<io::Result<Reason>>> {
        self.inner.go_away.send_pending_go_away(cx, &mut self.codec)
    }

    pub fn go_away_from_user(&mut self, e: Reason) {
        self.inner.as_dyn().go_away_from_user(e)
    }

    fn take_error(&mut self, ours: Reason, initiator: Initiator) -> Result<(), Error> {
        let (debug_data, theirs) = self
            .inner
            .error
            .take()
            .as_ref()
            .map_or((Bytes::new(), Reason::NO_ERROR), |frame| {
                (frame.debug_data().clone(), frame.reason())
            });

        match (ours, theirs) {
            (Reason::NO_ERROR, Reason::NO_ERROR) => Ok(()),
            (ours, Reason::NO_ERROR) => Err(Error::GoAway(Bytes::new(), ours, initiator)),
            // If both sides reported an error, give their
            // error back to th user. We assume our error
            // was a consequence of their error, and less
            // important.
            (_, theirs) => Err(Error::remote_go_away(debug_data, theirs)),
        }
    }

    /// Closes the connection by transitioning to a GOAWAY state
    /// iff there are no streams or references
    pub fn maybe_close_connection_if_no_streams(&mut self) {
        // If we poll() and realize that there are no streams or references
        // then we can close the connection by transitioning to GOAWAY
        if !self.inner.streams.has_streams_or_other_references() {
            self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
        }
    }

    /// Checks if there are any streams
    pub fn has_streams(&self) -> bool {
        self.inner.streams.has_streams()
    }

    /// Checks if there are any streams or references left
    pub fn has_streams_or_other_references(&self) -> bool {
        // If we poll() and realize that there are no streams or references
        // then we can close the connection by transitioning to GOAWAY
        self.inner.streams.has_streams_or_other_references()
    }

    pub(crate) fn take_user_pings(&mut self) -> Option<UserPings> {
        self.inner.ping_pong.take_user_pings()
    }

    /// Advances the internal state of the connection.
    pub fn poll(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        // XXX(eliza): cloning the span is unfortunately necessary here in
        // order to placate the borrow checker — `self` is mutably borrowed by
        // `poll2`, which means that we can't borrow `self.span` to enter it.
        // The clone is just an atomic ref bump.
        let span = self.inner.span.clone();
        let _e = span.enter();
        let span = tracing::trace_span!("poll");
        let _e = span.enter();

        loop {
            tracing::trace!(connection.state = ?self.inner.state);
            // TODO: probably clean up this glob of code
            match self.inner.state {
                // When open, continue to poll a frame
                State::Open => {
                    let result = match self.poll2(cx) {
                        Poll::Ready(result) => result,
                        // The connection is not ready to make progress
                        Poll::Pending => {
                            // Ensure all window updates have been sent.
                            //
                            // This will also handle flushing `self.codec`
                            ready!(self.inner.streams.poll_complete(cx, &mut self.codec))?;

                            if (self.inner.error.is_some()
                                || self.inner.go_away.should_close_on_idle())
                                && !self.inner.streams.has_streams()
                            {
                                self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
                                continue;
                            }

                            return Poll::Pending;
                        }
                    };

                    self.inner.as_dyn().handle_poll2_result(result)?
                }
                State::Closing(reason, initiator) => {
                    tracing::trace!("connection closing after flush");
                    // Flush/shutdown the codec
                    ready!(self.codec.shutdown(cx))?;

                    // Transition the state to error
                    self.inner.state = State::Closed(reason, initiator);
                }
                State::Closed(reason, initiator) => {
                    return Poll::Ready(self.take_error(reason, initiator));
                }
            }
        }
    }

    fn poll2(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        // This happens outside of the loop to prevent needing to do a clock
        // check and then comparison of the queue possibly multiple times a
        // second (and thus, the clock wouldn't have changed enough to matter).
        self.clear_expired_reset_streams();

        loop {
            // First, ensure that the `Connection` is able to receive a frame
            //
            // The order here matters:
            // - poll_go_away may buffer a graceful shutdown GOAWAY frame
            // - If it has, we've also added a PING to be sent in poll_ready
            if let Some(reason) = ready!(self.poll_go_away(cx)?) {
                if self.inner.go_away.should_close_now() {
                    if self.inner.go_away.is_user_initiated() {
                        // A user initiated abrupt shutdown shouldn't return
                        // the same error back to the user.
                        return Poll::Ready(Ok(()));
                    } else {
                        return Poll::Ready(Err(Error::library_go_away(reason)));
                    }
                }
                // Only NO_ERROR should be waiting for idle
                debug_assert_eq!(
                    reason,
                    Reason::NO_ERROR,
                    "graceful GOAWAY should be NO_ERROR"
                );
            }
            ready!(self.poll_ready(cx))?;

            match self
                .inner
                .as_dyn()
                .recv_frame(ready!(Pin::new(&mut self.codec).poll_next(cx)?))?
            {
                ReceivedFrame::Settings(frame) => {
                    self.inner.settings.recv_settings(
                        frame,
                        &mut self.codec,
                        &mut self.inner.streams,
                    )?;
                }
                ReceivedFrame::Refused(id) => {
                    debug_assert!(self.inner.pending_refusal.is_none());
                    self.inner.pending_refusal = Some(id);
                }
                ReceivedFrame::Continue => (),
                ReceivedFrame::Done => {
                    return Poll::Ready(Ok(()));
                }
            }

            // [本仓 patch] 尽力 flush，非门控：读侧排空中途（逐帧）把已积压的出站
            // 帧（生产者 DATA / 消费回填 WINDOW_UPDATE）按批推上线，不再滞留到
            // 排空拖尾。Pending 只吞不传播——codec 已注册写就绪 waker，滞留帧由
            // 既有 Pending 臂收尾，读循环永不因写堵中断（h2#975 镜像面）；错误仍
            // 传播。禁改回 `ready!` 透传：`flush_gate` 钉桩测试会红（见 REBASE.md）。
            if let Poll::Ready(res) = self.inner.streams.poll_complete(cx, &mut self.codec) {
                res?;
            }
        }
    }

    fn clear_expired_reset_streams(&mut self) {
        self.inner.streams.clear_expired_reset_streams();
    }
}

impl<P, B> ConnectionInner<P, B>
where
    P: Peer,
    B: Buf,
{
    fn as_dyn(&mut self) -> DynConnection<'_, B> {
        let ConnectionInner {
            state,
            go_away,
            streams,
            error,
            ping_pong,
            ..
        } = self;
        let streams = streams.as_dyn();
        DynConnection {
            state,
            go_away,
            streams,
            error,
            ping_pong,
        }
    }
}

impl<B> DynConnection<'_, B>
where
    B: Buf,
{
    fn go_away(&mut self, id: StreamId, e: Reason) {
        let frame = frame::GoAway::new(id, e);
        self.streams.send_go_away(id);
        self.go_away.go_away(frame);
    }

    fn go_away_now(&mut self, e: Reason) {
        let last_processed_id = self.streams.last_processed_id();
        let frame = frame::GoAway::new(last_processed_id, e);
        self.go_away.go_away_now(frame);
    }

    fn go_away_now_data(&mut self, e: Reason, data: Bytes) {
        let last_processed_id = self.streams.last_processed_id();
        let frame = frame::GoAway::with_debug_data(last_processed_id, e, data);
        self.go_away.go_away_now(frame);
    }

    fn go_away_from_user(&mut self, e: Reason) {
        let last_processed_id = self.streams.last_processed_id();
        let frame = frame::GoAway::new(last_processed_id, e);
        self.go_away.go_away_from_user(frame);

        // Notify all streams of reason we're abruptly closing.
        self.streams.handle_error(Error::user_go_away(e));
    }

    fn handle_poll2_result(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        match result {
            // The connection has shutdown normally
            Ok(()) => {
                *self.state = State::Closing(Reason::NO_ERROR, Initiator::Library);
                Ok(())
            }
            // Attempting to read a frame resulted in a connection level
            // error. This is handled by setting a GOAWAY frame followed by
            // terminating the connection.
            Err(Error::GoAway(debug_data, reason, initiator)) => {
                self.handle_go_away(reason, debug_data, initiator);
                Ok(())
            }
            // Attempting to read a frame resulted in a stream level error.
            // Locally detected stream errors are reported to the peer with
            // RST_STREAM. Remotely initiated resets have already been applied
            // by the streams state machine and must not be echoed back.
            Err(Error::Reset(id, reason, initiator)) => {
                if initiator == Initiator::Remote {
                    tracing::trace!(?id, ?reason, ?initiator, "stream reset");
                    return Ok(());
                }

                debug_assert_eq!(initiator, Initiator::Library);
                tracing::trace!(?id, ?reason, ?initiator, "stream error");
                match self.streams.send_reset(id, reason) {
                    Ok(()) => (),
                    Err(crate::proto::error::GoAway { debug_data, reason }) => {
                        self.handle_go_away(reason, debug_data, Initiator::Library);
                    }
                }
                Ok(())
            }
            // Attempting to read a frame resulted in an I/O error. All
            // active streams must be reset.
            //
            // TODO: Are I/O errors recoverable?
            Err(Error::Io(kind, inner)) => {
                tracing::debug!(error = ?kind, "Connection::poll; IO error");
                let e = Error::Io(kind, inner);

                // Reset all active streams
                self.streams.handle_error(e.clone());

                // Some client implementations drop the connections without notifying its peer
                // Attempting to read after the client dropped the connection results in UnexpectedEof
                // If as a server, we don't have anything more to send, just close the connection
                // without error
                //
                // See https://github.com/hyperium/hyper/issues/3427
                if self.streams.is_buffer_empty()
                    && matches!(kind, io::ErrorKind::UnexpectedEof)
                    && (self.streams.is_server()
                        || self.error.as_ref().map(|f| f.reason() == Reason::NO_ERROR)
                            == Some(true))
                {
                    *self.state = State::Closed(Reason::NO_ERROR, Initiator::Library);
                    return Ok(());
                }

                // Return the error
                Err(e)
            }
        }
    }

    fn handle_go_away(&mut self, reason: Reason, debug_data: Bytes, initiator: Initiator) {
        let e = Error::GoAway(debug_data.clone(), reason, initiator);
        tracing::debug!(error = ?e, "Connection::poll; connection error");

        // We may have already sent a GOAWAY for this error,
        // if so, don't send another, just flush and close up.
        if self
            .go_away
            .going_away()
            .map_or(false, |frame| frame.reason() == reason)
        {
            tracing::trace!("    -> already going away");
            *self.state = State::Closing(reason, initiator);
            return;
        }

        // Reset all active streams
        self.streams.handle_error(e);
        self.go_away_now_data(reason, debug_data);
    }

    fn recv_frame(&mut self, frame: Option<Frame>) -> Result<ReceivedFrame, Error> {
        use crate::frame::Frame::*;
        match frame {
            Some(Headers(frame)) => {
                tracing::trace!(?frame, "recv HEADERS");
                match self.streams.recv_headers(frame)? {
                    streams::RecvOutcome::Processed => (),
                    streams::RecvOutcome::Refused(id) => return Ok(ReceivedFrame::Refused(id)),
                }
            }
            Some(Data(frame)) => {
                tracing::trace!(?frame, "recv DATA");
                self.streams.recv_data(frame)?;
            }
            Some(Reset(frame)) => {
                tracing::trace!(?frame, "recv RST_STREAM");
                self.streams.recv_reset(frame)?;
            }
            Some(PushPromise(frame)) => {
                tracing::trace!(?frame, "recv PUSH_PROMISE");
                match self.streams.recv_push_promise(frame)? {
                    streams::RecvOutcome::Processed => (),
                    streams::RecvOutcome::Refused(id) => return Ok(ReceivedFrame::Refused(id)),
                }
            }
            Some(Settings(frame)) => {
                tracing::trace!(?frame, "recv SETTINGS");
                return Ok(ReceivedFrame::Settings(frame));
            }
            Some(GoAway(frame)) => {
                tracing::trace!(?frame, "recv GOAWAY");
                // This should prevent starting new streams,
                // but should allow continuing to process current streams
                // until they are all EOS. Once they are, State should
                // transition to GoAway.
                self.streams.recv_go_away(&frame)?;
                *self.error = Some(frame);
            }
            Some(Ping(frame)) => {
                tracing::trace!(?frame, "recv PING");
                let status = self.ping_pong.recv_ping(frame);
                if status.is_shutdown() {
                    assert!(
                        self.go_away.is_going_away(),
                        "received unexpected shutdown ping"
                    );

                    let last_processed_id = self.streams.last_processed_id();
                    self.go_away(last_processed_id, Reason::NO_ERROR);
                }
            }
            Some(WindowUpdate(frame)) => {
                tracing::trace!(?frame, "recv WINDOW_UPDATE");
                self.streams.recv_window_update(frame)?;
            }
            Some(Priority(frame)) => {
                tracing::trace!(?frame, "recv PRIORITY");
                // TODO: handle
            }
            None => {
                tracing::trace!("codec closed");
                self.streams.recv_eof(false).expect("mutex poisoned");
                return Ok(ReceivedFrame::Done);
            }
        }
        Ok(ReceivedFrame::Continue)
    }
}

enum ReceivedFrame {
    Refused(StreamId),
    Settings(frame::Settings),
    Continue,
    Done,
}

impl<T, B> Connection<T, client::Peer, B>
where
    T: AsyncRead + AsyncWrite,
    B: Buf,
{
    pub(crate) fn streams(&self) -> &Streams<B, client::Peer> {
        &self.inner.streams
    }
}

impl<T, B> Connection<T, server::Peer, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    pub fn next_incoming(&mut self) -> Option<StreamRef<B>> {
        self.inner.streams.next_incoming()
    }

    // Graceful shutdown only makes sense for server peers.
    pub fn go_away_gracefully(&mut self) {
        if self.inner.go_away.is_going_away() {
            // No reason to start a new one.
            return;
        }

        // According to http://httpwg.org/specs/rfc7540.html#GOAWAY:
        //
        // > A server that is attempting to gracefully shut down a connection
        // > SHOULD send an initial GOAWAY frame with the last stream
        // > identifier set to 2^31-1 and a NO_ERROR code. This signals to the
        // > client that a shutdown is imminent and that initiating further
        // > requests is prohibited. After allowing time for any in-flight
        // > stream creation (at least one round-trip time), the server can
        // > send another GOAWAY frame with an updated last stream identifier.
        // > This ensures that a connection can be cleanly shut down without
        // > losing requests.
        self.inner.as_dyn().go_away(StreamId::MAX, Reason::NO_ERROR);

        // We take the advice of waiting 1 RTT literally, and wait
        // for a pong before proceeding.
        self.inner.ping_pong.ping_shutdown();
    }
}

impl<T, P, B> Drop for Connection<T, P, B>
where
    P: Peer,
    B: Buf,
{
    fn drop(&mut self) {
        // Ignore errors as this indicates that the mutex is poisoned.
        let _ = self.inner.streams.recv_eof(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_data_frame_budget_scales_with_connection_window() {
        assert_eq!(
            DataFrameBudget::Auto.resolve(None),
            DEFAULT_INITIAL_WINDOW_SIZE as usize / 2
        );
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(DEFAULT_INITIAL_WINDOW_SIZE)),
            DEFAULT_INITIAL_WINDOW_SIZE as usize / 2
        );
        assert_eq!(DataFrameBudget::Auto.resolve(Some(1024 * 1024)), 512 * 1024);
    }

    #[test]
    fn auto_data_frame_budget_has_minimum() {
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(1)),
            DEFAULT_DATA_FRAME_BUDGET
        );
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(MAX_WINDOW_SIZE)),
            MAX_WINDOW_SIZE as usize / 2
        );
    }

    #[test]
    fn configured_data_frame_budget_is_unchanged() {
        assert_eq!(
            DataFrameBudget::Configured(123).resolve(Some(MAX_WINDOW_SIZE)),
            123
        );
    }
}

// [本仓 patch · C2 钉桩] Ready 臂非门控 flush 的三场景行为测试（campaign-plan §2）。
// 与 flush hunk 同文件共存：上游升级整文件覆盖时会连带删掉本模块，重放 hunk 时
// 必须整块带回（见 vendor/h2/REBASE.md 升级流程）；`flush_gate_bundles_...` 反向
// 引用 flow_control 阈值 patch，两侧任一被覆盖/回档都必红。
#[cfg(test)]
mod flush_gate {
    use crate::client::{self, Builder};
    use crate::proto::streams::flow_control::window_update_threshold;
    use crate::share::{RecvStream, SendStream};
    use bytes::{Bytes, BytesMut};
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    type ClientConn = client::Connection<SharedIo, Bytes>;

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const FRAME_HEADER_LEN: usize = 9;
    // 帧 payload 取 8 KiB（< 16 KiB 上游缺省帧上限）：突发 4 帧共 32 KiB，使
    // 「喂下一突发」时收窗余量在门控/非门控两种实现下都不触 FLOW_CONTROL，
    // 让钉桩差异只落在 flush 时序上。
    const FRAME_PAYLOAD: usize = 8 * 1024;
    /// 每突发帧数（4 × 8 KiB = 32 KiB）。
    const BURST_FRAMES: usize = 4;

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    /// 手工可操控的连接 io 状态体：
    /// - 每次 poll_read 至多吐一帧 ⇒ 「读侧持续 Ready」被拉伸成多个 poll 周期；
    /// - 每次 poll_read 前对 written 做快照 ⇒ 可断言 WU 在排空中途（而非拖尾）上线；
    /// - write_blocked ⇒ poll_write 恒 Pending（模拟对端不收，codec 已注册写 waker）。
    struct MockIo {
        read: BytesMut,
        written: BytesMut,
        write_blocked: bool,
        read_snapshots: Vec<usize>,
    }

    impl MockIo {
        fn poll_read_inner(&mut self, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let snapshot = self.written.len();
            self.read_snapshots.push(snapshot);
            if self.read.is_empty() {
                return Poll::Pending;
            }
            let n = (FRAME_PAYLOAD + FRAME_HEADER_LEN)
                .min(self.read.len())
                .min(buf.remaining());
            buf.put_slice(&self.read.split_to(n));
            Poll::Ready(Ok(()))
        }

        fn poll_write_inner(&mut self, buf: &[u8]) -> Poll<io::Result<usize>> {
            if self.write_blocked {
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
    }

    /// 连接构造后即拥有 io，测试侧经此句柄继续喂帧/观测 written。
    /// 单线程测试、poll 方法同步返回，锁不跨 await。
    #[derive(Clone)]
    struct SharedIo(Arc<Mutex<MockIo>>);

    impl SharedIo {
        fn new() -> Self {
            SharedIo(Arc::new(Mutex::new(MockIo {
                read: BytesMut::new(),
                written: BytesMut::new(),
                write_blocked: false,
                read_snapshots: Vec::new(),
            })))
        }

        fn feed(&self, frame: &[u8]) {
            self.0.lock().unwrap().read.extend_from_slice(frame);
        }

        fn set_write_blocked(&self, blocked: bool) {
            self.0.lock().unwrap().write_blocked = blocked;
        }

        fn clear_snapshots(&self) {
            self.0.lock().unwrap().read_snapshots.clear();
        }

        /// 钉 C2 判据：某次 poll_read 的 written 快照（第 1 次及以后）已含 WU ⇒
        /// WU 在读侧排空中途上线。上游缺陷（滞留到 Pending 臂拖尾）下，所有快照
        /// 均不含 WU——WU 只会写在最后一次 poll_read 之后。
        fn assert_wu_seen_mid_drain(&self) {
            let io = self.0.lock().unwrap();
            for &snap in io.read_snapshots.iter().skip(1) {
                if count_window_updates(&io.written[..snap]) > 0 {
                    return;
                }
            }
            panic!(
                "WINDOW_UPDATE never reached the wire mid-drain while inbound frames remained \
                 (flush hunk lost?); written={} bytes, read_snapshots={:?}",
                io.written.len(),
                io.read_snapshots
            );
        }
    }

    impl AsyncRead for SharedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0.lock().unwrap().poll_read_inner(buf)
        }
    }

    impl AsyncWrite for SharedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().poll_write_inner(buf)
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn frame_bytes(typ: u8, flags: u8, sid: u32, payload: &[u8]) -> Bytes {
        let mut out = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
        let len = payload.len() as u32;
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        out.extend_from_slice(&[typ, flags]);
        out.extend_from_slice(&sid.to_be_bytes());
        out.extend_from_slice(payload);
        out.freeze()
    }

    fn empty_settings() -> Bytes {
        frame_bytes(0x4, 0x0, 0, &[])
    }

    fn data_frame(payload: &[u8]) -> Bytes {
        frame_bytes(0x0, 0x0, 1, payload)
    }

    /// 响应 HEADERS：HPACK 字面量（不索引、不哈夫曼）`:status: 200`，END_HEADERS。
    fn response_headers() -> Bytes {
        frame_bytes(
            0x1,
            0x4,
            1,
            &[
                0x00, 0x07, b':', b's', b't', b'a', b't', b'u', b's', 0x03, b'2', b'0', b'0',
            ],
        )
    }

    /// 统计已写字节流里的 WINDOW_UPDATE 帧数（跳过 client preface 后逐帧扫描）。
    fn count_window_updates(bytes: &[u8]) -> usize {
        if bytes.len() <= PREFACE.len() {
            return 0;
        }
        let mut buf = &bytes[PREFACE.len()..];
        let mut n = 0;
        while buf.len() >= FRAME_HEADER_LEN {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < FRAME_HEADER_LEN + len {
                break;
            }
            if buf[3] == 0x8 {
                n += 1;
            }
            buf = &buf[FRAME_HEADER_LEN + len..];
        }
        n
    }

    fn handshake_client(
        cx: &mut Context<'_>,
        io: &SharedIo,
    ) -> (client::SendRequest<Bytes>, Pin<Box<ClientConn>>) {
        io.feed(&empty_settings());
        let mut handshake = Box::pin(Builder::new().handshake(io.clone()));
        let (send_request, conn) = match handshake.as_mut().poll(cx) {
            Poll::Ready(Ok(pair)) => pair,
            Poll::Ready(Err(e)) => panic!("handshake failed: {e}"),
            Poll::Pending => panic!("handshake unexpectedly pending"),
        };
        (send_request, Pin::new(Box::new(conn)) as Pin<Box<ClientConn>>)
    }

    fn drive(cx: &mut Context<'_>, conn: &mut Pin<Box<ClientConn>>) {
        match conn.as_mut().poll(cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => panic!("connection finished unexpectedly"),
            Poll::Ready(Err(e)) => panic!("connection errored: {e}"),
        }
    }

    fn open_get(
        cx: &mut Context<'_>,
        send_request: &mut client::SendRequest<Bytes>,
        end_of_stream: bool,
    ) -> (
        Pin<Box<client::ResponseFuture>>,
        SendStream<Bytes>,
    ) {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.com/")
            .body(())
            .unwrap();
        assert!(send_request.poll_ready(cx).is_ready());
        let (resp_fut, send_stream) = send_request.send_request(req, end_of_stream).unwrap();
        (Pin::new(Box::new(resp_fut)), send_stream)
    }

    fn await_response(
        cx: &mut Context<'_>,
        conn: &mut Pin<Box<ClientConn>>,
        resp_fut: &mut Pin<Box<client::ResponseFuture>>,
    ) -> RecvStream {
        for _ in 0..16 {
            drive(cx, conn);
            if let Poll::Ready(Ok(resp)) = resp_fut.as_mut().poll(cx) {
                return resp.into_body();
            }
        }
        panic!("response never arrived");
    }

    /// 消费全部已就绪 chunk 并逐块 release_capacity（= hyper 泵的回填动作）。
    fn pump(cx: &mut Context<'_>, body: &mut RecvStream) -> usize {
        let mut total = 0;
        loop {
            match body.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    total += chunk.len();
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .expect("release capacity");
                }
                Poll::Ready(Some(Err(e))) => panic!("recv error: {e}"),
                _ => break,
            }
        }
        total
    }

    /// 断言客户端请求 HEADERS 已排空上线（在喂响应帧之前——服务端不可能在
    /// 未见请求前响应；测试必须复刻这一物理顺序，否则 h2 会按 idle-stream
    /// 协议错误拒收）。
    fn assert_request_sent(io: &SharedIo) {
        let io0 = io.0.lock().unwrap();
        let mut buf = &io0.written[..];
        if buf.len() > PREFACE.len() {
            buf = &buf[PREFACE.len()..];
        } else {
            panic!("client preface missing");
        }
        while buf.len() >= FRAME_HEADER_LEN {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < FRAME_HEADER_LEN + len {
                break;
            }
            if buf[3] == 0x1 {
                return;
            }
            buf = &buf[FRAME_HEADER_LEN + len..];
        }
        panic!("request HEADERS never flushed; written={}", io0.written.len());
    }

    /// 场景①：单向大流量——读侧仍有待读帧时，消费回填的 WU 必须在下一两个
    /// poll 周期内上线（上游缺陷 = 滞留到排空拖尾/空窗）。
    #[test]
    fn flush_gate_wu_reaches_wire_while_read_side_hot() {
        let waker = Waker::from(Arc::new(NoopWake));
        let cx = &mut Context::from_waker(&waker);
        let io = &SharedIo::new();
        let (mut send_request, mut conn) = handshake_client(cx, io);
        let (mut resp_fut, _send_stream) = open_get(cx, &mut send_request, true);
        // 先驱动一轮：请求 HEADERS 上线 + 服务端 SETTINGS 消化，之后才可能收到响应。
        drive(cx, &mut conn);
        assert_request_sent(io);

        // 服务端突发：响应头 + 4 帧（32 KiB）。
        io.feed(&response_headers());
        for _ in 0..BURST_FRAMES {
            io.feed(&data_frame(&[0u8; FRAME_PAYLOAD]));
        }
        let mut body = await_response(cx, &mut conn, &mut resp_fut);
        // 泵掉突发并回填（WU 进 pending 队列；window_size 在 WU 上线时才回涨）。
        assert!(pump(cx, &mut body) > 0, "consumer must have data");

        // 读侧仍热：WU 还挂在队列里时紧接着喂下一突发——断言驱动的排空中途
        // WU 必须上线（上游缺陷：滞留到 Pending 臂拖尾，任何快照都不含 WU）。
        for _ in 0..BURST_FRAMES {
            io.feed(&data_frame(&[0u8; FRAME_PAYLOAD]));
        }
        io.clear_snapshots();
        drive(cx, &mut conn);
        io.assert_wu_seen_mid_drain();
        drive(cx, &mut conn); // 连接仍活
    }

    /// 场景②：双向慢读者——写堵（对端不收）+ 读侧持续有帧 ⇒ 读侧必须持续推进、
    /// 任务不停摆。门控实现（`ready!` 透传）= 每次外部 poll 只吞 1 帧 ⇒ 排空
    /// 不到一半即红。
    #[test]
    fn flush_gate_read_side_progresses_while_write_blocked() {
        let waker = Waker::from(Arc::new(NoopWake));
        let cx = &mut Context::from_waker(&waker);
        let io = &SharedIo::new();
        let (mut send_request, mut conn) = handshake_client(cx, io);
        let (mut resp_fut, _send_stream) = open_get(cx, &mut send_request, true);
        drive(cx, &mut conn);
        assert_request_sent(io);
        // 请求已上线后再堵写：模拟对端不收、本端编码器与 socket 写侧拥堵。
        io.set_write_blocked(true);

        io.feed(&response_headers());
        let mut body = None;
        let mut total = 0;
        for round in 0..4 {
            for _ in 0..2 {
                io.feed(&data_frame(&[0u8; FRAME_PAYLOAD]));
            }
            drive(cx, &mut conn);
            if body.is_none() {
                body = Some(await_response(cx, &mut conn, &mut resp_fut));
            }
            total += pump(cx, &mut body.as_mut().unwrap());
            // 回填 WU 随下一轮驱动的 poll_complete 上线，窗与消费同步推进。
            drive(cx, &mut conn);
            assert!(
                total >= (round + 1) * 2 * FRAME_PAYLOAD,
                "read side stalled at round {round} with {total} bytes while writes were blocked"
            );
        }
        assert_eq!(total, 8 * FRAME_PAYLOAD, "read side must fully drain");
        drive(cx, &mut conn); // 连接仍活：写堵不杀读侧
    }
    /// 场景③：控制帧饿死上界——生产者持续灌 DATA（编码器忙）+ 消费回填 WU +
    /// 读侧热 ⇒ WU 不得无限滞留：仍须在排空中途上线（上界 = 一个 poll 周期）。
    #[test]
    fn flush_gate_control_frames_not_starved_behind_data() {
        let waker = Waker::from(Arc::new(NoopWake));
        let cx = &mut Context::from_waker(&waker);
        let io = &SharedIo::new();
        let (mut send_request, mut conn) = handshake_client(cx, io);
        let (mut resp_fut, mut send_stream) = open_get(cx, &mut send_request, false);

        // 生产者灌 512 KiB（send_buffer 缺省上界内），期间连接随时驱动。
        send_stream.reserve_capacity(512 * 1024);
        let mut sent = 0;
        for _ in 0..256 {
            match send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(n))) => {
                    send_stream
                        .send_data(Bytes::from(vec![0u8; n]), false)
                        .unwrap();
                    sent += n;
                    if sent >= 512 * 1024 {
                        break;
                    }
                }
                Poll::Ready(Some(Err(e))) => panic!("send error: {e}"),
                Poll::Ready(None) => panic!("send stream closed unexpectedly"),
                Poll::Pending => drive(cx, &mut conn),
            }
        }
        assert!(sent > 0, "producer must queue data");
        drive(cx, &mut conn);
        assert_request_sent(io);

        io.feed(&response_headers());
        for _ in 0..BURST_FRAMES {
            io.feed(&data_frame(&[0u8; FRAME_PAYLOAD]));
        }
        let mut body = await_response(cx, &mut conn, &mut resp_fut);
        // 泵掉突发并回填（WU 挂 pending 队列）。
        assert!(pump(cx, &mut body) > 0, "consumer must have data");

        // 编码器被生产者 DATA 占着的状态下，读侧保持热 + WU 挂队 ⇒
        // 下一驱动周期的排空中途 WU 必须上线（上界 = 一个 poll 周期）。
        for _ in 0..BURST_FRAMES {
            io.feed(&data_frame(&[0u8; FRAME_PAYLOAD]));
        }
        io.clear_snapshots();
        drive(cx, &mut conn);
        io.assert_wu_seen_mid_drain();
        drive(cx, &mut conn);
    }

    /// 捆绑断言：C2 钉桩直接引用 flow_control 阈值 patch 的符号——阈值 patch
    /// 被上游升级覆盖（回档 window/2）时本测试编译期即红；反向（只回档 flush
    /// hunk、保留阈值）时三场景行为测试红。两侧必须同时在场。
    #[test]
    fn flush_gate_bundles_flow_control_threshold_patch() {
        assert_eq!(window_update_threshold(32 * 1024 * 1024), 4 * 1024);
        assert_eq!(window_update_threshold(4 * 1024), 2 * 1024);
    }
}
