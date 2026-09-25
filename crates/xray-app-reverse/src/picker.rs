//! StaticMuxPicker：最少连接选择算法。
//!
//! 对应 Go `app/reverse/portal.go` 的 `StaticMuxPicker`。
//! 纯算法可独立测试，不依赖 mux/pipe。

use parking_lot::Mutex;

use crate::error::ReverseError;

/// Picker worker trait：暴露 worker 状态给 picker 选择算法。
///
/// 对应 Go `PortalWorker` 的 `IsFull` / `Closed` / `ActiveConnections` / `draining`。
pub trait PickerWorker: Send + Sync {
    /// 是否已满（达到最大连接数）。
    fn is_full(&self) -> bool;

    /// 是否已关闭。
    fn is_closed(&self) -> bool;

    /// 是否处于 drain 状态（不再接收新连接）。
    fn is_draining(&self) -> bool;

    /// 当前活跃连接数（用于最少连接选择）。
    fn active_connections(&self) -> u32;
}

/// StaticMuxPicker：从一组 worker 中选择最少连接的非满 worker。
///
/// 对应 Go `StaticMuxPicker.PickAvailable`：
/// 1. 优先选择 draining=false 且 !IsFull 且 !Closed 的最少连接 worker
/// 2. 若无候选，再选 IsFull=false 的最少连接（含 draining）
/// 3. 仍无 → 返回 Err
pub struct StaticMuxPicker<W: PickerWorker> {
    workers: Mutex<Vec<W>>,
}

impl<W: PickerWorker> StaticMuxPicker<W> {
    pub fn new() -> Self {
        Self { workers: Mutex::new(Vec::new()) }
    }

    /// 添加 worker。
    pub fn add_worker(&self, worker: W) {
        self.workers.lock().push(worker);
    }

    /// 当前 worker 数量。
    pub fn len(&self) -> usize {
        self.workers.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.lock().is_empty()
    }

    /// 清理已关闭的 worker（对应 Go `cleanup`）。
    pub fn cleanup(&self) {
        let mut g = self.workers.lock();
        g.retain(|w| !w.is_closed());
    }

    /// 选择最少连接的非满 worker（不可变借用返回 snapshot 索引）。
    ///
    /// 返回选中 worker 在队列中的索引（供调用方按需索引具体 worker）。
    /// 若队列空返回 EmptyWorkerList；无可用返回 NoWorkerAvailable。
    pub fn pick_available_index(&self) -> Result<usize, ReverseError> {
        let g = self.workers.lock();
        if g.is_empty() {
            return Err(ReverseError::EmptyWorkerList);
        }

        // Pass 1：draining=false, !is_full, !is_closed
        let mut best_idx: Option<usize> = None;
        let mut best_conn: u32 = u32::MAX;
        for (i, w) in g.iter().enumerate() {
            if w.is_closed() || w.is_draining() || w.is_full() {
                continue;
            }
            let conn = w.active_connections();
            if conn < best_conn {
                best_conn = conn;
                best_idx = Some(i);
            }
        }

        // Pass 2：!is_full（允许 draining）
        if best_idx.is_none() {
            for (i, w) in g.iter().enumerate() {
                if w.is_closed() || w.is_full() {
                    continue;
                }
                let conn = w.active_connections();
                if conn < best_conn {
                    best_conn = conn;
                    best_idx = Some(i);
                }
            }
        }

        best_idx.ok_or(ReverseError::NoWorkerAvailable)
    }

    /// 选择并克隆最少连接 worker（生产路径：`W = Arc<PortalWorker>`）。
    pub fn pick_available(&self) -> Result<W, ReverseError>
    where
        W: Clone,
    {
        let idx = self.pick_available_index()?;
        Ok(self.workers.lock()[idx].clone())
    }

    /// 取不可变借用 snapshot：所有 worker 的元信息（用于测试）。
    pub fn snapshot(&self) -> Vec<WorkerSnapshot> {
        self.workers
            .lock()
            .iter()
            .map(|w| WorkerSnapshot {
                is_full: w.is_full(),
                is_closed: w.is_closed(),
                is_draining: w.is_draining(),
                active_connections: w.active_connections(),
            })
            .collect()
    }
}

impl<W: PickerWorker> Default for StaticMuxPicker<W> {
    fn default() -> Self {
        Self::new()
    }
}

/// Worker 状态快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSnapshot {
    pub is_full: bool,
    pub is_closed: bool,
    pub is_draining: bool,
    pub active_connections: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWorker {
        full: bool,
        closed: bool,
        draining: bool,
        conn: u32,
    }

    impl PickerWorker for MockWorker {
        fn is_full(&self) -> bool {
            self.full
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn is_draining(&self) -> bool {
            self.draining
        }

        fn active_connections(&self) -> u32 {
            self.conn
        }
    }

    fn mk(conn: u32) -> MockWorker {
        MockWorker { full: false, closed: false, draining: false, conn }
    }

    #[test]
    fn empty_picker_returns_empty_worker_list() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        let err = p.pick_available_index().unwrap_err();
        assert!(matches!(err, ReverseError::EmptyWorkerList));
    }

    #[test]
    fn single_worker_picked() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(mk(5));
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 0);
    }

    #[test]
    fn picks_least_connections() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(mk(10));
        p.add_worker(mk(3)); // <- 最少
        p.add_worker(mk(7));
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn skips_draining_in_pass1() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        // worker 0 是 draining 但 conn 最少，pass 1 应跳过
        p.add_worker(MockWorker { full: false, closed: false, draining: true, conn: 0 });
        p.add_worker(mk(5));
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn skips_full_in_pass1() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(MockWorker { full: true, closed: false, draining: false, conn: 0 });
        p.add_worker(mk(5));
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn skips_closed_in_pass1() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(MockWorker { full: false, closed: true, draining: false, conn: 0 });
        p.add_worker(mk(5));
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn pass2_accepts_draining() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        // 所有非 closed 都 draining 或 full → pass 2 选 draining 最少 conn
        p.add_worker(MockWorker { full: true, closed: false, draining: false, conn: 100 });
        p.add_worker(MockWorker { full: false, closed: false, draining: true, conn: 2 });
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn no_worker_available_when_all_closed_or_full() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(MockWorker { full: true, closed: false, draining: false, conn: 100 });
        p.add_worker(MockWorker { full: false, closed: true, draining: false, conn: 0 });
        let err = p.pick_available_index().unwrap_err();
        assert!(matches!(err, ReverseError::NoWorkerAvailable));
    }

    #[test]
    fn cleanup_removes_closed_workers() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(mk(1));
        p.add_worker(MockWorker { full: false, closed: true, draining: false, conn: 0 });
        p.add_worker(mk(2));
        assert_eq!(p.len(), 3);
        p.cleanup();
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn snapshot_returns_metadata() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(MockWorker { full: true, closed: false, draining: false, conn: 100 });
        p.add_worker(MockWorker { full: false, closed: false, draining: true, conn: 3 });
        let snap = p.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap[0].is_full);
        assert!(snap[1].is_draining);
        assert_eq!(snap[1].active_connections, 3);
    }

    #[test]
    fn add_worker_increments_len() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        assert!(p.is_empty());
        p.add_worker(mk(1));
        p.add_worker(mk(2));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn default_is_empty() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::default();
        assert!(p.is_empty());
    }

    #[test]
    fn equal_connections_picks_first() {
        let p: StaticMuxPicker<MockWorker> = StaticMuxPicker::new();
        p.add_worker(mk(5));
        p.add_worker(mk(5));
        let idx = p.pick_available_index().unwrap();
        assert_eq!(idx, 0);
    }
}
