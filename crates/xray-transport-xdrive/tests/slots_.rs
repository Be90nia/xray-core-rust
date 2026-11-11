//! xdrive 环形槽位端到端行为锚（bd hjtlk B5 验收④ + 规划 §6 门 B5）：
//! 真 dial → 真 serve → 槽位分配（make_slot 建环）→ 双向数据 → 回收（collector）。
//!
//! 槽位路接线证明：① make_slot 被真实调用（环已建，非 WAL 分段路）；② 流对象
//! 命名为槽位形态 `streams/<sid>/{c2s,s2c}/sN` 且无 `.seg` 段对象；③ announce
//! 对象携带非空载荷（环 JSON）。满槽回压锚（Go TestSlotConnSlowReader 的
//! e2e 面）：读者不读时写侧排队不丢数。
//!
//! 对照 Go `xdrive_test.go`/`slots_test.go`（memSlots 后端注入 =
//! [`set_test_storage_factory`](xray_transport_xdrive::storage::set_test_storage_factory)
//! 的既有等价面，同 `drive_.rs`）。

#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（bd g3cr）
#![allow(clippy::print_stderr)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::sync::Mutex;
use xray_transport::{dialer::StreamSettings, listener_registry::ConnHandler};
use xray_transport_xdrive::{
    Config, dial, serve,
    storage::{SlotStore, Storage, reset_test_storage_factory, set_test_storage_factory},
};

// TEST_FACTORY 进程级全局：slots 集成测试串行执行（同 drive_.rs 惯例）。
static SERIAL: Mutex<()> = Mutex::const_new(());

const ANNOUNCE_INLINE_LIMIT: usize = 12000;

#[derive(Default, Clone)]
struct MemObject {
    description: String,
    body: Vec<u8>,
}

#[derive(Default)]
struct MemCore {
    objects: BTreeMap<String, MemObject>,
    make_slot_calls: usize,
}

/// 内存对象存储 + 槽位能力（Go memSlots + drive 形态并集；id = 对象名，
/// 使槽位对象进同一命名空间供 list/回收语义复用）。
struct MemSlots {
    core: Arc<parking_lot::Mutex<MemCore>>,
}

fn subtree_keys(core: &MemCore, prefix: &str) -> Vec<String> {
    let with_slash = format!("{prefix}/");
    core.objects
        .range(prefix.to_string()..)
        .take_while(|(k, _)| k.as_str() == prefix || k.starts_with(&with_slash))
        .map(|(k, _)| k.clone())
        .collect()
}

#[async_trait::async_trait]
impl Storage for MemSlots {
    async fn put(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        // Go putInline/putMedia 的形态面：≤12000 → description = base64，否则 body。
        let object = if data.len() <= ANNOUNCE_INLINE_LIMIT {
            MemObject {
                description: std_ext::encode::base64_encode(
                    data,
                    std_ext::encode::Base64Alphabet::Std,
                    true,
                ),
                body: Vec::new(),
            }
        } else {
            MemObject { description: String::new(), body: data.to_vec() }
        };
        self.core.lock().objects.insert(name.to_string(), object);
        Ok(())
    }

    async fn get(&self, name: &str) -> std::io::Result<Vec<u8>> {
        let core = self.core.lock();
        let object =
            core.objects.get(name).ok_or_else(xray_transport_xdrive::storage::not_found)?;
        if !object.body.is_empty() {
            return Ok(object.body.clone());
        }
        if object.description.is_empty() {
            return Ok(Vec::new());
        }
        std_ext::encode::base64_decode(&object.description, std_ext::encode::Base64Alphabet::Std)
            .map_err(|e| std::io::Error::other(format!("bad inline base64: {e}")))
    }

    async fn delete(&self, name: &str) -> std::io::Result<()> {
        let mut core = self.core.lock();
        for key in subtree_keys(&core, name) {
            core.objects.remove(&key);
        }
        Ok(())
    }

    async fn list(
        &self,
        prefix: &str,
    ) -> std::io::Result<Vec<xray_transport_xdrive::storage::Entry>> {
        let core = self.core.lock();
        let keys = subtree_keys(&core, prefix);
        let mut entries = Vec::new();
        for key in keys {
            let rest = &key[prefix.len()..];
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            // 单级目录语义：只取首段（Go os.ReadDir / drive List 首层子级）。
            let name = rest.split('/').next().unwrap_or(rest).to_string();
            if name.is_empty()
                || entries.iter().any(|e: &xray_transport_xdrive::storage::Entry| e.name == name)
            {
                continue;
            }
            let object = &core.objects[&key];
            let inline = std_ext::encode::base64_decode(
                &object.description,
                std_ext::encode::Base64Alphabet::Std,
            )
            .ok();
            entries.push(xray_transport_xdrive::storage::Entry { name, inline });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn close(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// 槽位能力面：e2e 锚要真走环槽路，必须把自身交出去（默认 `None` = WAL 路）。
    fn slot_store(self: Arc<Self>) -> Option<Arc<dyn SlotStore>> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl SlotStore for MemSlots {
    async fn make_slot(&self, name: &str, _lane: bool) -> std::io::Result<String> {
        let mut core = self.core.lock();
        core.make_slot_calls += 1;
        core.objects.entry(name.to_string()).or_default();
        Ok(name.to_string())
    }

    async fn set_slot(
        &self,
        id: &str,
        description: &str,
        body: Option<&[u8]>,
        _lane: bool,
    ) -> std::io::Result<()> {
        let mut core = self.core.lock();
        let Some(object) = core.objects.get_mut(id) else {
            return Err(xray_transport_xdrive::storage::not_found());
        };
        object.description = description.to_string();
        if let Some(body) = body {
            object.body = body.to_vec();
        }
        Ok(())
    }

    async fn read_description(&self, id: &str, _lane: bool) -> std::io::Result<String> {
        let core = self.core.lock();
        let Some(object) = core.objects.get(id) else {
            return Err(xray_transport_xdrive::storage::not_found());
        };
        Ok(object.description.clone())
    }

    async fn read_body(&self, id: &str) -> std::io::Result<Vec<u8>> {
        let core = self.core.lock();
        let Some(object) = core.objects.get(id) else {
            return Err(xray_transport_xdrive::storage::not_found());
        };
        Ok(object.body.clone())
    }
}

fn slot_settings() -> StreamSettings {
    StreamSettings::from_json(Some(&serde_json::json!({
        "network": "xdrive",
        "xdriveSettings": {
            "service": "local",
            "remoteFolder": "/tmp/xdrive-slots-e2e",
            "segmentBytes": 16384,
            "concurrency": 2,
            "flushIntervalMs": 5,
            "pollIntervalMs": 5,
            "maxPollIntervalMs": 20,
            "eagerWindowMs": 50,
            "sessionTtlSeconds": 1,
        },
    })))
}

async fn start_pair(
    core: Arc<parking_lot::Mutex<MemCore>>,
) -> (
    Box<dyn xray_transport::connection::Connection>,
    Box<dyn xray_transport::connection::Connection>,
) {
    use xray_common::net::{
        address::Address, destination::Destination, network::Network, port::Port,
    };

    set_test_storage_factory(Arc::new(move |s: &StreamSettings| {
        let _ = Config::from_settings(s)?;
        Ok(Arc::new(MemSlots { core: Arc::clone(&core) }) as Arc<dyn Storage>)
    }));

    let settings = slot_settings();
    let (conn_tx, mut conn_rx) =
        tokio::sync::mpsc::channel::<Box<dyn xray_transport::connection::Connection>>(4);
    let handler: ConnHandler = Arc::new(move |conn| {
        let conn_tx = conn_tx.clone();
        tokio::spawn(async move {
            let _ = conn_tx.send(conn).await;
        });
    });
    let listener =
        serve("127.0.0.1:0".parse().unwrap(), settings.clone(), Default::default(), handler)
            .await
            .unwrap();

    let dest = Destination::new(Address::new_domain("xdrive.test"), Port::new(443), Network::TCP);
    let client = dial(&dest, &Default::default(), &settings).await.unwrap();
    let server = tokio::time::timeout(Duration::from_secs(10), conn_rx.recv())
        .await
        .expect("listener must accept the announced session in time")
        .expect("handler channel closed");
    drop(listener);
    (client, server)
}

/// 生命周期锚（bd hjtlk B5 验收④）：真 dial → 真 serve → 槽位分配 → 300KB
/// 双向逐字节 → 双侧 shutdown → collector 回收 streams/<sid> 对象。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slots_transport_lifecycle_roundtrip_and_reclaim() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let _guard = SERIAL.lock().await;
    let core = Arc::new(parking_lot::Mutex::new(MemCore::default()));
    let (mut client, mut server) = start_pair(Arc::clone(&core)).await;

    // 接线证明：环已建（make_slot ≥ 2×depth+2）、无 WAL .seg 对象、announce 已被
    // claim 消费（Go `acceptPending`：claim → 丢 announce，故此处应无残留）。
    {
        let core = core.lock();
        assert!(
            core.make_slot_calls >= 6,
            "the slot path must allocate a ring, got {} make_slot calls",
            core.make_slot_calls
        );
        assert!(
            !core.objects.keys().any(|k| k.ends_with(".seg")),
            "slot sessions must not go in WAL segments"
        );
        assert!(
            !core.objects.keys().any(|k| k.starts_with("sessions/")),
            "the claimed announce object must be dropped (Go acceptPending)"
        );
        let mut slot_objects = 0;
        for key in core.objects.keys() {
            if key.contains("/c2s/s") || key.contains("/s2c/s") {
                slot_objects += 1;
            }
        }
        assert!(slot_objects > 0, "no slot objects under the session prefix");
    }

    // 上行 300KB（跨多圈轮转：depth 2 × 段 16KiB ≈ 19 圈）逐字节比对。
    let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(60), server.read_exact(&mut received))
        .await
        .expect("uplink must arrive in time")
        .unwrap();
    assert_eq!(received, payload, "uplink must arrive byte-equal");

    // 下行回写 → 客户端读。
    server.write_all(&received).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(60), client.read_exact(&mut echoed))
        .await
        .expect("downlink must arrive in time")
        .unwrap();
    assert_eq!(echoed, payload, "downlink must arrive byte-equal");

    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();

    // collector 回收：sessionTtl 1s，轮询等待 streams/ 前缀对象清空。
    let mut reclaimed = false;
    for _ in 0..48 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let core = core.lock();
        if !core.objects.keys().any(|name| name.starts_with("streams/")) {
            reclaimed = true;
            break;
        }
    }
    assert!(reclaimed, "collector must reclaim the streams/ objects of the closed session");

    reset_test_storage_factory();
}

/// 满槽回压锚（Go TestSlotConnSlowReader 的 e2e 面）：读者 200ms 不读，写侧
/// 排队不丢数，随后一次读齐。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slots_slow_reader_backpressure_preserves_payload() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let _guard = SERIAL.lock().await;
    let core = Arc::new(parking_lot::Mutex::new(MemCore::default()));
    let (mut client, mut server) = start_pair(core).await;

    let payload: Vec<u8> = (0..400_000u32).map(|i| (i % 249) as u8).collect();
    let expected = payload.clone();
    let writer = tokio::spawn(async move {
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
    });
    // 读者停 200ms（> 若干圈的水位线节拍）——写侧必须被回压而非丢数。
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut received = Vec::new();
    let read = server.read_to_end(&mut received);
    tokio::time::timeout(Duration::from_secs(60), read)
        .await
        .expect("the stalled reader must still see the whole stream")
        .unwrap();
    assert_eq!(received, expected, "a stalled reader must not lose ring laps");
    writer.await.unwrap();
}
