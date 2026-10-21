//! WFP 安装层（仅 Windows）——把 [`super::spec`] 的规格翻译成 `Fwpm*` 调用。
//!
//! 对应 Go `proxy/tun/tun_windows_wfp.go`：
//! - `open_engine` ≈ Go `openWFPEngine`（:222）：**动态会话**（`FWPM_SESSION_FLAG_DYNAMIC`）， 关闭
//!   engine 即删除全部过滤器，进程崩溃 Windows 也会清理（Go :197-198 同语义）。
//! - [`install`] ≈ Go `blockLeaks`（:199）：事务里一次性装好，失败即回滚。
//! - `add_filter` ≈ Go `addFilter`（:429）。
//!
//! ## 安全边界
//!
//! - 过滤器只针对**指定 LUID 的 TUN 接口**（条件里带接口 LUID），不装全局 block 规则；
//! - 一切失败路径都走「事务 abort + 关闭 engine」，不留残余规则；
//! - 权限不足（未提权）时返回明确错误，由调用方决定是否继续启动 TUN。
//!
//! 规格层（过滤条件/动作/权重）在 [`super::spec`]，本文件只做翻译。

use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr};

use windows_sys::{
    Win32::{
        Foundation::{ERROR_SUCCESS, HANDLE, LocalFree},
        NetworkManagement::{
            IpHelper::ConvertInterfaceIndexToLuid, Ndis::NET_LUID_LH,
            WindowsFilteringPlatform as wfp,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            GetSecurityDescriptorLength,
        },
        System::SystemInformation::OSVERSIONINFOW,
    },
    core::{GUID, PWSTR},
};

use super::spec::{DNS_CLIENT_SID, LeakFilterInput, WINDOWS_DOH_DNS_BUILD, leak_filter_specs};

/// `RPC_C_AUTHN_WINNT`（Go `rpcCAuthnWinNT`，:35）。
const RPC_C_AUTHN_WINNT: u32 = 10;

/// WFP 引擎句柄守卫：Drop 时关闭 engine（动态会话的过滤器随之删除）。
pub struct LeakFilterGuard {
    engine: HANDLE,
}

// SAFETY：engine 句柄由 WFP 管理，关闭只在 Drop 里发生一次；句柄本身可跨线程使用。
unsafe impl Send for LeakFilterGuard {}
unsafe impl Sync for LeakFilterGuard {}

impl Drop for LeakFilterGuard {
    fn drop(&mut self) {
        unsafe { wfp::FwpmEngineClose0(self.engine) };
    }
}

/// 安装泄漏阻断过滤器。
///
/// - `tun_if_index`：TUN 接口索引（由 `tun-rs` 的 `if_index()` 给出）→ 换算成 LUID；
/// - `dns` / `ipv4` / `ipv6`：分别阻断 DNS / IPv4 / IPv6 泄漏（Go `tun_windows.go:254-257`）。
///
/// # Errors
///
/// 权限不足、引擎打开失败、过滤器添加失败等，返回可诊断错误文本。
pub fn install(
    tun_if_index: u32,
    dns: bool,
    ipv4: bool,
    ipv6: bool,
) -> Result<LeakFilterGuard, String> {
    let tun_luid = interface_luid(tun_if_index)?;
    install_with_luid(tun_luid, dns, ipv4, ipv6)
}

/// 以**已知 LUID** 安装（接口索引已换算好的场景；也用于真机自检时用哑 LUID）。
pub fn install_with_luid(
    tun_luid: u64,
    dns: bool,
    ipv4: bool,
    ipv6: bool,
) -> Result<LeakFilterGuard, String> {
    let app_id = current_exe_app_id()?;
    let build = windows_build();
    let dns_client_sd = if dns && build >= WINDOWS_DOH_DNS_BUILD {
        Some(dns_client_security_descriptor()?)
    } else {
        None
    };
    let specs = leak_filter_specs(&LeakFilterInput {
        tun_luid,
        app_id,
        dns,
        ipv4,
        ipv6,
        windows_build: build,
        dns_client_sd,
    });
    install_specs(&specs)
}

/// 打开动态会话引擎（Go `openWFPEngine`，:222）。
fn open_engine() -> Result<HANDLE, String> {
    let name = wide("Xray TUN");
    let mut session: wfp::FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    session.displayData =
        wfp::FWPM_DISPLAY_DATA0 { name: name.as_ptr() as PWSTR, description: ptr::null_mut() };
    session.flags = wfp::FWPM_SESSION_FLAG_DYNAMIC;
    let mut engine: HANDLE = ptr::null_mut();
    // SAFETY：session/engine 均为有效栈/局部变量，API 只读取 session、写出 engine。
    let status = unsafe {
        wfp::FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT, ptr::null(), &session, &mut engine)
    };
    check(status, "FwpmEngineOpen0")?;
    Ok(engine)
}

/// 在一个事务里装好全部过滤器（Go `blockLeaks`，:199-220）。
fn install_specs(specs: &[super::spec::FilterSpec]) -> Result<LeakFilterGuard, String> {
    let engine = open_engine()?;
    let guard = LeakFilterGuard { engine };
    // SAFETY：engine 有效。
    check(unsafe { wfp::FwpmTransactionBegin0(engine, 0) }, "FwpmTransactionBegin0")?;

    let result = (|| {
        let sublayer = new_guid();
        add_sublayer(engine, sublayer)?;
        for spec in specs {
            add_filter(engine, sublayer, spec)?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            // SAFETY：engine 有效。
            check(unsafe { wfp::FwpmTransactionCommit0(engine) }, "FwpmTransactionCommit0")?;
            Ok(guard)
        },
        Err(e) => {
            // 回滚：abort 事务 + 关闭 engine（guard drop）——不留残余规则。
            // SAFETY：engine 有效。
            unsafe { wfp::FwpmTransactionAbort0(engine) };
            Err(e)
        },
    }
}

/// 新建子层（Go :260-268）。
fn add_sublayer(engine: HANDLE, sublayer_key: GUID) -> Result<(), String> {
    let name = wide("Xray TUN");
    let mut sublayer: wfp::FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sublayer.subLayerKey = sublayer_key;
    sublayer.displayData =
        wfp::FWPM_DISPLAY_DATA0 { name: name.as_ptr() as PWSTR, description: ptr::null_mut() };
    sublayer.weight = 0xffff;
    // SAFETY：sublayer 为有效局部变量。
    check(
        unsafe { wfp::FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut()) },
        "FwpmSubLayerAdd0",
    )?;
    Ok(())
}

/// 添加一条过滤器（Go `addFilter`，:429-446）。
fn add_filter(
    engine: HANDLE,
    sublayer_key: GUID,
    spec: &super::spec::FilterSpec,
) -> Result<(), String> {
    let name = wide(&spec.name);
    let mut arena = CondArena::default();
    let mut conditions = build_conditions(&spec.conditions, &mut arena);

    let mut filter: wfp::FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.displayData =
        wfp::FWPM_DISPLAY_DATA0 { name: name.as_ptr() as PWSTR, description: ptr::null_mut() };
    filter.flags = spec.flags;
    filter.layerKey = layer_guid(spec.layer);
    filter.subLayerKey = sublayer_key;
    filter.weight = wfp::FWP_VALUE0 {
        r#type: wfp::FWP_UINT8,
        Anonymous: wfp::FWP_VALUE0_0 { uint8: spec.weight },
    };
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition =
        if conditions.is_empty() { ptr::null_mut() } else { conditions.as_mut_ptr() };
    filter.action = wfp::FWPM_ACTION0 {
        r#type: match spec.action {
            super::spec::Action::Permit => wfp::FWP_ACTION_PERMIT,
            super::spec::Action::Block => wfp::FWP_ACTION_BLOCK,
        },
        // SAFETY：union 全零 = 无 callout。
        Anonymous: unsafe { std::mem::zeroed() },
    };
    // SAFETY：filter/conditions/arena 在调用期间均有效（arena 持有所需缓冲）。
    let status = unsafe { wfp::FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) };
    check(status, &format!("FwpmFilterAdd0({})", spec.name))?;
    Ok(())
}

/// 条件值需要的稳定内存（blob 数据、u64、16 字节地址）。
// Box 是**语义必需**：这些指针要存进 FWP union（blob 描述符 / uint64 / addr16），
// 元素必须地址稳定——`Vec<T>` 会在扩容时搬家，clippy 的 vec_box 建议在此不可采纳。
#[allow(clippy::vec_box)]
#[derive(Default)]
struct CondArena {
    /// blob 数据底座（`Box<[u8]>` 保证地址稳定）。
    data: Vec<Box<[u8]>>,
    /// blob 描述符。
    blobs: Vec<Box<wfp::FWP_BYTE_BLOB>>,
    /// 64 位值（union 里是指针）。
    u64s: Vec<Box<u64>>,
    /// 16 字节地址。
    arrays: Vec<Box<wfp::FWP_BYTE_ARRAY16>>,
}

impl CondArena {
    /// 分配一个字节 blob，返回稳定指针。
    fn blob(&mut self, bytes: &[u8]) -> *mut wfp::FWP_BYTE_BLOB {
        let data: Box<[u8]> = bytes.to_vec().into_boxed_slice();
        let data_ptr = data.as_ptr() as *mut u8;
        let size = data.len() as u32;
        self.data.push(data);
        let mut blob = Box::new(wfp::FWP_BYTE_BLOB { size, data: data_ptr });
        let ptr = &mut *blob as *mut wfp::FWP_BYTE_BLOB;
        self.blobs.push(blob);
        ptr
    }

    /// 分配一个 u64，返回稳定指针。
    fn u64(&mut self, value: u64) -> *mut u64 {
        let mut boxed = Box::new(value);
        let ptr = &mut *boxed as *mut u64;
        self.u64s.push(boxed);
        ptr
    }

    /// 分配一个 16 字节地址，返回稳定指针。
    fn array16(&mut self, value: [u8; 16]) -> *mut wfp::FWP_BYTE_ARRAY16 {
        let mut boxed = Box::new(wfp::FWP_BYTE_ARRAY16 { byteArray16: value });
        let ptr = &mut *boxed as *mut wfp::FWP_BYTE_ARRAY16;
        self.arrays.push(boxed);
        ptr
    }
}

/// 把规格条件翻译成 WFP 条件数组。
fn build_conditions(
    conds: &[super::spec::Condition],
    arena: &mut CondArena,
) -> Vec<wfp::FWPM_FILTER_CONDITION0> {
    conds
        .iter()
        .map(|c| {
            let (ty, anon) = match &c.value {
                super::spec::Value::Bytes(b) => {
                    let blob = arena.blob(b);
                    let ty = if c.field == super::spec::Field::AleUserId {
                        wfp::FWP_SECURITY_DESCRIPTOR_TYPE
                    } else {
                        wfp::FWP_BYTE_BLOB_TYPE
                    };
                    (ty, wfp::FWP_CONDITION_VALUE0_0 { byteBlob: blob })
                },
                super::spec::Value::U8(v) => {
                    (wfp::FWP_UINT8, wfp::FWP_CONDITION_VALUE0_0 { uint8: *v })
                },
                super::spec::Value::U16(v) => {
                    (wfp::FWP_UINT16, wfp::FWP_CONDITION_VALUE0_0 { uint16: *v })
                },
                super::spec::Value::U32(v) => {
                    (wfp::FWP_UINT32, wfp::FWP_CONDITION_VALUE0_0 { uint32: *v })
                },
                super::spec::Value::U64(v) => {
                    let p = arena.u64(*v);
                    (wfp::FWP_UINT64, wfp::FWP_CONDITION_VALUE0_0 { uint64: p })
                },
                super::spec::Value::Addr16(a) => {
                    let p = arena.array16(*a);
                    (wfp::FWP_BYTE_ARRAY16_TYPE, wfp::FWP_CONDITION_VALUE0_0 { byteArray16: p })
                },
            };
            wfp::FWPM_FILTER_CONDITION0 {
                fieldKey: field_guid(c.field),
                matchType: match c.match_type {
                    super::spec::MatchType::Equal => wfp::FWP_MATCH_EQUAL,
                    super::spec::MatchType::FlagsAllSet => wfp::FWP_MATCH_FLAGS_ALL_SET,
                },
                conditionValue: wfp::FWP_CONDITION_VALUE0 { r#type: ty, Anonymous: anon },
            }
        })
        .collect()
}

/// 条件字段 → WFP GUID。
fn field_guid(field: super::spec::Field) -> GUID {
    match field {
        super::spec::Field::AleAppId => wfp::FWPM_CONDITION_ALE_APP_ID,
        super::spec::Field::AleUserId => wfp::FWPM_CONDITION_ALE_USER_ID,
        super::spec::Field::IpRemotePort => wfp::FWPM_CONDITION_IP_REMOTE_PORT,
        super::spec::Field::IpLocalPort => wfp::FWPM_CONDITION_IP_LOCAL_PORT,
        super::spec::Field::IpLocalInterface => wfp::FWPM_CONDITION_IP_LOCAL_INTERFACE,
        super::spec::Field::IpNexthopInterface => wfp::FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
        super::spec::Field::IpArrivalInterface => wfp::FWPM_CONDITION_IP_ARRIVAL_INTERFACE,
        super::spec::Field::IpProtocol => wfp::FWPM_CONDITION_IP_PROTOCOL,
        super::spec::Field::IpRemoteAddress => wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
        super::spec::Field::Flags => wfp::FWPM_CONDITION_FLAGS,
    }
}

/// 层 → WFP GUID。
fn layer_guid(layer: super::spec::Layer) -> GUID {
    match layer {
        super::spec::Layer::AuthConnectV4 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        super::spec::Layer::AuthRecvAcceptV4 => wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        super::spec::Layer::AuthConnectV6 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        super::spec::Layer::AuthRecvAcceptV6 => wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// 接口索引 → LUID（`iphlpapi!ConvertInterfaceIndexToLuid`）。
fn interface_luid(if_index: u32) -> Result<u64, String> {
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY：luid 为有效局部变量，API 只写出。
    let status = unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) };
    check(status, "ConvertInterfaceIndexToLuid")?;
    // SAFETY：NET_LUID_LH 的 Value 成员是 u64（union 的标量视图）。
    Ok(unsafe { luid.Value })
}

/// 本进程 AppID（`FwpmGetAppIdFromFileName0`）。
fn current_exe_app_id() -> Result<Vec<u8>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe for WFP app id: {e}"))?;
    let path = wide_path(&exe);
    let mut blob: *mut wfp::FWP_BYTE_BLOB = ptr::null_mut();
    // SAFETY：path 为有效 UTF-16 缓冲；blob 由 API 写出。
    let status = unsafe { wfp::FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
    check(status, "FwpmGetAppIdFromFileName0")?;
    if blob.is_null() {
        return Err("FwpmGetAppIdFromFileName0 returned no app id".to_string());
    }
    // SAFETY：blob 非空且由 API 分配，size/data 有效。
    let bytes = unsafe {
        let size = (*blob).size as usize;
        if size == 0 || (*blob).data.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts((*blob).data, size).to_vec()
        }
    };
    // 释放 API 分配的内存。
    let mut raw = blob as *mut c_void;
    // SAFETY：raw 是 API 返回的指针，按文档用 FwpmFreeMemory0 释放。
    unsafe { wfp::FwpmFreeMemory0(&mut raw) };
    Ok(bytes)
}

/// DNS Client 服务（NT SERVICE\Dnscache）的匹配用安全描述符。
///
/// Go `tun_windows_wfp.go:333-339`：SDDL 串 `O:SYG:SYD:(A;;CCRC;;;<SID>)` → 安全描述符字节，
/// 作为 `FWP_SECURITY_DESCRIPTOR_TYPE` 条件值。
fn dns_client_security_descriptor() -> Result<Vec<u8>, String> {
    let sddl = format!("O:SYG:SYD:(A;;CCRC;;;{DNS_CLIENT_SID})");
    let text = wide(&sddl);
    let mut sd: *mut c_void = ptr::null_mut();
    // SAFETY：text 为有效 UTF-16；sd 由 API 写出（LocalAlloc 内存）。
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err("ConvertStringSecurityDescriptorToSecurityDescriptorW failed".to_string());
    }
    // SAFETY：sd 非空（API 成功时保证），长度由 API 读取。
    let len = unsafe { GetSecurityDescriptorLength(sd) } as usize;
    // SAFETY：sd 指向 len 字节的有效安全描述符。
    let bytes = unsafe { std::slice::from_raw_parts(sd as *const u8, len) }.to_vec();
    // SAFETY：sd 是 LocalAlloc 分配的，用 LocalFree 释放。
    unsafe { LocalFree(sd) };
    Ok(bytes)
}

/// Windows build 号（`RtlGetVersion`）——决定是否需要 DNS Client 服务的过滤器。
fn windows_build() -> u32 {
    let mut info: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    // SAFETY：info 为有效局部变量。
    let status = unsafe { RtlGetVersion(&mut info) };
    if status == 0 { info.dwBuildNumber } else { 0 }
}

// `ntdll!RtlGetVersion`（`GetVersionExW` 会被兼容性清单改写，只有它说真话）。
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version_info: *mut OSVERSIONINFOW) -> i32;
}

/// 随机 GUID（子层键）。
fn new_guid() -> GUID {
    let u = uuid::Uuid::new_v4();
    let (data1, data2, data3, data4) = u.as_fields();
    GUID { data1, data2, data3, data4: *data4 }
}

/// 宽字符串（UTF-16，NUL 结尾）。
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 路径的宽字符串（`OsStr` 的 WTF-8 → UTF-16）。
fn wide_path(p: &std::path::Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// 检查 WFP 返回码。
fn check(status: u32, what: &str) -> Result<(), String> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{what} failed with status 0x{status:08x}"))
    }
}
