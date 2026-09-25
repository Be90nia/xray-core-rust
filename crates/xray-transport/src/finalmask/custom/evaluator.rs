//! # 表达式引擎（对应 Go `finalmask/header/custom/evaluator.go`）
//!
//! 17 个操作符 + 类型定义 + measure（求大小）+ metadata 加载。
//! TCP / UDP 共用此引擎。

use std::{collections::HashMap, io, net::SocketAddr};

use crate::finalmask::custom::UDPItem;

/// 表达式节点：操作符 + 参数列表。
#[derive(Debug, Clone)]
pub struct Expr {
    pub op: String,
    pub args: Vec<ExprArg>,
}

/// 表达式参数（oneof，对应 Go `ExprArg_Value` oneof）。
#[derive(Debug, Clone)]
pub enum ExprArg {
    Bytes(Vec<u8>),
    U64(u64),
    Var(String),
    Metadata(String),
    Expr(Box<Expr>),
}

/// 求值结果（二选一：bytes 或 u64）。
///
/// 与 Go 一致：`is_bytes` 标记 bytes 类型；`u64 != None` 标记 u64 类型。
#[derive(Debug, Clone, Default)]
pub struct EvalValue {
    pub bytes: Vec<u8>,
    pub u64: Option<u64>,
    pub is_bytes: bool,
}

impl EvalValue {
    /// 构造 bytes 类型结果。
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self { bytes: b, u64: None, is_bytes: true }
    }

    /// 构造 u64 类型结果。
    pub fn from_u64(v: u64) -> Self {
        Self { bytes: Vec::new(), u64: Some(v), is_bytes: false }
    }

    /// 转为字节（类型不符报错）。
    pub fn as_bytes(&self) -> io::Result<Vec<u8>> {
        if self.is_bytes {
            Ok(self.bytes.clone())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "expr value is not bytes"))
        }
    }

    /// 转为 u64（类型不符报错）。
    pub fn as_u64(&self) -> io::Result<u64> {
        self.u64.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expr value is not u64"))
    }
}

/// 求值上下文：变量绑定（按名取字节）+ 元数据（按名取 EvalValue）。
#[derive(Debug, Default)]
pub struct EvalContext {
    pub vars: HashMap<String, Vec<u8>>,
    pub metadata: HashMap<String, EvalValue>,
}

impl EvalContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// 加载 local/remote 元数据（端口、IPv4 u32）。
    pub fn with_addrs(local: Option<SocketAddr>, remote: Option<SocketAddr>) -> Self {
        let mut ctx = Self::new();
        load_metadata(&mut ctx.metadata, "local", local);
        load_metadata(&mut ctx.metadata, "remote", remote);
        ctx
    }
}

/// 对单个 item 求值（按 rand/packet/var/expr 优先级），返回字节；写 save 到 ctx.vars。
#[allow(clippy::too_many_arguments)] // 参数对应 TCPItem/UDPItem 字段，无法进一步聚合
pub(crate) fn evaluate_item_fields(
    rand_len: i32,
    rand_min: u8,
    rand_max: u8,
    packet: &[u8],
    save: &str,
    var_name: &str,
    expr: Option<&Expr>,
    ctx: &mut EvalContext,
) -> io::Result<Vec<u8>> {
    let value: Vec<u8> = if rand_len > 0 {
        let mut buf = vec![0u8; rand_len as usize];
        fill_rand_bytes_between(&mut buf, rand_min, rand_max);
        buf
    } else if !packet.is_empty() {
        packet.to_vec()
    } else if !var_name.is_empty() {
        ctx.vars.get(var_name).cloned().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown variable: {var_name}"))
        })?
    } else if let Some(expr) = expr {
        evaluate_expr(expr, ctx)?.as_bytes()?
    } else {
        Vec::new()
    };

    if !save.is_empty() {
        ctx.vars.insert(save.to_string(), value.clone());
    }
    Ok(value)
}

/// 测量单个 item 的字节长度（基于 rand/packet/var/expr + save 记录到 size_ctx）。
pub(crate) fn measure_item(
    rand_len: i32,
    packet: &[u8],
    save: &str,
    var_name: &str,
    expr: Option<&Expr>,
    sizes: &mut HashMap<String, usize>,
) -> io::Result<usize> {
    let size = if rand_len > 0 {
        rand_len as usize
    } else if !packet.is_empty() {
        packet.len()
    } else if !var_name.is_empty() {
        *sizes.get(var_name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown variable: {var_name}"))
        })?
    } else if let Some(expr) = expr {
        measure_expr(expr, sizes)?
    } else {
        0
    };

    if !save.is_empty() {
        sizes.insert(save.to_string(), size);
    }
    Ok(size)
}

/// 17 个操作符分发（对应 Go `evaluateExpr`）。
pub(crate) fn evaluate_expr(expr: &Expr, ctx: &mut EvalContext) -> io::Result<EvalValue> {
    match expr.op.as_str() {
        "concat" => {
            let mut out = Vec::new();
            for arg in &expr.args {
                let v = evaluate_expr_arg(arg, ctx)?;
                out.extend_from_slice(&v.as_bytes()?);
            }
            Ok(EvalValue::from_bytes(out))
        },
        "slice" => evaluate_slice(&expr.args, ctx),
        "xor16" => evaluate_xor(&expr.args, 0xFFFF, 2, ctx),
        "xor32" => evaluate_xor(&expr.args, 0xFFFF_FFFF, 4, ctx),
        "be16" => evaluate_pack(&expr.args, "be16", 2, true, ctx),
        "be32" => evaluate_pack(&expr.args, "be32", 4, true, ctx),
        "le16" => evaluate_pack(&expr.args, "le16", 2, false, ctx),
        "le32" => evaluate_pack(&expr.args, "le32", 4, false, ctx),
        "le64" => evaluate_pack(&expr.args, "le64", 8, false, ctx),
        "pad" => evaluate_pad(&expr.args, ctx),
        "truncate" => evaluate_truncate(&expr.args, ctx),
        "add" => evaluate_binary_u64(&expr.args, "add", ctx, |l, r| {
            l.checked_add(r)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "add overflow"))
        }),
        "sub" => evaluate_binary_u64(&expr.args, "sub", ctx, |l, r| {
            if l < r {
                Err(io::Error::new(io::ErrorKind::InvalidData, "sub underflow"))
            } else {
                Ok(l - r)
            }
        }),
        "and" => evaluate_binary_u64(&expr.args, "and", ctx, |l, r| Ok(l & r)),
        "or" => evaluate_binary_u64(&expr.args, "or", ctx, |l, r| Ok(l | r)),
        "shl" => evaluate_shift(&expr.args, "shl", ctx, |v, s| {
            if v > (u64::MAX >> s) {
                Err(io::Error::new(io::ErrorKind::InvalidData, "shl overflow"))
            } else {
                Ok(v << s)
            }
        }),
        "shr" => evaluate_shift(&expr.args, "shr", ctx, |v, s| Ok(v >> s)),
        other => {
            Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported expr op: {other}")))
        },
    }
}

/// 测量表达式字节长度（对应 Go `measureExpr`）。
pub(crate) fn measure_expr(expr: &Expr, sizes: &HashMap<String, usize>) -> io::Result<usize> {
    match expr.op.as_str() {
        "concat" => {
            let mut total = 0;
            for arg in &expr.args {
                total += measure_expr_arg(arg, sizes)?;
            }
            Ok(total)
        },
        "slice" => expect_u64_literal_arg(&expr.args, 3, "slice length must be u64"),
        "be16" | "le16" => Ok(2),
        "be32" | "le32" => Ok(4),
        "le64" => Ok(8),
        "pad" => expect_u64_literal_arg(&expr.args, 3, "pad length must be u64"),
        "truncate" => expect_u64_literal_arg(&expr.args, 2, "truncate length must be u64"),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expr size is not bytes for op: {other}"),
        )),
    }
}

/// 求值 ExprArg（对应 Go `evaluateExprArg`）。
pub(crate) fn evaluate_expr_arg(arg: &ExprArg, ctx: &mut EvalContext) -> io::Result<EvalValue> {
    match arg {
        ExprArg::Bytes(b) => Ok(EvalValue::from_bytes(b.clone())),
        ExprArg::U64(v) => Ok(EvalValue::from_u64(*v)),
        ExprArg::Var(name) => {
            let saved = ctx.vars.get(name).cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("unknown variable: {name}"))
            })?;
            Ok(EvalValue::from_bytes(saved))
        },
        ExprArg::Metadata(name) => ctx.metadata.get(name).cloned().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown metadata: {name}"))
        }),
        ExprArg::Expr(inner) => evaluate_expr(inner, ctx),
    }
}

/// 测量 ExprArg 字节长度（对应 Go `measureExprArg`）。
pub(crate) fn measure_expr_arg(arg: &ExprArg, sizes: &HashMap<String, usize>) -> io::Result<usize> {
    match arg {
        ExprArg::Bytes(b) => Ok(b.len()),
        ExprArg::U64(_) => {
            Err(io::Error::new(io::ErrorKind::InvalidData, "u64 arg has no byte width"))
        },
        ExprArg::Var(name) => sizes.get(name).copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown variable: {name}"))
        }),
        ExprArg::Metadata(name) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("metadata not implemented: {name}"),
        )),
        ExprArg::Expr(inner) => measure_expr(inner, sizes),
    }
}

// ===== 公共辅助：供 tcp/udp 调用 =====

/// 按 UDP items 列表求值（对应 Go `evaluateUDPItemsWithContext`）。
pub(crate) fn evaluate_udp_items(items: &[UDPItem], ctx: &mut EvalContext) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for item in items {
        let v = evaluate_udp_item(item, ctx)?;
        out.extend_from_slice(&v);
    }
    Ok(out)
}

/// UDP item 求值（展开字段后调用 `evaluate_item_fields`）。
pub(crate) fn evaluate_udp_item(item: &UDPItem, ctx: &mut EvalContext) -> io::Result<Vec<u8>> {
    evaluate_item_fields(
        item.rand,
        item.rand_min,
        item.rand_max,
        &item.packet,
        &item.save,
        &item.var,
        item.expr.as_ref(),
        ctx,
    )
}

/// 测量 UDP items 总长度（无 fallback；对应 Go `measureUDPItems`）。
pub(crate) fn measure_udp_items(items: &[UDPItem]) -> io::Result<usize> {
    measure_udp_items_with_fallback(items, &HashMap::new())
}

/// 测量 UDP items 总长度（带 fallback；对应 Go `measureUDPItemsWithFallback`）。
pub(crate) fn measure_udp_items_with_fallback(
    items: &[UDPItem],
    fallback: &HashMap<String, usize>,
) -> io::Result<usize> {
    let mut sizes = fallback.clone();
    let mut total = 0;
    for item in items {
        let s = measure_item(
            item.rand,
            &item.packet,
            &item.save,
            &item.var,
            item.expr.as_ref(),
            &mut sizes,
        )?;
        total += s;
    }
    Ok(total)
}

/// 收集所有 save 的字节数（对应 Go `collectSavedUDPSizes`），供 server 测量时填充 var。
pub(crate) fn collect_saved_udp_sizes(items: &[UDPItem]) -> HashMap<String, usize> {
    let mut sizes = HashMap::new();
    for item in items {
        if let Ok(s) = measure_item(
            item.rand,
            &item.packet,
            &item.save,
            &item.var,
            item.expr.as_ref(),
            &mut sizes,
        ) {
            if !item.save.is_empty() {
                sizes.insert(item.save.clone(), s);
            }
        }
    }
    sizes
}

/// UDP 包匹配：检查 data 开头是否符合 items 模式（对应 Go `matchUDPItems`）。
///
/// 成功返回 vars（含 save），失败返回 None。
pub(crate) fn match_udp_items(
    items: &[UDPItem],
    data: &[u8],
    total_size: usize,
    initial: &HashMap<String, Vec<u8>>,
) -> Option<HashMap<String, Vec<u8>>> {
    if data.len() < total_size {
        return None;
    }
    let mut ctx = EvalContext::new();
    ctx.vars = initial.clone();
    let mut offset = 0usize;
    for item in items {
        let mut sizes = sizes_from_vars(&ctx.vars);
        let length = match measure_item(
            item.rand,
            &item.packet,
            &item.save,
            &item.var,
            item.expr.as_ref(),
            &mut sizes,
        ) {
            Ok(l) => l,
            Err(_) => return None,
        };
        if data[offset..].len() < length {
            return None;
        }
        let segment = data[offset..offset + length].to_vec();
        if item.rand > 0 {
            // 随机字节跳过
        } else if !item.packet.is_empty() {
            if item.packet != segment {
                return None;
            }
        } else if !item.var.is_empty() {
            match ctx.vars.get(&item.var) {
                Some(saved) if saved == &segment => {},
                _ => return None,
            }
        } else if let Some(expr) = &item.expr {
            match evaluate_expr(expr, &mut ctx) {
                Ok(v) => match v.as_bytes() {
                    Ok(expected) if expected == segment => {},
                    _ => return None,
                },
                Err(_) => return None,
            }
        }
        if !item.save.is_empty() {
            ctx.vars.insert(item.save.clone(), segment);
        }
        offset += length;
    }
    Some(ctx.vars)
}

/// 从 vars 派生 size map（名字→字节长度）。
pub(crate) fn sizes_from_vars(vars: &HashMap<String, Vec<u8>>) -> HashMap<String, usize> {
    vars.iter().map(|(k, v)| (k.clone(), v.len())).collect()
}

// ===== 内部辅助 =====

fn evaluate_slice(args: &[ExprArg], ctx: &mut EvalContext) -> io::Result<EvalValue> {
    if args.len() != 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "slice expects 3 args"));
    }
    let source = evaluate_expr_arg(&args[0], ctx)?.as_bytes()?;
    let offset = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    let length = evaluate_expr_arg(&args[2], ctx)?.as_u64()?;
    let end = offset.checked_add(length).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "slice offset+length overflow")
    })?;
    if end > source.len() as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "slice out of bounds"));
    }
    Ok(EvalValue::from_bytes(source[offset as usize..end as usize].to_vec()))
}

fn evaluate_pack(
    args: &[ExprArg],
    name: &str,
    width: usize,
    big_endian: bool,
    ctx: &mut EvalContext,
) -> io::Result<EvalValue> {
    if args.len() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} expects 1 arg")));
    }
    let v = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let out = match width {
        2 => {
            if v > 0xFFFF {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} overflow")));
            }
            let x = v as u16;
            if big_endian { x.to_be_bytes().to_vec() } else { x.to_le_bytes().to_vec() }
        },
        4 => {
            if v > 0xFFFF_FFFF {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} overflow")));
            }
            let x = v as u32;
            if big_endian { x.to_be_bytes().to_vec() } else { x.to_le_bytes().to_vec() }
        },
        8 => {
            if big_endian {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        },
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported pack width")),
    };
    Ok(EvalValue::from_bytes(out))
}

fn evaluate_pad(args: &[ExprArg], ctx: &mut EvalContext) -> io::Result<EvalValue> {
    if args.len() != 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pad expects 3 args"));
    }
    let source = evaluate_expr_arg(&args[0], ctx)?.as_bytes()?;
    let target = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    let fill = evaluate_expr_arg(&args[2], ctx)?.as_bytes()?;
    if fill.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pad fill must not be empty"));
    }
    if target < source.len() as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pad target shorter than source"));
    }
    let mut out = source;
    while (out.len() as u64) < target {
        let remaining = target as usize - out.len();
        if remaining >= fill.len() {
            out.extend_from_slice(&fill);
        } else {
            out.extend_from_slice(&fill[..remaining]);
        }
    }
    Ok(EvalValue::from_bytes(out))
}

fn evaluate_truncate(args: &[ExprArg], ctx: &mut EvalContext) -> io::Result<EvalValue> {
    if args.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncate expects 2 args"));
    }
    let source = evaluate_expr_arg(&args[0], ctx)?.as_bytes()?;
    let length = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    if length > source.len() as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncate out of bounds"));
    }
    Ok(EvalValue::from_bytes(source[..length as usize].to_vec()))
}

fn evaluate_binary_u64(
    args: &[ExprArg],
    name: &str,
    ctx: &mut EvalContext,
    op: impl Fn(u64, u64) -> io::Result<u64>,
) -> io::Result<EvalValue> {
    if args.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} expects 2 args")));
    }
    let left = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let right = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    let result = op(left, right)?;
    Ok(EvalValue::from_u64(result))
}

fn evaluate_shift(
    args: &[ExprArg],
    name: &str,
    ctx: &mut EvalContext,
    op: impl Fn(u64, u32) -> io::Result<u64>,
) -> io::Result<EvalValue> {
    if args.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} expects 2 args")));
    }
    let value = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let shift_u64 = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    if shift_u64 >= 64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "shift out of range"));
    }
    let result = op(value, shift_u64 as u32)?;
    Ok(EvalValue::from_u64(result))
}

fn evaluate_xor(
    args: &[ExprArg],
    mask: u64,
    width: usize,
    ctx: &mut EvalContext,
) -> io::Result<EvalValue> {
    if args.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xor expects 2 args"));
    }
    let left = evaluate_expr_arg(&args[0], ctx)?.as_u64()?;
    let right = evaluate_expr_arg(&args[1], ctx)?.as_u64()?;
    if width == 2 && (left > 0xFFFF || right > 0xFFFF) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xor16 overflow"));
    }
    if width == 4 && (left > 0xFFFF_FFFF || right > 0xFFFF_FFFF) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xor32 overflow"));
    }
    Ok(EvalValue::from_u64((left ^ right) & mask))
}

/// 取第 idx 个 arg 为 U64 字面量（measure 用）。
fn expect_u64_literal_arg(args: &[ExprArg], expected: usize, err: &str) -> io::Result<usize> {
    if args.len() != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("expects {expected} args")));
    }
    match &args[expected - 1] {
        ExprArg::U64(v) => Ok(*v as usize),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, err)),
    }
}

/// 用 [min, max] 闭区间的随机字节填充 buf（对应 Go `crypto.RandBytesBetween`）。
fn fill_rand_bytes_between(buf: &mut [u8], min: u8, max: u8) {
    use rand::Rng;
    let mut rng = rand::rng();
    for b in buf.iter_mut() {
        *b = rng.random_range(min..=max);
    }
}

/// 加载元数据：port / ip4_u32（对应 Go `loadMetadata` + `loadIPPortMetadata`）。
fn load_metadata(
    metadata: &mut HashMap<String, EvalValue>,
    prefix: &str,
    addr: Option<SocketAddr>,
) {
    let addr = match addr {
        Some(a) => a,
        None => return,
    };
    let port = addr.port() as u64;
    metadata.insert(format!("{prefix}_port"), EvalValue::from_u64(port));
    if prefix == "remote" {
        metadata.insert("src_port_u16".into(), EvalValue::from_u64(port));
    } else if prefix == "local" {
        metadata.insert("dst_port_u16".into(), EvalValue::from_u64(port));
    }
    if let std::net::SocketAddr::V4(v4) = addr {
        let octets = v4.ip().octets();
        let ip_u32 = u32::from_be_bytes(octets) as u64;
        metadata.insert(format!("{prefix}_ip4_u32"), EvalValue::from_u64(ip_u32));
        if prefix == "remote" {
            metadata.insert("src_ip4_u32".into(), EvalValue::from_u64(ip_u32));
        } else if prefix == "local" {
            metadata.insert("dst_ip4_u32".into(), EvalValue::from_u64(ip_u32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(b: &[u8]) -> ExprArg {
        ExprArg::Bytes(b.to_vec())
    }

    fn u64_arg(v: u64) -> ExprArg {
        ExprArg::U64(v)
    }

    fn expr(op: &str, args: Vec<ExprArg>) -> Expr {
        Expr { op: op.into(), args }
    }

    #[test]
    fn concat_concatenates_bytes() {
        let e = expr("concat", vec![bytes(b"ab"), bytes(b"cd"), bytes(b"ef")]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), b"abcdef");
    }

    #[test]
    fn slice_returns_subsequence() {
        let e = expr("slice", vec![bytes(b"hello"), u64_arg(1), u64_arg(3)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), b"ell");
    }

    #[test]
    fn slice_out_of_bounds_errors() {
        let e = expr("slice", vec![bytes(b"hi"), u64_arg(0), u64_arg(10)]);
        let mut ctx = EvalContext::new();
        assert!(evaluate_expr(&e, &mut ctx).is_err());
    }

    #[test]
    fn be16_encodes_big_endian() {
        let e = expr("be16", vec![u64_arg(0x1234)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), vec![0x12, 0x34]);
    }

    #[test]
    fn le32_encodes_little_endian() {
        let e = expr("le32", vec![u64_arg(0x12345678)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn xor16_masks_to_16_bits() {
        let e = expr("xor16", vec![u64_arg(0x1234), u64_arg(0xFFFF)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_u64().unwrap(), 0xEDCB);
    }

    #[test]
    fn xor32_returns_u64_type() {
        let e = expr("xor32", vec![u64_arg(0x12345678), u64_arg(0xFFFFFFFF)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_u64().unwrap(), 0xEDCBA987);
        assert!(!v.is_bytes);
    }

    #[test]
    fn pad_fills_to_target() {
        let e = expr("pad", vec![bytes(b"abc"), u64_arg(6), bytes(b"XY")]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), b"abcXYX"[..6].to_vec());
        // abc + XY + X（target=6 → "abc" + "XY" + "X"）
        assert_eq!(v.as_bytes().unwrap(), b"abcXYX");
    }

    #[test]
    fn truncate_takes_prefix() {
        let e = expr("truncate", vec![bytes(b"hello"), u64_arg(3)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), b"hel");
    }

    #[test]
    fn add_returns_u64() {
        let e = expr("add", vec![u64_arg(10), u64_arg(20)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_u64().unwrap(), 30);
    }

    #[test]
    fn add_overflow_errors() {
        let e = expr("add", vec![u64_arg(u64::MAX), u64_arg(1)]);
        let mut ctx = EvalContext::new();
        assert!(evaluate_expr(&e, &mut ctx).is_err());
    }

    #[test]
    fn shl_shifts_left() {
        let e = expr("shl", vec![u64_arg(1), u64_arg(8)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_u64().unwrap(), 256);
    }

    #[test]
    fn var_lookup_fails_when_missing() {
        let e = expr("concat", vec![ExprArg::Var("nope".into())]);
        let mut ctx = EvalContext::new();
        assert!(evaluate_expr(&e, &mut ctx).is_err());
    }

    #[test]
    fn var_lookup_succeeds_when_set() {
        let mut ctx = EvalContext::new();
        ctx.vars.insert("greeting".into(), b"hi".to_vec());
        let e = expr("concat", vec![ExprArg::Var("greeting".into())]);
        let v = evaluate_expr(&e, &mut ctx).unwrap();
        assert_eq!(v.as_bytes().unwrap(), b"hi");
    }

    #[test]
    fn metadata_loads_ipv4_port() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let ctx = EvalContext::with_addrs(Some(addr), None);
        // local_port
        assert_eq!(ctx.metadata["local_port"].as_u64().unwrap(), 8080);
        // dst_port_u16 alias
        assert_eq!(ctx.metadata["dst_port_u16"].as_u64().unwrap(), 8080);
        // local_ip4_u32 = 0x7F000001 (big-endian u32)
        assert_eq!(ctx.metadata["local_ip4_u32"].as_u64().unwrap(), 0x7F000001);
    }

    #[test]
    fn evaluate_item_priority_rand_then_packet_then_var_then_expr() {
        // expr 路径：be16(0x1234) → 2 字节
        let e = expr("be16", vec![u64_arg(0x1234)]);
        let mut ctx = EvalContext::new();
        let v = evaluate_item_fields(0, 0, 0, b"", "", "", Some(&e), &mut ctx).unwrap();
        assert_eq!(v, vec![0x12, 0x34]);
    }

    #[test]
    fn evaluate_item_save_writes_to_vars() {
        let mut ctx = EvalContext::new();
        let _ = evaluate_item_fields(0, 0, 0, b"hello", "saved", "", None, &mut ctx).unwrap();
        assert_eq!(ctx.vars.get("saved").map(|v| v.as_slice()), Some(b"hello" as &[u8]));
    }

    #[test]
    fn rand_item_fills_random_bytes() {
        let mut ctx = EvalContext::new();
        let v1 = evaluate_item_fields(8, 0x41, 0x41, b"", "", "", None, &mut ctx).unwrap();
        let v2 = evaluate_item_fields(8, 0x41, 0x41, b"", "", "", None, &mut ctx).unwrap();
        // 同种子下应都填充 0x41
        assert_eq!(v1, vec![0x41; 8]);
        assert_eq!(v2, vec![0x41; 8]);
    }
}
