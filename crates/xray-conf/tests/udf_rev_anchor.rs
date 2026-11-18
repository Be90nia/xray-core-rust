//! udf 依赖锚校验（bd jyjko；issue #68 后真值源 = 仓库根 `.github/udf-frame.rev`）。
//!
//! 主仓对 udf 走 **path 依赖**（`crates/udf-frame/*`），`Cargo.lock` 只记 `path`、
//! **不记 commit**——「自然记录实际 commit」是错的。消费 revision 钉死在
//! `.github/udf-frame.rev`（单行 40-hex 全 SHA，issue #68 决断 2026-11-18），
//! 本测试比对「udf 工作副本 HEAD」与 pin，不一致即失败。
//!
//! CI 与本地**同源真校验**（收口 bd yyoy9 的 CI-SKIP 缺口）：CI 侧 fetch-udf
//! action 按 pin fetch 并硬校验 HEAD==pin，checkout 自带 pin 文件 → 本测试在 CI
//! 照常执行，不再「无锚可比打 SKIP」。
//!
//! pin 缺失/格式坏 = fail-closed（与 fetch-udf action 同口径），禁把
//! 「没有锚可比」伪装成通过。
//!
//! 为什么住 `xray-conf`：它是主仓唯一直连 udf 的消费方（`udf-skeleton` /
//! `udf-std-ext` / `udf-skeleton-infra`），根 `tests/` 是红线不可动。
//!
//! 更新流程见 `docs/ops/udf-frame-pin.md`（验证上游全绿 → 换工作副本 → 改 pin →
//! 本地锚测试 + 全门 → PR）。

use std::{fs, path::PathBuf, process::Command};

#[test]
fn udf_frame_head_matches_rev_anchor() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let udf = manifest.join("..").join("udf-frame");
    // pin 住仓库根 .github/，相对 crates/xray-conf 上跳两级
    let pin_path = manifest.join("..").join("..").join(".github").join("udf-frame.rev");

    let raw = fs::read_to_string(&pin_path).unwrap_or_else(|e| {
        panic!(
            "pin 文件 {} 不可读（{e}）——udf-frame 消费已钉死，缺 pin 即拒（fail-closed）。\
             修法：git -C crates/udf-frame rev-parse HEAD > .github/udf-frame.rev；\
             流程见 docs/ops/udf-frame-pin.md",
            pin_path.display()
        )
    });
    let pinned = raw.trim();
    let is_full_sha = pinned.len() == 40
        && pinned.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    assert!(
        is_full_sha,
        "pin 文件 {} 不是单行 40-hex 小写全 SHA（得到 {:?}）——fail-closed。\
         修法：git -C crates/udf-frame rev-parse HEAD > .github/udf-frame.rev",
        pin_path.display(),
        pinned
    );

    let out = Command::new("git")
        .arg("-C")
        .arg(&udf)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap_or_else(|e| panic!("无法执行 git（udf 锚校验需要 git）: {e}"));
    assert!(
        out.status.success(),
        "git -C {} rev-parse HEAD 失败: {}",
        udf.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let head = String::from_utf8_lossy(&out.stdout);
    let head = head.trim();

    assert_eq!(
        head, pinned,
        "udf 工作副本 HEAD 与 pin 不一致：HEAD={head}，pin={pinned}。\
         升级 udf 须走 docs/ops/udf-frame-pin.md 流程（验证上游全绿 → 改 pin）"
    );
}
