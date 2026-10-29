//! udf 依赖锚校验（bd jyjko）。
//!
//! 主仓对 udf 走 **path 依赖**（`crates/udf-frame/*`），`Cargo.lock` 只记 `path`、
//! **不记 commit**——「自然记录实际 commit」是错的。真实版本 = 工作副本 HEAD，
//! 故用 `crates/udf-frame/REV` 把它钉成文件，本测试比对两侧，不一致即失败。
//!
//! 为什么住 `xray-conf`：它是主仓唯一直连 udf 的消费方（`udf-skeleton` /
//! `udf-std-ext` / `udf-skeleton-infra`），根 `tests/` 是红线不可动。
//!
//! `crates/udf-frame/` 被 `.git/info/exclude` 排除（工作副本，不入库），故本地
//! 升级 udf 后须同步 REV：`git -C crates/udf-frame rev-parse HEAD > crates/udf-frame/REV`。
//! CI 侧该目录是 checkout 时新 clone（不带 REV）→ 本测试显式跳过并打印原因，
//! 不把「无锚可比」伪装成通过。

use std::{fs, path::PathBuf, process::Command};

#[test]
fn udf_frame_head_matches_rev_anchor() {
    let udf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("udf-frame");
    let rev_path = udf.join("REV");

    let Ok(anchored) = fs::read_to_string(&rev_path) else {
        eprintln!(
            "SKIP udf_rev_anchor: {} 不存在（CI clone / 未落锚）——本机升级 udf 后跑 \
             `git -C crates/udf-frame rev-parse HEAD > crates/udf-frame/REV`",
            rev_path.display()
        );
        return;
    };
    let anchored = anchored.trim();

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
        head, anchored,
        "udf 工作副本 HEAD 与 REV 锚不一致：HEAD={head}，REV={anchored}。\
         升级 udf 后须一并更新 crates/udf-frame/REV（锚是显式文件，不是 Cargo.lock）"
    );
}
