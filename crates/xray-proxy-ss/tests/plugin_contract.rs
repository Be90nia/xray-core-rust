//! ss 族契约豁免清单（B6 审计，bd 7dce，2026-10-24）——**登记处，非夹具**。
//!
//! 本文件当前**零测试**：`xray-proxy-ss` 尚未接入强约束插件模型，L4 夹具无
//! 锚点。这份清单登记缺什么、为何缺、补的阻碍——债显式化，防 CI 照绿被误读
//! 为「ss 已受契约约束」。
//!
//! # 缺什么
//!
//! 对照 15 个已接线协议 crate（样板：vmess 12 条全适用、freedom 9 适用 +
//! 3 N/A、blackhole 10 适用 + 1 N/A）：
//! 1. 声明面：无 `impl Plugin`（`name/version/contract/lifecycle/build` 五方 法），无
//!    `PluginContract`（clauses / extra / not_applicable 全缺）—— `src/` 无
//!    plugin.rs，`SsInbound`/`SsOutbound` 为纯 handler 直出形态；
//! 2. 声明面夹具：`assert_plugin_contract!` 无插件类型可指；
//! 3. 行为夹具接线：conn_id（坑 3）/ deadline（坑 2）/ log（坑 10/11）/ pool（坑
//!    4/9）四件全未接线——接线依据是 `contract()` 声明面，ss 无
//!    声明面则无从决定跑哪些，硬跑反而制造「已受约束」的假象；
//! 4. 协议专属条款（extra）：ss2022 wire 语义（sing 对端读路径反推的分帧 / 响应头 /
//!    重计数约束）未条款化。
//!
//! # 为何缺 / 补的阻碍
//!
//! 1. **未插件化是根因**：补夹具的前置是插件化改造（`impl Plugin` + `Lifecycle` 三相 + build 段路由
//!    + 装配接线），属框架 P0-P4 接线批次， 非契约审计可顺手做——没有装配链就硬造 `impl Plugin`
//!      只会产出假声明面。
//! 2. **构造面无空转语义**：夹具要求 `Default::default()` 实例可跑 lifecycle 三相，而 ss handler
//!    构造依赖运行时密钥材料（`MemoryAccount` / ss2022 psk / 多用户表）——插件化时须先定义「空配置 =
//!    构造成功、build 期 fail-visible」的语义，否则夹具无从构造实例。
//! 3. **CI 无机械门**：`.github/workflows` 无「缺 plugin_contract.rs 即红」
//!    检查（`xray_frame::contract_assert` 头注释的「缺 = CI 红」是规范约定， 未落 CI
//!    lint）。本豁免的解除须伴随 CI 门上线，否则债会静默回填。
//!
//! 条款 × 断言面现状的权威标注面：`xray_frame::contract_assert` 模块文档
//! 「条款声明态」节（三态：已实现 / 部分 / 仅声明）。
