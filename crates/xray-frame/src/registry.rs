//! L5 装配门第一半：插件静态注册表（模型 §2.2 L5「装配期硬校验」）。
//!
//! - 容量 fail-closed（坑约束 #9 装配侧）：`new(0)` 与超容量注册均拒。
//! - 重名**不覆盖**：强约束模型下同名 = bug，fail-visible——与 `xray-features/src/registry.rs:63
//!   register_feature` 的同名覆盖语义相反。
//! - `start_order` 按 `deps()` 做 Kahn 拓扑排序：注册序 ≠ 启动序，同层并列
//!   按注册序稳定输出（确定性）；缺依赖 → `MissingDep`（plugin=声明方， dep=缺名），成环 →
//!   `CyclicDep{cycle}`，均在装配期（启动前）报错。 原型 `xray-core/src/instance.rs:58`
//!   的「注册序=启动序、close=逆序」被 deps 显式声明序取代（模型 §2.1 注册装配差异行）。
//!
//! PM 拍板（2026-10-23）：`start_order` 每次重算不缓存——注册表小而固定，
//! 缓存属过早优化；`BoundedRegistry` 另造判定（KV 容器无依赖解析，非同构，
//! 仅借用其容量纪律：skeleton-infra/src/memgov.rs:58）。

use std::{collections::HashMap, sync::Arc};

use crate::{error::PluginError, plugin::Plugin};

/// 插件静态注册表：容量上界 + 重名拒 + deps 拓扑排序 + 按名查表。
///
/// 生命周期钩子的调用归 P0-4 编排器，本件只产**次序**（stop 逆序即
/// `start_order` 逆序，坑约束 #6 的次序来源，P0-4/P0-8 消费）。
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,       // 注册序
    index: HashMap<&'static str, usize>, // name → 注册序位
    max: usize,                          // 容量上界（fail-closed）
}

impl PluginRegistry {
    /// 容量构造。`max == 0` → `Err(Full)`（比 udf `BoundedRegistry::new` 的
    /// assert 温和，装配期错误统一走 `PluginError`）。
    pub fn new(max: usize) -> Result<Self, PluginError> {
        if max == 0 {
            return Err(PluginError::Full { cap: 0 });
        }
        Ok(Self { plugins: Vec::new(), index: HashMap::new(), max })
    }

    /// 注册一个插件。重名 → `Err(Duplicate)`（不覆盖）；满 → `Err(Full)`。
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> Result<(), PluginError> {
        if self.index.contains_key(plugin.name()) {
            return Err(PluginError::Duplicate { name: plugin.name().to_string() });
        }
        if self.plugins.len() >= self.max {
            return Err(PluginError::Full { cap: self.max });
        }
        self.index.insert(plugin.name(), self.plugins.len());
        self.plugins.push(plugin);
        Ok(())
    }

    /// Kahn 拓扑排序：`deps()` 声明序 → 启动序；同层并列按注册序稳定输出。
    ///
    /// 缺依赖 → `Err(MissingDep)`；成环 → `Err(CyclicDep{ cycle })`，
    /// `cycle` = Kahn 残留集（参与环的全部插件名 + 环下游无法排程者，按
    /// 注册序——自洽链，非最短环）。
    pub fn start_order(&self) -> Result<Vec<Arc<dyn Plugin>>, PluginError> {
        // 依赖存在性先于排序全量校验：首个缺失按（注册序 × deps 声明序）报。
        for plugin in &self.plugins {
            for dep in plugin.deps() {
                if !self.index.contains_key(dep.name) {
                    return Err(PluginError::MissingDep {
                        plugin: plugin.name().to_string(),
                        dep: dep.name.to_string(),
                    });
                }
            }
        }

        // 每轮扫「依赖已全部排程」的**最小注册序位** → 同层稳定按注册序。
        // 轮数上界 = n：每轮必推进一个节点，n 轮内必收敛；显式上界使「成环分支
        // 被去掉」的变异体以断言失败退出，而不是在 `find` 恒 None 下空转挂死。
        let n = self.plugins.len();
        let mut scheduled = vec![false; n];
        let mut order = Vec::with_capacity(n);
        for _ in 0..n {
            let Some((i, plugin)) = self.plugins.iter().enumerate().find(|(i, plugin)| {
                !scheduled[*i] && plugin.deps().iter().all(|dep| scheduled[self.index[dep.name]])
            }) else {
                // 无可排程节点：残留集即环链（含环全体 + 环下游）。
                let cycle = self
                    .plugins
                    .iter()
                    .zip(&scheduled)
                    .filter(|&(_, &done)| !done)
                    .map(|(plugin, _)| plugin.name().to_string())
                    .collect();
                return Err(PluginError::CyclicDep { cycle });
            };
            scheduled[i] = true;
            order.push(Arc::clone(plugin));
        }
        // 上界耗尽仍有节点未排程 = 出现了无进展轮（只可能来自绕过上方成环分支
        // 的代码腐化）。用 assert 而非 debug_assert：release 下也宁可炸，不静默返半序。
        assert_eq!(order.len(), n, "start_order: 上界内未排完全部节点（无进展轮绕过了成环分支）");
        Ok(order)
    }

    /// 按名查表（O(1)，注册期建索引）。
    pub fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        let &i = self.index.get(name)?;
        Some(Arc::clone(&self.plugins[i]))
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// 注册序遍历（**非**启动序；启动序走 [`start_order`](Self::start_order)）。
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Plugin>> {
        self.plugins.iter()
    }
}
