use moka::sync::Cache;
use once_cell::sync::Lazy;
use std::{sync::Arc, time::Duration};

use crate::core::parts::transport_carrier::TransportCarrier;

// --- 全局缓存定义 ---

// 定义缓存的值类型为一个 Arc<DeviceState>。
// 使用 Arc 可以在多个地方共享同一个设备状态实例，减少克隆开销。
// Cache<String, Arc<DeviceState>> 是线程安全的。
static DEVICE_CACHE: Lazy<Cache<String, Arc<TransportCarrier>>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(100_000) // 例如，最大缓存10万个设备
        .time_to_live(Duration::from_secs(60 * 60)) // 例如，TTL 设置为 1 小时
        // .time_to_idle(Duration::from_secs(1 * 60 * 60)) // 也可以设置空闲过期时间 (TTI)
        .build()
});

pub struct ProtocolCache {}

impl ProtocolCache {
    // --- 公共访问函数 ---

    /// 根据设备号获取设备状态的共享引用 (Arc)。
    /// 如果缓存中不存在或已过期，则返回 None。
    pub fn read(unique: &str) -> Option<Arc<TransportCarrier>> {
        DEVICE_CACHE.get(unique)
        // .cloned() // moka v0.10+ 返回 Option<&V>, 需要 clone() 或 cloned()
        // 注意：moka v0.12+ get() 直接返回 Option<V> (如果是 Arc，则 Arc 被 clone)
    }

    // 从缓存里获取，如果空，则根据unique&upstream_count_hex创建一个新的。upstream_count_hex是上行序列号，通常来说，协议都需要。如果不需要传个随便什么就行。
    pub fn read_or_default(unique: &str, upstream_count_hex: &str) -> Arc<TransportCarrier> {
        Self::read(unique).unwrap_or_else(|| {
            let tp = TransportCarrier::new_with_device_no_and_upstream_count_hex(
                unique,
                upstream_count_hex,
            );
            let arc_tp = Arc::new(tp);
            Self::store(unique, Arc::clone(&arc_tp));
            arc_tp
        })
    }

    /// 插入或更新设备状态到缓存中。
    /// `state` 应该是 `Arc<DeviceState>` 类型。
    pub fn store(unique: &str, state: Arc<TransportCarrier>) {
        DEVICE_CACHE.insert(unique.into(), state);
    }
    /// 从缓存中移除设备状态。
    pub fn remove(device_no: &str) {
        DEVICE_CACHE.invalidate(device_no);
    }

    /// 获取缓存中当前的设备数量 (近似值)。
    pub fn read_size() -> u64 {
        DEVICE_CACHE.entry_count()
    }
}

// --- 示例用法 (可以在其他模块或JNI函数中调用) ---

/*
fn example_usage(device_no: &str) {
    if let Some(state) = get_device_state(device_no) {
        println!("Cache HIT: Device Type: {}", state.device_type());
        let current_up_count = state.increment_upstream(); // 安全地增加计数器
        println!("New upstream count: {}", current_up_count + 1);

        // 如果需要修改 cipher_slot
        // state.set_cipher_slot(1);

    } else {
        println!("Cache MISS for {}", device_no);
        // 这里应该从数据库或其他持久化存储加载设备信息
        let new_state = Arc::new(DeviceState::new(device_no, device_no /* ... */));
        insert_device_state(device_no.to_string(), new_state);
        println!("Device state loaded and cached.");
    }
}
*/
