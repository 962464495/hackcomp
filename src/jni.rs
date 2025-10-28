/// JNI 接口模块
///
/// 提供 Java 与 Rust 之间的桥接，用于 LSPosed 模块集成
///
/// 主要功能：
/// - JNI_OnLoad: 库加载时自动调用
/// - install: 接收配置并安装 Seccomp hooks
/// - 配置结构体：从 Java 传递系统调用列表和选项

use jni::objects::{JClass, JIntArray};
use jni::sys::{jboolean, jint, jintArray, jlong, jstring, JNI_VERSION_1_6};
use jni::JNIEnv;
use log::{error, info, warn};
use syscalls::Sysno;

use crate::Builder;

/// 初始化 Android Logger
/// 使用 tag "Hackcomp" 输出到 logcat
fn init_logger() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("Hackcomp")
            .with_max_level(log::LevelFilter::Debug)
            .with_filter(
                android_logger::FilterBuilder::new()
                    .parse("debug,hackcomp=trace")
                    .build(),
            ),
    );
}

/// JNI_OnLoad - 当动态库被加载时由 JVM 自动调用
///
/// 这个函数会在 System.loadLibrary("hackcomp") 时被调用
///
/// 返回值：JNI 版本号
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jint {
    // 初始化日志系统
    init_logger();

    info!("=================================================");
    info!("Hackcomp JNI Library Loaded");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("=================================================");

    JNI_VERSION_1_6 as jint
}

/// Java 调用入口：安装 Hooks
///
/// Java 签名：
/// ```java
/// public static native long install(
///     int[] syscalls,
///     boolean enableLogger,
///     boolean hideSeccomp,
///     boolean hideMaps
/// );
/// ```
///
/// 参数：
/// - syscalls: 要监控的系统调用编号数组
/// - enableLogger: 是否启用日志
/// - hideSeccomp: 是否隐藏 seccomp
/// - hideMaps: 是否隐藏内存映射
///
/// 返回值：
/// - 0: 成功
/// - -1: 失败
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_security_syscallmonitor_HackcompJNI_install(
    mut env: JNIEnv,
    _class: JClass,
    syscalls: jintArray,
    enable_logger: jboolean,
    hide_seccomp: jboolean,
    hide_maps: jboolean,
) -> jlong {
    info!("=================================================");
    info!("Installing Hackcomp Hooks from Java...");

    // 解析系统调用编号数组
    let syscall_list = match parse_syscall_array(&mut env, syscalls) {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to parse syscall array: {:?}", e);
            return -1;
        }
    };

    info!("Configuration:");
    info!("  - Syscalls to monitor: {} items", syscall_list.len());
    info!("  - Enable Logger: {}", enable_logger != 0);
    info!("  - Hide Seccomp: {}", hide_seccomp != 0);
    info!("  - Hide Maps: {}", hide_maps != 0);

    // 构建 Hackcomp
    let mut builder = Builder::new();

    // 添加系统调用日志 Hook
    if enable_logger != 0 && !syscall_list.is_empty() {
        info!("Adding SysLogger hook for {} syscalls", syscall_list.len());
        builder = builder.add_hook(crate::SysLogger::new(&syscall_list));
    }

    // 添加隐藏 Seccomp Hook
    if hide_seccomp != 0 {
        info!("Adding HideSeccomp hook");
        builder = builder.add_hook(crate::HideSeccomp::new());
    }

    // 添加隐藏内存映射 Hook
    if hide_maps != 0 {
        info!("Adding HideMaps hook (hiding 'hackcomp' and 'libhackcomp')");
        builder = builder.add_hook(crate::HideMaps::new(&[
            "hackcomp",
            "libhackcomp",
        ]));
    }

    // 构建并安装
    match builder.build() {
        Ok(hackcomp) => {
            info!("Hackcomp built successfully, installing...");
            match hackcomp.install() {
                Ok(_) => {
                    info!("=================================================");
                    info!("✓ Hackcomp Hooks Installed Successfully!");
                    info!("=================================================");
                    0
                }
                Err(e) => {
                    error!("Failed to install hooks: {:?}", e);
                    error!("=================================================");
                    -1
                }
            }
        }
        Err(e) => {
            error!("Failed to build Hackcomp: {:?}", e);
            error!("=================================================");
            -1
        }
    }
}

/// 辅助函数：解析 Java int 数组为 Rust Vec<Sysno>
fn parse_syscall_array(env: &mut JNIEnv, array: jintArray) -> Result<Vec<Sysno>, String> {
    // 将 jintArray 转换为 JIntArray
    let array_obj = unsafe { JIntArray::from_raw(array) };

    // 获取数组长度
    let len = env
        .get_array_length(&array_obj)
        .map_err(|e| format!("Failed to get array length: {:?}", e))? as usize;

    if len == 0 {
        warn!("Empty syscall array provided");
        return Ok(vec![]);
    }

    // 读取数组内容
    let mut buf = vec![0i32; len];
    env.get_int_array_region(&array_obj, 0, &mut buf)
        .map_err(|e| format!("Failed to read array: {:?}", e))?;

    // 转换为 Sysno
    let syscalls: Vec<Sysno> = buf
        .iter()
        .filter_map(|&num| {
            if num >= 0 {
                // 使用 syscalls crate 将编号转换为 Sysno
                Sysno::new(num as usize)
            } else {
                warn!("Invalid syscall number: {}", num);
                None
            }
        })
        .collect();

    info!("Parsed {} valid syscalls from Java array", syscalls.len());
    for (i, sysno) in syscalls.iter().enumerate() {
        info!("  [{}] {} ({})", i, sysno.name(), sysno.id());
    }

    Ok(syscalls)
}

/// Java 调用入口：检查是否已安装
///
/// Java 签名：
/// ```java
/// public static native boolean isInstalled();
/// ```
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_security_syscallmonitor_HackcompJNI_isInstalled(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    // TODO: 实现状态检查
    // 目前简单返回 false，需要在 lib.rs 中添加全局状态追踪
    0
}

/// Java 调用入口：获取版本信息
///
/// Java 签名：
/// ```java
/// public static native String getVersion();
/// ```
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_security_syscallmonitor_HackcompJNI_getVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let version = env!("CARGO_PKG_VERSION");
    let output = env.new_string(version).unwrap();
    output.into_raw()
}
