"use strict";

// ============================================================================
// Frida Agent —— 敏感 API 拦截代理脚本
// ============================================================================
// 运行环境：目标 APP 进程内部（由 Frida 注入）
// 核心功能：在 Java/Native 层面拦截各类敏感 API 调用，收集隐私行为证据
// 通信机制：通过 send() 将状态消息和 API 调用事件发送给 Python 控制端
//
// 整体架构：
//   1. Native 层早期防护 —— 在 Java 虚拟机就绪前，先通过 Interceptor 拦截
//      libc 中的底层函数，对抗反调试、Root 检测、系统属性探测
//   2. Java 层 Hook 注册 —— 等待 Java Runtime 可用后，在 Java.perform 中
//      批量注册对敏感 API（设备标识、位置、相机、麦克风等）的拦截
//   3. 反分析对抗 —— 对 Magisk/SuperSU/Xposed 等检测行为进行伪装和阻断
// ============================================================================

// 加载 Frida 的 Java 桥接模块，用于与 Android Java 层交互
var Java = require("frida-java-bridge");

// ============================================================================
// Native 早期防护状态记录
// ============================================================================
// 用于防止同一防护模块被重复安装，确保每个 Native Guard 只注册一次
var earlyNativeGuardState = {
    tracerPid: false,      // TracerPid 反调试防护是否已安装
    rootPath: false,       // Root 路径探测防护是否已安装
    systemProperty: false, // 系统属性伪造防护是否已安装
    bootstrapped: false    // 整体早期防护是否已启动（防止多次调用）
};

// ============================================================================
// resolveExport —— 跨版本解析 Native 导出符号地址
// ============================================================================
// 兼容不同 Frida 版本的 API，从指定模块中查找导出函数的地址
//
// @param moduleName - 目标模块名（如 "libc.so"）
// @param symbolName - 目标符号名（如 "fgets"、"access"）
// @returns NativePointer | null —— 找到则返回函数指针，找不到返回 null
//
// 说明：先尝试全局 Module.getExportByName，再尝试 Process.getModuleByName
//       这是为了兼容 Frida 不同版本（12.x / 14.x / 16.x）的 API 差异
function resolveExport(moduleName, symbolName) {
    // 路径 1：尝试 Frida 全局 Module API
    try {
        if (typeof Module !== "undefined" && Module) {
            if (typeof Module.getExportByName === "function") {
                try {
                    return Module.getExportByName(moduleName, symbolName);
                } catch (e) {}
            }
            // 注意：此处原始代码存在语法问题，实际执行时会被外层 catch 捕获
            if (typeof MolName);
                } catch (e) {}
            }
        }
    } catch (e) {}

    // 路径 2：通过 Process 对象获取模块后再查找导出符号
    try {
        if (typeof Process !== "undefined" && Process && typeof Process.getModuleByName === "function") {
            var moduleObject = Process.getModuleByName(moduleName);
            if (moduleObject) {
                // 尝试 getExportByName（新版 API）
                if (typeof moduleObject.getExportByName === "function") {
                    try {
                        return moduleObject.getExportByName(symbolName);
                    } catch (e) {}
                }
                // 尝试 findExportByName（旧版 API，兼容性降级）
                if (typeof moduleObject.findExportByName === "function") {
                    try {
                        return moduleObject.findExportByName(symbolName);
                    } catch (e) {}
                }
            }
        }
    } catch (e) {}

    // 所有路径均失败，返回 null 表示不可用
    return null;
}

// ============================================================================
// readNativeUtf8 —— 安全读取 Native 指针指向的 UTF-8 字符串
// ============================================================================
// @param pointerValue - NativePointer 对象，指向 C 风格字符串
// @returns string —— 成功返回读取的字符串，失败或为空返回 ""
function readNativeUtf8(pointerValue) {
    try {
        if (!pointerValue || pointerValue.isNull()) {
            return "";
        }
        return String(Memory.readUtf8String(pointerValue) || "");
    } catch (e) {
        return "";
    }
}

// ============================================================================
// isSuspiciousNativePath —— 判定文件路径是否为可疑的反分析探测路径
// ============================================================================
// 对 Native 层文件访问路径进行关键字匹配，识别 APP 是否在检测：
//   - su 二进制文件（Root 检测）
//   - Xposed 框架文件
//   - Busybox 工具
//   - Frida 服务端
//   - /proc 进程信息（反调试）
//   - Superuser 超级用户应用
//
// @param pathText - 需要判定的文件路径字符串
// @returns boolean —— 命中任一关键字返回 true，否则返回 false
function isSuspiciousNativePath(pathText) {
    var normalized = String(pathText || "").toLowerCase();
    if (!normalized) return false;
    // 可疑关键字列表 —— 涵盖主流 Root/Xposed/Frida/反调试探测特征
    var keywords = [
        "/system/bin/su",
        "/system/xbin/su",
             "xposed",
        "busybox",
        "frida",
        "/proc/self/status",
        "/proc/",
        "superuser"
    ];
    return keywords.some(function (keyword) { return normalized.indexOf(keyword) !== -1; });
}

// ============================================================================
// installNativeTracerPidGuard —— Native 层 TracerPid 反调试防护
// ============================================================================
// 拦截 libc.so 中 fgets 函数，当 APP 读取 /proc/self/status 中的 TracerPid
// 字段时，将值强制修改为 0，从而隐藏 Frida 调试器附加的痕迹。
//
// 原理：
//   Android 系统中，/proc/self/status 的 TracerPid 字段记录了当前进程
//   是否被 ptrace 附加。Frida 注入会设置此值，APP 通过读取该字段可以发
//   现自己被调试。本防护通过修改 fgets 返回的缓冲区内容来伪造 TracerPid。
function installNativeTracerPidGuard() {
    // 防止重复安装
    if (earlyNativeGuardState.tracerPid) {
        return;
    }
    try {
        // 查找 libc.so 中 fgets 函数的地址
        var fgetsPtr = resolveExport("libc.so", "fgets");
        if (!fgetsPtr || typeof Interceptor === "undefined" || typeof Interceptor.attach !== "function") {
            send({ type: "status", message: "native anti-debug skipped" });
            return;
        }
        // 对 fgets 进行函数级拦截
        Interceptor.attach(fgetsPtr, {
            // 进入函数时：保存读入缓冲区指针
            onEnter: function (args) {
                this.buffer = args[0];
            },
            // 离开函数时：检查并修改 TracerPid 相关内容
            onLeave: function (retval) {
                try {
                    if (!this.buffer || retval.isNull()) return;
                    var line = Memory.readUtf8String(this.buffer);
                    // 如果读取到的行包含 "TracerPid:"，将其值改为 0
                    if (line && line.indexOf("TracerPid:") !== -1) {
                        Memory.writeUtf8String(this.buffer, "TracerPid:\t0");
                    }
                } catch (e) {}
            }
        });
        earlyNativeGuardState.tracerPid = true;
        send({ type: "status", message: "native anti-debug installed" });
    } catch (e) {
        send({ type: "status", message: "native anti-debug skipped: " + e });
    }
}

// ============================================================================
// installNativeRootPathGuard —— Native 层 Root 路径探测防护
// ============================================================================
// 拦截 libc.so 中的文件系统访问函数（access / stat / lstat / open / openat / faccessat），
// 当目标路径命中可疑关键字（su / magisk / frida / xposed 等）时，
// 让函数返回失败（-1），使 APP 认为目标文件不存在。
//
// 覆盖的函数及对应的路径参数位置：
//   access(path, mode)     → args[0]
//   stat(path, buf)        → args[0]
//   lstat(path, buf)       → args[0]
//   open(path, flags)      → args[0]
//   openat(dirfd, path, flags)  → args[1]
//   faccessat(dirfd, path, mode, flags) → args[1]
function installNativeRootPathGuard() {
    // 处理 root / Frida / Xposed 路径探测：拦截 access/stat/open 等 native 文件访问函数，
    // 当目标路径命中可疑关键字时返回失败，降低动态分析环境被识别的概率。
    if (earlyNativeGuardState.rootPath) {
        return;
    }
    try {
        if (typeof Interceptor === "undefined" || typeof Interceptor.attach !== "function") {
            send({ type: "status", message: "native root path guard skipped" });
            return;
        }

        var installedCount = 0;
        // 定义需要拦截的符号及其路径参数在 args 数组中的索引
        [
            { symbol: "access", pathIndex: 0 },
            { symbol: "stat", pathIndex: 0 },
            { symbol: "lstat", pathIndex: 0 },
            { symbol: "open", pathIndex: 0 },
            { symbol: "openat", pathIndex: 1 },
            { symbol: "faccessat", pathIndex: 1 }
        ].forEach(function (hookSpec) {
            // 按变体顺序闭包捕获，避免 JavaScript 闭包变量污染
            var nativePtr = resolveExport("libc.so", hookSpec.symbol);
            if (!nativePtr) {
                return;
            }
            Interceptor.attach(nativePtr, {
                // 进入函数时：读取路径参数并判断是否需要伪装
                onEnter: function (args) {
                    this.targetPath = readNativeUtf8(args[hookSpec.pathIndex]);
                    this.shouldMask = isSuspiciousNativePath(this.targetPath);
                },
                // 离开函数时：如果需要伪装，将返回值设为 -1（失败）
                onLeave: function (retval) {
                    if (!this.shouldMask) {
                        return;
                    }
                    try {
                        retval.replace(ptr("-1"));
                    } catch (replaceError) {
                        try {
                            retval.replace(-1);
                        } catch (ignored) {}
                    }
                }
            });
            installedCount += 1;
        });

        if (installedCount > 0) {
            earlyNativeGuardState.rootPath = true;
            send({ type: "status", message: "native root path guard installed" });
        } else {
            send({ type: "status", message: "native root path guard skipped" });
        }
    } catch (e) {
        send({ type: "status", message: "native root path guard skipped: " + e });
    }
}

// ============================================================================
// installNativeSystemPropertyGuard —— Native 层系统属性伪造防护
// ============================================================================
// 拦截 libc.so 中的 __system_property_get 函数，当 APP 通过 Native 代码
// 读取以下系统属性时，返回伪造的安全值：
//
//   ro.debuggable  → "0"   （伪装为不可调试）
//   ro.secure      → "1"   （伪装为安全模式）
//   ro.build.tags  → "release-keys" （伪装为正式发布版本）
//
// 说明：
//   部分 APP 会在 Native 层直接调用 __system_property_get 绕过 Java 层
//   的 SystemProperties 类，因此需要在 libc 层面再做一层防护。
function installNativeSystemPropertyGuard() {
    if (earlyNativeGuardState.systemProperty) {
        return;
    }
    try {
        // 查找 __system_property_get 符号，注意不同 Android 版本可能有前缀差异
        var propertyPtr = resolveExport("libc.so", "__system_property_get");
        if (!propertyPtr || typeof Interceptor === "undefined" || typeof Interceptor.attach !== "function") {
            send({ type: "status", message: "native system property guard skipped" });
            return;
        }
        Interceptor.attach(propertyPtr, {
            // 进入函数时：记录属性名和返回值缓冲区
            onEnter: function (args) {
                this.key = readNativeUtf8(args[0]).toLowerCase();
                this.valueBuffer = args[1];
            },
            // 离开函数时：如果是敏感属性，替换返回值为安全值
            onLeave: function (retval) {
                if (!this.valueBuffer || !this.key) {
                    return;
                }
                var replacement = "";
                if (this.key === "ro.debuggable") replacement = "0";
                if (this.key === "ro.secure") replacement = "1";
                if (this.key === "ro.build.tags") replacement = "release-keys";
                if (!replacement) {
                    return;
                }
                try {
                    // 将伪造的值写入返回值缓冲区，同时更新返回的长度
                    Memory.writeUtf8String(this.valueBuffer, replacement);
                    retval.replace(ptr(String(replacement.length)));
                } catch (e) {}
            }
        });
        earlyNativeGuardState.systemProperty = true;
        send({ type: "status", message: "native system property guard installed" });
    } catch (e) {
        send({ type: "status", message: "native system property guard skipped: " + e });
    }
}

// ============================================================================
// installEarlyNativeGuards —— 安装所有 Native 层早期防护
// ============================================================================
// 在 Java 虚拟机尚未就绪的阶段，优先部署 Native 层反分析保护。
// 这是对抗 APP 早期检测（启动阶段就进行反调试/环境检测）的关键防线。
//
// 三大防护模块：
//   1. TracerPid 反调试防护 —— 隐藏 Frida 附加痕迹
//   2. Root 路径探测防护 —— 屏蔽可疑文件存在性检测
//   3. 系统属性伪造防护 —— 伪装为正式发布环境
function installEarlyNativeGuards() {
    // 全局仅执行一次，防止重复安装
    if (earlyNativeGuardState.bootstrapped) {
        return;
    }
    earlyNativeGuardState.bootstrapped = true;
    installNativeTracerPidGuard();
    installNativeRootPathGuard();
    installNativeSystemPropertyGuard();
}

// ============================================================================
// bootstrapHooks —— Agent 启动入口（核心引导函数）
// ============================================================================
// 整个 Frida Agent 的主入口，采用分阶段启动策略：
//
// 阶段一（retryCount === 0）：
//   1. 发送启动状态消息通知 Python 控制端
//   2. 立即安装 Native 层早期防护（在 Java 虚拟机就绪前抢占先机）
//
// 阶段二（等待 Java Runtime）：
//   通过 Java.available 轮询检查 Dalvik/ART 是否就绪，最多等待 60 秒。
//   每 10 秒发送一次等待状态消息，便于调试。
//
// 阶段三（Java.perform 内部）：
//   在 Java 桥接就绪后，执行所有 Java 层敏感 API Hook 的注册。
//
// @param retryCount - 当前重试次数，首次调用时为 0
function bootstrapHooks(retryCount) {
    // Agent 启动入口。先安装 native 反分析保护，再等待 Java Runtime 可用，
    // 最后在 Java.perform 中注册具体敏感 API Hook。

    // ========== 阶段一：首次进入，安装 Native 早期防护 ==========
    if ((retryCount || 0) === 0) {
        send({ type: "status", message: "frida bootstrap entered" });
        installEarlyNativeGuards();
    }

    // ========== 阶段二：轮询等待 Java Runtime 就绪 ==========
    if (!Java.available) {
        // 超过 60 次重试（约 60 秒），判定 Java 运行时不可用，上报错误并退出
        if ((retryCount || 0) >= 60) {
            send({ type: "error", message: "Java runtime is not available." });
            return;
        }
        // 每 10 次重试（约 10 秒）发送一次等待状态
        if ((retryCount || 0) % 10 === 0) {
            send({
                type: "status",
                message: "waiting for Java runtime",
                retry: retryCount || 0
            });
        }
        // 1 秒后递归重试
        setTimeout(function () { bootstrapHooks((retryCount || 0) + 1); }, 1000);
        return;
    }

    // ========== 阶段三：Java Runtime 就绪，注册 Hook ==========
    send({ type: "status", message: "java runtime detected" });

    // 兼容不同 Frida 版本的 Java.perform API
    var performWithJava = typeof Java.performNow === "function" ? Java.performNow.bind(Java) : Java.perform.bind(Java);
    try {
        performWithJava(function () {
            send({ type: "status", message: "java bridge ready" });
            try {
            // 获取 Android 基础类引用，后续 Hook 和工具函数会用
            var Log = Java.use("android.util.Log");
            var Exception = Java.use("java.lang.Exception");

            // 记录 Hook 启动时间戳，用于区分"启动窗口期"内的异常行为
            var bootstrapStartedAt = Date.now();

            // ==================================================================
            // 内部工具函数区域
            // ==================================================================

            // s —— 安全地将任意值转换为字符串
            // 用于将 Java 参数/返回值转换为可序列化的字符串，
            // 超过 280 字符会被截断（防止日志过大）
            function s(v) {
                try {
                    if (v === null || v === undefined) return "";
                    var t = String(v);
                    return t.length > 280 ? t.slice(0, 280) + "..." : t;
                } catch (e) {
                    return "[unprintable]";
                }
            }

            // stack —— 获取当前调用栈的字符串表示
            // 利用 android.util.Log.getStackTraceString 获取 Java 层调用栈，
            // 用于分析 API 调用的来源和上下文
            function stack() {
                try {
                    return s(Log.getStackTraceString(Exception.$new()));
                } catch (e) {
                    return "";
                }
            }

            // sendStatus —— 发送状态消息到 Python 控制端
            // 用于上报 Hook 进度、安装状态等非敏感运行时信息
            function sendStatus(message) {
                send({ type: "status", timestamp: Date.now() / 1000, message: message });
            }

            // sendError —— 发送错误消息到 Python 控制端
            // 集中处理异常上报，便于诊断 Hook 安装失败原因
            function sendError(message) {
                send({ type: "error", timestamp: Date.now() / 1000, message: String(message) });
            }

            // safeStackLower —— 安全获取小写的调用栈字符串
            // 将 stack() 结果转为小写后返回，失败则返回空字符串
            function safeStackLower() {
                try {
                    return stack().toLowerCase();
                } catch (e) {
                    return "";
                }
            }

            // withinStartupGuardWindow —— 判断当前是否处于启动保护窗口期
            // 返回值：true 表示距离启动不超过 20 秒
            // 用途：在启动窗口期内增强反分析保护力度（如阻止自杀行为）
            function withinStartupGuardWindow() {
                return Date.now() - bootstrapStartedAt <= 20000;
            }

            // isSecurityProbeText —— 判断文本是否包含反分析探测特征关键词
            // 用于识别 APP 通过 exec 命令或其他方式执行的安全探测行为
            function isSecurityProbeText(text) {
                return has(text, [
                    "su",
                    "magisk",
                    "zygisk",
                    "xposed",
                    "busybox",
                    "frida",
                    "tracerpid",
                    "/proc/self/status",
                    "getprop",
                    "which"
                ]);
            }

            // isSecurityStack —— 判断调用栈是否涉及反分析相关代码
            // 用于利用调用栈信息识别来自安全检测模块的 API 调用
            function isSecurityStack(stackText) {
                return has(stackText, [
                    "root",
                    "magisk",
                    "zygisk",
                    "xposed",
                    "frida",
                    "hook",
                    "tracerpid",
                    "debug",
                    "su"
                ]);
            }

            // sanitizeExecArg —— 清洗 exec 命令参数中的敏感内容
            // 如果参数包含安全探测关键词，替换为 "invalid_command" 使命令执行失败
            // 支持字符串和数组两种参数形式（兼容 Runtime.exec 的不同重载）
            function sanitizeExecArg(value) {
                if (value === null || value === undefined) return value;
                if (typeof value === "string") {
                    return isSecurityProbeText(value) ? "invalid_command" : value;
                }
                try {
                    // 处理数组类型参数（如 Runtime.exec(String[]) ）
                    if (typeof value.length === "number") {
                        for (var i = 0; i < value.length; i++) {
                            var itemText = s(value[i]);
                            if (itemText && isSecurityProbeText(itemText)) {
                                value[i] = "invalid_command";
                            }
                        }
                    }
                } catch (e) {}
                return value;
            }

            // shouldBlockTermination —— 判断是否应该阻止进程终止操作
            // 条件：处于启动窗口期（20 秒内）且检测到反分析行为特征
            // 用途：阻止 APP 在检测到 Hook 环境后通过 System.exit / killProcess
            //       / Activity.finish 等方式自杀
            function shouldBlockTermination(reasonText) {
                var stackText = safeStackLower();
                if (!withinStartupGuardWindow()) return false;
                return isSecurityProbeText(reasonText) || isSecurityStack(stackText);
            }

            // ==================================================================
            // sendApi —— 上报 API 调用事件（核心通信函数）
            // ==================================================================
            // 将拦截到的敏感 API 调用构造为标准事件格式，通过 send() 发送给 Python 控制端。
            // 每条事件包含：时间戳、分类、信号键、API 名称、描述、参数列表、返回值、调用栈
            //
            // @param meta  - { category, signalKey, api, description } 元信息对象
            // @param args  - 调用参数数组
            // @param ret   - 返回值
            // @param extra - 额外字段（如分类重写、包名等），会被合并到 payload 中
            function sendApi(meta, args, ret, extra) {
                var payload = {
                    type: "api_call",
                    timestamp: Date.now() / 1000,
                    category: meta.category || "other",
                    signal_key: meta.signalKey || meta.api,
                    api: meta.api,
                    description: meta.description || meta.api,
                    args: (args || []).map(s),
                    return_value: s(ret),
                    stack: stack()
                };
                // 合并额外字段（如 enrich 函数添加的 service_name、uri 等）
                if (extra) {
                    Object.keys(extra).forEach(function (key) { payload[key] = extra[key]; });
                }
                send(payload);
            }

            // sendAntiAnalysisProbe —— 上报反分析探测事件（sendApi 的便捷封装）
            // 专门用于记录 APP 的安全分析/环境检测行为
            function sendAntiAnalysisProbe(apiName, detailText, extra) {
                sendApi(
                    {
                        category: "anti_analysis",
                        signalKey: "antiAnalysisProbe",
                        api: apiName,
                        description: detailText || "anti-analysis probe"
                    },
                    detailText ? [detailText] : [],
                    "",
                    extra || {}
                );
            }

            // has —— 判断文本是否包含 patterns 数组中的任一关键词
            // 大小写不敏感的模糊匹配，用于安全特征识别
            function has(text, patterns) {
                var normalized = s(text).toLowerCase();
                return patterns.some(function (item) { return normalized.indexOf(item) !== -1; });
            }

        // ======================================================================
        // hookMethod —— 通用 Java 方法 Hook 包装器（核心 Hook 引擎）
        // ======================================================================
        // 对指定 Java 类的指定方法的所有重载（overloads）进行拦截。
        // 拦截流程：
        //   1. 通过 Java.use 获取目标类
        //   2. 遍历目标方法的所有重载（overloads）
        //   3. 为每个重载替换 implementation，插入拦截逻辑
        //   4. 先调用原始方法获取真实返回值，再通过 sendApi 上报
        //   5. 支持 filter（过滤）和 enrich（丰富信息）两个可选回调
        //
        // @param className  - Java 类的完全限定名（如 "android.telephony.TelephonyManager"）
        // @param methodName - 要 Hook 的方法名
        // @param meta       - { category, signalKey, api, description } 元信息
        // @param options    - { filter?, enrich? } 可选配置
        //   filter: function(args, ret) => boolean —— 返回 true 才上报事件
        //   enrich: function(args, ret) => object  —— 添加上报的额外字段
        // @returns boolean —— Hook 成功返回 true，失败返回 false
        function hookMethod(className, methodName, meta, options) {
            try {
                var Target = Java.use(className);
                if (!Target[methodName]) return false;
                // 遍历所有重载变体，确保每种参数组合都被拦截
                Target[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        // 将 arguments 转为标准数组
                        var args = Array.prototype.slice.call(arguments);
                        var ret;
                        // 先执行原始方法逻辑，确保 APP 正常运行不受影响
                        try {
                            ret = overload.call.apply(overload, [this].concat(args));
                        } catch (callError) {
                            // 原始方法抛出异常时也上报（标记 error: true）
                            sendApi(meta, args, "[throw] " + callError, { error: true });
                            throw callError;
                        }
                        // 根据 filter 判定是否需要上报，根据 enrich 添加补充信息
                        try {
                            var ok = !options || !options.filter || !!options.filter(args, ret);
                            var extra = ok && options && options.enrich ? (options.enrich(args, ret) || {}) : {};
                            if (ok) sendApi(meta, args, ret, extra);
                        } catch (e) {
                            sendError(className + "." + methodName + " -> " + e);
                        }
                        return ret;
                    };
                });
                sendStatus("hooked " + className + "." + methodName);
                return true;
            } catch (e) {
                return false;
            }
        }

        // installNativeAntiDebug —— Java 层触发的 Native 反调试保护安装
        // 实际上委托给全局的 installNative*Guard 函数执行
        function installNativeAntiDebug() {
            installNativeTracerPidGuard();
            installNativeRootPathGuard();
            installNativeSystemPropertyGuard();
        }

        // ======================================================================
        // installRootBypass —— Root 检测全面绕过（关键防护模块）
        // ======================================================================
        // 通过 Hook 多个关键 Java API，系统性地对抗 APP 的以下检测行为：
        //
        //   1. 文件存在性检测（java.io.File.exists）
        //      → 对 su/magisk/frida 路径返回 false
        //
        //   2. 命令行执行探测（Runtime.exec / ProcessBuilder.start）
        //      → 清洗包含安全探测特征的命令参数
        //
        //   3. 调试检测（Debug.isDebuggerConnected / waitingForDebugger）
        //      → 始终返回 false
        //
        //   4. 系统属性检测（SystemProperties.get）
        //      → ro.debuggable → "0", ro.secure → "1", ro.build.tags → "release-keys"
        //
        //   5. 可疑包名检测（PackageManager.getPackageInfo / getApplicationInfo）
        //      → 查询 Magisk/SuperSU/Xposed 包名时抛出 NameNotFoundException
        //
        //   6. 进程自杀检测（System.exit / Process.killProcess / Activity.finish）
        //      → 启动窗口期（20秒）内阻止任何终止行为
        function installRootBypass() {
            try {
                // 预加载所有需要使用的 Java 类
                var File = Java.use("java.io.File");
                var Runtime = Java.use("java.lang.Runtime");
                var Debug = Java.use("android.os.Debug");
                var SystemProperties = Java.use("android.os.SystemProperties");
                var Activity = Java.use("android.app.Activity");
                var Process = Java.use("android.os.Process");
                var SystemClass = Java.use("java.lang.System");
                var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
                var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
                var NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
                var ArrayList = Java.use("java.util.ArrayList");

                // 可疑文件路径列表（Root / Frida 特征路径）
                var suspicious = ["/system/bin/su", "/system/xbin/su", "/data/local/tmp/frida-server", "magisk", "frida"];

                // 可疑应用包名列表（Magisk / SuperSU / Xposed 等）
                var suspiciousPackages = [
                    "com.topjohnwu.magisk",
                    "eu.chainfire.supersu",
                    "com.thirdparty.superuser",
                    "com.koushikdutta.superuser",
                    "de.robv.android.xposed.installer",
                    "io.github.vvb2060.magisk"
                ];

                // -------- 1. 文件存在性检测绕过 --------
                var exists = File.exists.overload();
                exists.implementation = function () {
                    var absolutePath = s(this.getAbsolutePath());
                    // 如果路径命中了可疑列表，上报探测事件并返回 false（文件不存在）
                    if (has(absolutePath, suspicious)) {
                        sendAntiAnalysisProbe("java.io.File.exists", "probe suspicious path: " + absolutePath, { path: absolutePath });
                        return false;
                    }
                    return exists.call(this);
                };

                // -------- 2. Runtime.exec 命令行清洗 --------
                Runtime.exec.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var joinedCommand = s(args);
                        // 检测到安全探测命令时上报
                        if (isSecurityProbeText(joinedCommand)) {
                            sendAntiAnalysisProbe("java.lang.Runtime.exec", "runtime exec security probe", { command: joinedCommand });
                        }
                        // 清洗所有参数中的敏感内容
                        for (var i = 0; i < args.length; i++) {
                            args[i] = sanitizeExecArg(args[i]);
                        }
                        return overload.call.apply(overload, [this].concat(args));
                    };
                });

                // -------- 3. ProcessBuilder.start 命令清洗 --------
                try {
                    var startProcessBuilder = ProcessBuilder.start.overload();
                    startProcessBuilder.implementation = function () {
                        try {
                            var commandList = this.command();
                            var joined = s(commandList);
                            // 如果命令中检测到安全探测特征，替换为无害命令
                            if (isSecurityProbeText(joined)) {
                                var safeList = ArrayList.$new();
                                safeList.add("invalid_command");
                                this.command(safeList);
                                sendAntiAnalysisProbe("java.lang.ProcessBuilder.start", "process builder security probe", { command: joined });
                                sendStatus("neutralized ProcessBuilder root probe");
                            }
                        } catch (e) {}
                        return startProcessBuilder.call(this);
                    };
                } catch (e) {
                    sendError("process builder bypass failed: " + e);
                }

                // -------- 4. 调试检测绕过 --------
                // 始终返回 false，让 APP 认为没有调试器连接
                Debug.isDebuggerConnected.implementation = function () {
                    return false;
                };
                Debug.waitingForDebugger.implementation = function () {
                    return false;
                };

                // -------- 5. 系统属性伪造（单参数版） --------
                try {
                    var getProperty = SystemProperties.get.overload("java.lang.String");
                    getProperty.implementation = function (key) {
                        var normalized = s(key).toLowerCase();
                        // 记录对敏感属性的探测行为
                        if (normalized === "ro.debuggable" || normalized === "ro.secure" || normalized === "ro.build.tags") {
                            sendAntiAnalysisProbe("android.os.SystemProperties.get", "system property probe: " + normalized, { property_key: normalized });
                        }
                        // 返回伪造的安全值
                        if (normalized === "ro.debuggable") return "0";
                        if (normalized === "ro.secure") return "1";
                        if (normalized === "ro.build.tags") return "release-keys";
                        return getProperty.call(this, key);
                    };
                } catch (e) {}

                // -------- 6. 系统属性伪造（双参数带默认值版） --------
                try {
                    var getPropertyDefault = SystemProperties.get.overload("java.lang.String", "java.lang.String");
                    getPropertyDefault.implementation = function (key, fallback) {
                        var normalized = s(key).toLowerCase();
                        if (normalized === "ro.debuggable" || normalized === "ro.secure" || normalized === "ro.build.tags") {
                            sendAntiAnalysisProbe("android.os.SystemProperties.get", "system property probe: " + normalized, { property_key: normalized });
                        }
                        if (normalized === "ro.debuggable") return "0";
                        if (normalized === "ro.secure") return "1";
                        if (normalized === "ro.build.tags") return "release-keys";
                        return getPropertyDefault.call(this, key, fallback);
                    };
                } catch (e) {}

                // -------- 7. 可疑应用包名查询拦截 --------
                // 当 APP 通过 PackageManager 查询 Magisk/SuperSU/Xposed 等包信息时，
                // 抛出 NameNotFoundException 异常，伪装为"未安装"
                try {
                    ["getPackageInfo", "getApplicationInfo"].forEach(function (methodName) {
                        if (!ApplicationPackageManager[methodName]) return;
                        ApplicationPackageManager[methodName].overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                var packageName = s(arguments[0]).toLowerCase();
                                if (suspiciousPackages.indexOf(packageName) !== -1) {
                                    sendAntiAnalysisProbe("android.app.ApplicationPackageManager." + methodName, "query suspicious package: " + packageName, { package_name: packageName });
                                    throw NameNotFoundException.$new(arguments[0]);
                                }
                                return overload.call.apply(overload, [this].concat(Array.prototype.slice.call(arguments)));
                            };
                        });
                    });
                } catch (e) {
                    sendError("package manager bypass failed: " + e);
                }

                // -------- 8. System.exit 自杀拦截 --------
                // 启动窗口期内阻止进程退出，防止 APP 发现被 Hook 后自杀
                try {
                    var systemExit = SystemClass.exit.overload("int");
                    systemExit.implementation = function (code) {
                        if (shouldBlockTermination("system.exit " + code)) {
                            sendAntiAnalysisProbe("java.lang.System.exit", "blocked system exit during startup", { exit_code: s(code) });
                            sendStatus("blocked System.exit during startup security probe");
                            return;
                        }
                        return systemExit.call(this, code);
                    };
                } catch (e) {}

                // -------- 9. Process.killProcess 自杀拦截 --------
                try {
                    var killProcess = Process.killProcess.overload("int");
                    killProcess.implementation = function (pid) {
                        if (shouldBlockTermination("killProcess " + pid)) {
                            sendAntiAnalysisProbe("android.os.Process.killProcess", "blocked killProcess during startup", { pid: s(pid) });
                            sendStatus("blocked Process.killProcess during startup security probe");
                            return;
                        }
                        return killProcess.call(this, pid);
                    };
                } catch (e) {}

                // -------- 10. Activity 终止拦截 --------
                // 拦截 finish / finishAffinity / finishAndRemoveTask，
                // 防止 APP 通过关闭 Activity 来退出
                ["finish", "finishAffinity", "finishAndRemoveTask"].forEach(function (methodName) {
                    try {
                        if (!Activity[methodName]) return;
                        Activity[methodName].overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                if (shouldBlockTermination("activity." + methodName)) {
                                    sendAntiAnalysisProbe("android.app.Activity." + methodName, "blocked activity termination during startup", { method: methodName });
                                    sendStatus("blocked Activity." + methodName + " during startup security probe");
                                    return;
                                }
                                return overload.call.apply(overload, [this].concat(Array.prototype.slice.call(arguments)));
                            };
                        });
                    } catch (e) {}
                });
                sendStatus("root bypass installed");
            } catch (e) {
                sendError("root bypass failed: " + e);
            }
        }

        // ======================================================================
        // hookSimple —— 批量 Hook 注册（便捷方法）
        // ======================================================================
        // 遍历配置列表，逐条调用 hookMethod 进行注册。
        // 每条配置包含：className、methodName、meta、options（可选）
        function hookSimple(items) {
            items.forEach(function (item) {
                hookMethod(item.className, item.methodName, item.meta, item.options);
            });
        }

        // ======================================================================
        // classifyService —— 系统服务分类识别
        // ======================================================================
        // 根据 getSystemService 传入的服务名，识别其隐私敏感类别
        //
        // @param name - 服务名字符串（如 "location"、"phone"）
        // @returns { category, signalKey, description } | null
        function classifyService(name) {
            var service = s(name).toLowerCase();
            if (has(service, ["location", "gps"])) return { category: "location", signalKey: "getLocation", description: "request location service" };
            if (has(service, ["phone", "telephony"])) return { category: "device_identifier", signalKey: "getDeviceId", description: "request telephony service" };
            if (has(service, ["camera"])) return { category: "camera", signalKey: "openCamera", description: "request camera service" };
            if (has(service, ["audio", "media"])) return { category: "microphone", signalKey: "startRecording", description: "request audio service" };
            if (has(service, ["clipboard"])) return { category: "clipboard", signalKey: "readClipboard", description: "request clipboard service" };
            if (has(service, ["account"])) return { category: "account", signalKey: "getAccount", description: "request account service" };
            if (has(service, ["package", "launcher"])) return { category: "package_manager", signalKey: "getInstalledPackages", description: "request package service" };
            return null;
        }

        // ======================================================================
        // classifyUri —— ContentProvider URI 分类识别
        // ======================================================================
        // 根据 ContentResolver 操作的目标 URI，识别其访问的数据类型
        //
        // @param uriText - URI 字符串（如 "content://contacts/..."）
        // @returns { category, signalKey, description } | null
        function classifyUri(uriText) {
            var uri = s(uriText).toLowerCase();
            if (has(uri, ["contacts", "com.android.contacts"])) return { category: "contacts", signalKey: "readContacts", description: "access contacts provider" };
            if (has(uri, ["sms", "mms", "mms-sms"])) return { category: "sms", signalKey: "readSms", description: "access sms provider" };
            if (has(uri, ["call_log", "calllog"])) return { category: "call_log", signalKey: "readCallLog", description: "access call log provider" };
            if (has(uri, ["calendar", "com.android.calendar"])) return { category: "calendar", signalKey: "accessCalendar", description: "access calendar provider" };
            if (has(uri, ["media", "external", "downloads"])) return { category: "storage", signalKey: "accessStorage", description: "access storage provider" };
            return null;
        }

        // ======================================================================
        // getAppOpsMeta —— AppOps 操作码分类识别
        // ======================================================================
        // 将 AppOpsManager 的操作码（整数或字符串）映射为隐私类别元信息。
        // 支持两种映射方式：
        //   1. 数字码映射（codeMap）—— 兼容旧版 Android API
        //   2. 字符串常量映射（stringMap）—— 兼容 Android 10+ 的 OPSTR_* 常量
        //   3. 模糊关键字匹配 —— 兜底方案
        //
        // @param opValue - AppOps 操作码（数字或字符串）
        // @returns { opName, category, signalKey, description } | null
        function getAppOpsMeta(opValue) {
            var text = s(opValue).toLowerCase();
            var code = null;
            // 尝试将操作码解析为整数
            if (typeof opValue === "number") {
                code = opValue;
            } else if (/^-?\d+$/.test(text)) {
                code = parseInt(text, 10);
            }

            // 数字码 → 隐私类别映射表
            var codeMap = {
                0: { opName: "OP_COARSE_LOCATION", category: "location", signalKey: "getLocation", description: "AppOps coarse location" },
                1: { opName: "OP_FINE_LOCATION", category: "location", signalKey: "getLocation", description: "AppOps fine location" },
                4: { opName: "OP_READ_CONTACTS", category: "contacts", signalKey: "readContacts", description: "AppOps read contacts" },
                6: { opName: "OP_READ_CALL_LOG", category: "call_log", signalKey: "readCallLog", description: "AppOps read call log" },
                8: { opName: "OP_READ_CALENDAR", category: "calendar", signalKey: "accessCalendar", description: "AppOps read calendar" },
                14: { opName: "OP_READ_SMS", category: "sms", signalKey: "readSms", description: "AppOps read sms" },
                20: { opName: "OP_SEND_SMS", category: "sms", signalKey: "sendSms", description: "AppOps send sms" },
                26: { opName: "OP_CAMERA", category: "camera", signalKey: "openCamera", description: "AppOps camera" },
                27: { opName: "OP_RECORD_AUDIO", category: "microphone", signalKey: "startRecording", description: "AppOps record audio" },
                59: { opName: "OP_READ_EXTERNAL_STORAGE", category: "storage", signalKey: "accessStorage", description: "AppOps read external storage" },
                60: { opName: "OP_WRITE_EXTERNAL_STORAGE", category: "storage", signalKey: "accessStorage", description: "AppOps write external storage" },
                87: { opName: "OP_RECORD_AUDIO_HOTWORD", category: "microphone", signalKey: "startRecording", description: "AppOps hotword audio" }
            };
            if (code !== null && codeMap[code]) {
                return codeMap[code];
            }

            // 字符串常量 → 隐私类别映射表（Android 10+ OPSTR_* 格式）
            var stringMap = {
                "android:coarse_location": { opName: "OPSTR_COARSE_LOCATION", category: "location", signalKey: "getLocation", description: "AppOps coarse location" },
                "android:fine_location": { opName: "OPSTR_FINE_LOCATION", category: "location", signalKey: "getLocation", description: "AppOps fine location" },
                "android:camera": { opName: "OPSTR_CAMERA", category: "camera", signalKey: "openCamera", description: "AppOps camera" },
                "android:record_audio": { opName: "OPSTR_RECORD_AUDIO", category: "microphone", signalKey: "startRecording", description: "AppOps record audio" },
                "android:read_contacts": { opName: "OPSTR_READ_CONTACTS", category: "contacts", signalKey: "readContacts", description: "AppOps read contacts" },
                "android:read_call_log": { opName: "OPSTR_READ_CALL_LOG", category: "call_log", signalKey: "readCallLog", description: "AppOps read call log" },
                "android:read_calendar": { opName: "OPSTR_READ_CALENDAR", category: "calendar", signalKey: "accessCalendar", description: "AppOps read calendar" },
                "android:read_sms": { opName: "OPSTR_READ_SMS", category: "sms", signalKey: "readSms", description: "AppOps read sms" },
                "android:send_sms": { opName: "OPSTR_SEND_SMS", category: "sms", signalKey: "sendSms", description: "AppOps send sms" },
                "android:read_external_storage": { opName: "OPSTR_READ_EXTERNAL_STORAGE", category: "storage", signalKey: "accessStorage", description: "AppOps read storage" },
                "android:write_external_storage": { opName: "OPSTR_WRITE_EXTERNAL_STORAGE", category: "storage", signalKey: "accessStorage", description: "AppOps write storage" },
                "android:get_usage_stats": { opName: "OPSTR_GET_USAGE_STATS", category: "system_inspection", signalKey: "appOpsSensitiveAction", description: "AppOps usage stats" },
                "android:read_clipboard": { opName: "OPSTR_READ_CLIPBOARD", category: "clipboard", signalKey: "readClipboard", description: "AppOps read clipboard" },
                "android:write_clipboard": { opName: "OPSTR_WRITE_CLIPBOARD", category: "clipboard", signalKey: "readClipboard", description: "AppOps write clipboard" },
                "android:access_accessibility": { opName: "OPSTR_ACCESS_ACCESSIBILITY", category: "system_control", signalKey: "appOpsSensitiveAction", description: "AppOps accessibility" }
            };
            if (stringMap[text]) {
                return stringMap[text];
            }

            // 兜底：通过关键字模糊匹配（用于未知或自定义操作码）
            if (has(text, ["location"])) return { opName: text || "OPSTR_LOCATION", category: "location", signalKey: "getLocation", description: "AppOps location" };
            if (has(text, ["camera"])) return { opName: text || "OPSTR_CAMERA", category: "camera", signalKey: "openCamera", description: "AppOps camera" };
            if (has(text, ["audio", "record"])) return { opName: text || "OPSTR_RECORD_AUDIO", category: "microphone", signalKey: "startRecording", description: "AppOps microphone" };
            if (has(text, ["contacts"])) return { opName: text || "OPSTR_READ_CONTACTS", category: "contacts", signalKey: "readContacts", description: "AppOps contacts" };
            if (has(text, ["call_log"])) return { opName: text || "OPSTR_READ_CALL_LOG", category: "call_log", signalKey: "readCallLog", description: "AppOps call log" };
            if (has(text, ["calendar"])) return { opName: text || "OPSTR_READ_CALENDAR", category: "calendar", signalKey: "accessCalendar", description: "AppOps calendar" };
            if (has(text, ["sms"])) return { opName: text || "OPSTR_SMS", category: "sms", signalKey: "readSms", description: "AppOps sms" };
            if (has(text, ["storage", "external"])) return { opName: text || "OPSTR_STORAGE", category: "storage", signalKey: "accessStorage", description: "AppOps storage" };
            if (has(text, ["clipboard"])) return { opName: text || "OPSTR_CLIPBOARD", category: "clipboard", signalKey: "readClipboard", description: "AppOps clipboard" };
            return null;
        }

        // ======================================================================
        // buildAppOpsExtra —— 构造 AppOps 事件补充信息
        // ======================================================================
        // 从 AppOpsManager 的调用参数中提取操作码和包名，构造 enriched extra 对象
        //
        // @param args - 函数调用参数数组，args[0] 为操作码，后续参数中查找包名
        // @returns { app_op, package_name, category, signal_key, description }
        function buildAppOpsExtra(args) {
            var meta = getAppOpsMeta(args && args.length > 0 ? args[0] : null) || {};
            var packageName = "";
            // 从后续参数中查找包名（包含 "." 且不以 "android:" 开头的字符串）
            for (var i = 1; i < (args || []).length; i++) {
                var argText = s(args[i]);
                if (argText.indexOf(".") !== -1 && argText.indexOf("android:") !== 0) {
                    packageName = argText;
                    break;
                }
            }
            return {
                app_op: meta.opName || s(args && args.length > 0 ? args[0] : ""),
                package_name: packageName,
                category: meta.category || "app_ops",
                signal_key: meta.signalKey || "appOpsSensitiveAction",
                description: meta.description || "AppOps sensitive action"
            };
        }

        // ========== 安装 Native 反调试和 Root 绕过 ==========
        installNativeAntiDebug();
        installRootBypass();

        // ======================================================================
        // AppOpsManager Hook —— 权限操作拦截
        // ======================================================================
        // 拦截 AppOpsManager 的 8 个核心方法（noteOp / checkOp / startOp 系列），
        // 通过 filter 过滤掉非敏感操作，通过 enrich 补充操作码和包名信息。
        // AppOps 是 Android 权限管理的底层机制，能捕获到通过任何方式触发的权限操作。
        ["noteOp", "noteOpNoThrow", "noteProxyOp", "noteProxyOpNoThrow", "checkOp", "checkOpNoThrow", "startOp", "startOpNoThrow"].forEach(function (methodName) {
            hookMethod("android.app.AppOpsManager", methodName, {
                category: "app_ops",
                signalKey: "appOpsSensitiveAction",
                api: "android.app.AppOpsManager." + methodName,
                description: "observe AppOps sensitive action"
            }, {
                // filter：只上报已知的敏感操作码对应的事件
                filter: function (args) {
                    return args && args.length > 0 && getAppOpsMeta(args[0]) !== null;
                },
                // enrich：提取操作码名称和包名作为补充信息
                enrich: function (args) {
                    return buildAppOpsExtra(args);
                }
            });
        });

        // ======================================================================
        // 敏感 API Hook 配置区（批量注册）
        // ======================================================================
        // 以下通过 hookSimple 批量注册各种隐私敏感 API 的拦截。
        // 每行配置定义一个 Hook 点，包括目标类、方法、分类元信息。
        //
        // Hook 覆盖的隐私类别：
        //   1. 设备标识符（IMEI / IMSI / MAC / Android ID / 序列号 / OAID）
        //   2. 位置信息（GPS / Fused Location）
        //   3. 相机
        //   4. 麦克风 / 录音
        //   5. 剪切板
        //   6. 账户信息
        //   7. 已安装应用列表
        //   8. 权限请求 / 权限检查
        //   9. WebView 导航 / Cookie
        //  10. 网络连接
        //  11. 文件存储
        //  12. 短信发送
        hookSimple([
            // ===== 设备标识符 =====
            { className: "android.telephony.TelephonyManager", methodName: "getDeviceId", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.telephony.TelephonyManager.getDeviceId", description: "read device IMEI or MEID" } },
            { className: "android.telephony.TelephonyManager", methodName: "getImei", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.telephony.TelephonyManager.getImei", description: "read IMEI" } },
            { className: "android.telephony.TelephonyManager", methodName: "getMeid", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.telephony.TelephonyManager.getMeid", description: "read MEID" } },
            { className: "android.telephony.TelephonyManager", methodName: "getSubscriberId", meta: { category: "device_identifier", signalKey: "getSubscriberId", api: "android.telephony.TelephonyManager.getSubscriberId", description: "read IMSI" } },
            { className: "android.telephony.TelephonyManager", methodName: "getSimSerialNumber", meta: { category: "device_identifier", signalKey: "getSubscriberId", api: "android.telephony.TelephonyManager.getSimSerialNumber", description: "read SIM serial" } },
            { className: "android.telephony.TelephonyManager", methodName: "getLine1Number", meta: { category: "device_identifier", signalKey: "getSubscriberId", api: "android.telephony.TelephonyManager.getLine1Number", description: "read phone number" } },
            // Settings.Secure.getString —— 仅当读取 android_id 时才上报（通过 filter 过滤）
            { className: "android.provider.Settings$Secure", methodName: "getString", meta: { category: "device_identifier", signalKey: "getAndroidId", api: "android.provider.Settings$Secure.getString", description: "read Android ID" }, options: { filter: function (args) { return args.length > 1 && s(args[1]).toLowerCase() === "android_id"; } } },
            { className: "android.provider.Settings$System", methodName: "getString", meta: { category: "device_identifier", signalKey: "getAndroidId", api: "android.provider.Settings$System.getString", description: "read Android ID" }, options: { filter: function (args) { return args.length > 1 && s(args[1]).toLowerCase() === "android_id"; } } },
            { className: "android.os.Build", methodName: "getSerial", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.os.Build.getSerial", description: "read device serial" } },
            // MAC 地址
            { className: "android.net.wifi.WifiInfo", methodName: "getMacAddress", meta: { category: "device_identifier", signalKey: "getMacAddress", api: "android.net.wifi.WifiInfo.getMacAddress", description: "read MAC" } },
            { className: "android.bluetooth.BluetoothAdapter", methodName: "getAddress", meta: { category: "device_identifier", signalKey: "getMacAddress", api: "android.bluetooth.BluetoothAdapter.getAddress", description: "read Bluetooth MAC" } },

            // ===== 位置信息 =====
            { className: "android.location.LocationManager", methodName: "getLastKnownLocation", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.getLastKnownLocation", description: "read last location" } },
            { className: "android.location.LocationManager", methodName: "requestLocationUpdates", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.requestLocationUpdates", description: "request location updates" } },
            { className: "android.location.LocationManager", methodName: "requestSingleUpdate", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.requestSingleUpdate", description: "request single update" } },
            { className: "android.location.LocationManager", methodName: "getCurrentLocation", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.getCurrentLocation", description: "request current location" } },
            // Google Play Services 融合定位
            { className: "com.google.android.gms.location.FusedLocationProviderClient", methodName: "getLastLocation", meta: { category: "location", signalKey: "getLocation", api: "com.google.android.gms.location.FusedLocationProviderClient.getLastLocation", description: "read fused location" } },
            { className: "com.google.android.gms.location.FusedLocationProviderClient", methodName: "requestLocationUpdates", meta: { category: "location", signalKey: "getLocation", api: "com.google.android.gms.location.FusedLocationProviderClient.requestLocationUpdates", description: "request fused updates" } },
            { className: "com.google.android.gms.location.FusedLocationProviderClient", methodName: "getCurrentLocation", meta: { category: "location", signalKey: "getLocation", api: "com.google.android.gms.location.FusedLocationProviderClient.getCurrentLocation", description: "request fused current location" } },

            // ===== 相机 =====
            { className: "android.hardware.Camera", methodName: "open", meta: { category: "camera", signalKey: "openCamera", api: "android.hardware.Camera.open", description: "open legacy camera" } },
            { className: "android.hardware.camera2.CameraManager", methodName: "openCamera", meta: { category: "camera", signalKey: "openCamera", api: "android.hardware.camera2.CameraManager.openCamera", description: "open Camera2 camera" } },
            { className: "androidx.camera.core.ImageCapture", methodName: "takePicture", meta: { category: "camera", signalKey: "openCamera", api: "androidx.camera.core.ImageCapture.takePicture", description: "capture photo by CameraX" } },

            // ===== 麦克风 / 录音 =====
            { className: "android.media.MediaRecorder", methodName: "start", meta: { category: "microphone", signalKey: "startRecording", api: "android.media.MediaRecorder.start", description: "start recorder" } },
            { className: "android.media.MediaRecorder", methodName: "setAudioSource", meta: { category: "microphone", signalKey: "startRecording", api: "android.media.MediaRecorder.setAudioSource", description: "set audio source" } },
            { className: "android.media.AudioRecord", methodName: "startRecording", meta: { category: "microphone", signalKey: "startRecording", api: "android.media.AudioRecord.startRecording", description: "start audio record" } },
            { className: "android.speech.SpeechRecognizer", methodName: "startListening", meta: { category: "microphone", signalKey: "startRecording", api: "android.speech.SpeechRecognizer.startListening", description: "start speech recognizer" } },

            // ===== 剪切板 =====
            { className: "android.content.ClipboardManager", methodName: "getPrimaryClip", meta: { category: "clipboard", signalKey: "readClipboard", api: "android.content.ClipboardManager.getPrimaryClip", description: "read clipboard" } },
            { className: "android.content.ClipboardManager", methodName: "setPrimaryClip", meta: { category: "clipboard", signalKey: "readClipboard", api: "android.content.ClipboardManager.setPrimaryClip", description: "write clipboard" } },

            // ===== 账户信息 =====
            { className: "android.accounts.AccountManager", methodName: "getAccounts", meta: { category: "account", signalKey: "getAccount", api: "android.accounts.AccountManager.getAccounts", description: "read account list" } },
            { className: "android.accounts.AccountManager", methodName: "getAccountsByType", meta: { category: "account", signalKey: "getAccount", api: "android.accounts.AccountManager.getAccountsByType", description: "read accounts by type" } },
            { className: "android.accounts.AccountManager", methodName: "getAccountsByTypeAndFeatures", meta: { category: "account", signalKey: "getAccount", api: "android.accounts.AccountManager.getAccountsByTypeAndFeatures", description: "read accounts by features" } },

            // ===== 已安装应用列表 =====
            { className: "android.app.ApplicationPackageManager", methodName: "getInstalledPackages", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.getInstalledPackages", description: "read installed packages" } },
            { className: "android.app.ApplicationPackageManager", methodName: "getInstalledApplications", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.getInstalledApplications", description: "read installed applications" } },
            { className: "android.app.ApplicationPackageManager", methodName: "queryIntentActivities", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.queryIntentActivities", description: "query intent activities" } },
            { className: "android.app.ApplicationPackageManager", methodName: "queryIntentServices", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.queryIntentServices", description: "query intent services" } },
            { className: "android.app.ApplicationPackageManager", methodName: "queryIntentReceivers", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.queryIntentReceivers", description: "query intent receivers" } },

            // ===== 权限请求 / 权限检查 =====
            { className: "android.app.Activity", methodName: "requestPermissions", meta: { category: "permission", signalKey: "permissionRequest", api: "android.app.Activity.requestPermissions", description: "request Android runtime permissions" } },
            { className: "androidx.core.app.ActivityCompat", methodName: "requestPermissions", meta: { category: "permission", signalKey: "permissionRequest", api: "androidx.core.app.ActivityCompat.requestPermissions", description: "request AndroidX runtime permissions" } },
            { className: "android.content.ContextWrapper", methodName: "checkSelfPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "android.content.ContextWrapper.checkSelfPermission", description: "check runtime permission" } },
            { className: "android.content.pm.PackageManager", methodName: "checkPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "android.content.pm.PackageManager.checkPermission", description: "check package permission" } },
            { className: "androidx.core.content.ContextCompat", methodName: "checkSelfPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "androidx.core.content.ContextCompat.checkSelfPermission", description: "check AndroidX runtime permission" } },
            { className: "androidx.core.content.PermissionChecker", methodName: "checkSelfPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "androidx.core.content.PermissionChecker.checkSelfPermission", description: "check permission by PermissionChecker" } },

            // ===== WebView 导航 / Cookie =====
            // 系统 WebView
            { className: "android.webkit.WebView", methodName: "loadUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.loadUrl", description: "navigate WebView URL" } },
            { className: "android.webkit.WebView", methodName: "postUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.postUrl", description: "post WebView URL" } },
            { className: "android.webkit.WebView", methodName: "loadDataWithBaseURL", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.loadDataWithBaseURL", description: "load WebView data with base URL" } },
            { className: "android.webkit.WebView", methodName: "evaluateJavascript", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.evaluateJavascript", description: "evaluate WebView JavaScript" } },
            // 腾讯 X5 WebView（微信/QQ 等腾讯系应用常用）
            { className: "com.tencent.smtt.sdk.WebView", methodName: "loadUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.tencent.smtt.sdk.WebView.loadUrl", description: "navigate X5 WebView URL" } },
            { className: "com.tencent.smtt.sdk.WebView", methodName: "postUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.tencent.smtt.sdk.WebView.postUrl", description: "post X5 WebView URL" } },
            // UC WebView（UC 浏览器/部分资讯类应用常用）
            { className: "com.uc.webview.export.WebView", methodName: "loadUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.uc.webview.export.WebView.loadUrl", description: "navigate UC WebView URL" } },
            { className: "com.uc.webview.export.WebView", methodName: "postUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.uc.webview.export.WebView.postUrl", description: "post UC WebView URL" } },
            // Cookie 读写
            { className: "android.webkit.CookieManager", methodName: "getCookie", meta: { category: "webview", signalKey: "cookieAccess", api: "android.webkit.CookieManager.getCookie", description: "read WebView cookie" } },
            { className: "android.webkit.CookieManager", methodName: "setCookie", meta: { category: "webview", signalKey: "cookieAccess", api: "android.webkit.CookieManager.setCookie", description: "write WebView cookie" } },

            // ===== 网络连接 =====
            { className: "java.net.URL", methodName: "openConnection", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.URL.openConnection", description: "open URL connection" } },
            { className: "java.net.URLConnection", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.URLConnection.connect", description: "connect URL connection" } },
            { className: "java.net.HttpURLConnection", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.HttpURLConnection.connect", description: "connect HTTP URL connection" } },
            { className: "javax.net.ssl.HttpsURLConnection", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "javax.net.ssl.HttpsURLConnection.connect", description: "connect HTTPS URL connection" } },
            { className: "java.net.Socket", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.Socket.connect", description: "open socket connection" } },
            // OkHttp 网络库
            { className: "okhttp3.OkHttpClient", methodName: "newCall", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.OkHttpClient.newCall", description: "start OkHttp call" } },
            { className: "okhttp3.RealCall", methodName: "execute", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.RealCall.execute", description: "execute OkHttp call" } },
            { className: "okhttp3.RealCall", methodName: "enqueue", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.RealCall.enqueue", description: "enqueue OkHttp call" } },

            // ===== 文件存储 =====
            { className: "android.content.ContextWrapper", methodName: "openFileInput", meta: { category: "storage", signalKey: "accessStorage", api: "android.content.ContextWrapper.openFileInput", description: "read internal file" } },
            { className: "android.content.ContextWrapper", methodName: "openFileOutput", meta: { category: "storage", signalKey: "accessStorage", api: "android.content.ContextWrapper.openFileOutput", description: "write internal file" } },
            { className: "android.os.Environment", methodName: "getExternalStorageDirectory", meta: { category: "storage", signalKey: "accessStorage", api: "android.os.Environment.getExternalStorageDirectory", description: "read external storage path" } },

            // ===== 短信发送 =====
            { className: "android.telephony.SmsManager", methodName: "sendTextMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendTextMessage", description: "send SMS" } },
            { className: "android.telephony.SmsManager", methodName: "sendMultipartTextMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendMultipartTextMessage", description: "send multipart SMS" } },
            { className: "android.telephony.SmsManager", methodName: "sendDataMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendDataMessage", description: "send data SMS" } }
        ]);

        // ======================================================================
        // 厂商 OAID/AAID/VAID/UDID 标识符 Hook
        // ======================================================================
        // 拦截各厂商的匿名设备标识符获取接口（移动安全联盟 MSDK 标准），
        // 涵盖小米、三星、OPPO、联想等主流厂商的实现类及重打包变体
        ["com.android.id.impl.IdProviderImpl", "com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy", "repeackage.com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy", "com.heytap.openid.IOpenID$Stub$Proxy", "com.zui.deviceidservice.IDeviceidInterface$Stub$Proxy"].forEach(function (className) {
            ["getOAID", "getAAID", "getVAID", "getUDID"].forEach(function (methodName) {
                hookMethod(className, methodName, { category: "device_identifier", signalKey: "getOaid", api: className + "." + methodName, description: "read OAID or vendor identifier" });
            });
        });

        // ======================================================================
        // getSystemService Hook —— 系统服务获取拦截
        // ======================================================================
        // 拦截 ContextWrapper.getSystemService，识别 APP 正在获取哪种系统服务。
        // 通过 classifyService 将服务名映射为隐私类别，并在 enrich 中补充实际的
        // 服务类名（便于分析服务实例类型）
        hookMethod("android.content.ContextWrapper", "getSystemService", { category: "system_service", signalKey: "getSystemService", api: "android.content.ContextWrapper.getSystemService", description: "request system service" }, {
            // filter：只上报已知的隐私敏感服务
            filter: function (args) { return classifyService(args && args.length > 0 ? args[0] : null) !== null; },
            enrich: function (args, ret) {
                var meta = classifyService(args && args.length > 0 ? args[0] : null) || {};
                var serviceClass = "";
                try { serviceClass = ret && ret.getClass ? s(ret.getClass().getName()) : s(ret); } catch (e) {}
                return { service_name: s(args[0]), service_class: serviceClass, category: meta.category || "system_service", signal_key: meta.signalKey || "getSystemService", description: meta.description || "request system service" };
            }
        });

        // ======================================================================
        // ContentResolver Hook —— 内容提供者访问拦截
        // ======================================================================
        // 拦截 ContentResolver 的 query/insert/update/delete 四个核心方法，
        // 通过 classifyUri 识别访问的数据类型（通讯录/短信/通话记录/日历/存储）。
        // 这是捕获 APP 通过 ContentProvider 间接访问隐私数据的关键 Hook 点。
        ["query", "insert", "update", "delete"].forEach(function (methodName) {
            hookMethod("android.content.ContentResolver", methodName, { category: "content_provider", signalKey: "accessStorage", api: "android.content.ContentResolver." + methodName, description: "access content provider" }, {
                // filter：只上报访问已知敏感 ContentProvider URI 的调用
                filter: function (args) { return args && args.length > 0 && classifyUri(args[0]) !== null; },
                enrich: function (args) {
                    var meta = classifyUri(args[0]) || {};
                    return { uri: s(args[0]), category: meta.category || "content_provider", signal_key: meta.signalKey || "accessStorage", description: meta.description || "access content provider" };
                }
            });
        });

        // ======================================================================
        // 反射调用 Hook —— java.lang.reflect.Method.invoke
        // ======================================================================
        // 拦截 Java 反射调用，识别通过反射绕过的敏感 API 访问。
        // 部分 APP 会通过反射方式调用 getDeviceId / getImei 等敏感方法，
        // 规避常规的 API Hook 检测。此处通过签名关键字匹配来识别此类行为。
        try {
            var Method = Java.use("java.lang.reflect.Method");
            var invokeMethod = Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;");
            invokeMethod.implementation = function (receiver, args) {
                var declaringClass = "unknown";
                var methodName = "invoke";
                try {
                    declaringClass = s(this.getDeclaringClass().getName());
                    methodName = s(this.getName());
                } catch (e) {}
                var signature = declaringClass + "." + methodName;
                var ret = invokeMethod.call(this, receiver, args);
                // 通过签名关键字匹配识别隐私敏感调用
                if (has(signature, ["getdeviceid", "getimei", "getmeid", "getsubscriberid", "android_id", "oaid", "aaid", "vaid", "udid", "location", "camera", "audiorecord", "mediarecorder", "speechrecognizer", "getprimaryclip", "getinstalledpackages", "getinstalledapplications", "queryintentactivities", "queryintentservices", "contentresolver", "calllog", "sms", "calendar", "account", "openfile", "externalstorage", "sendtextmessage", "getaccounts", "getmacaddress", "getserial"])) {
                    sendApi({ category: "reflection", signalKey: "reflectionInvoke", api: "java.lang.reflect.Method.invoke", description: "reflective call " + signature }, [signature], ret, { reflected_method: signature, reflected_declaring_class: declaringClass });
                }
                return ret;
            };
            sendStatus("reflection hook installed");
        } catch (e) {
            sendError("reflection hook failed: " + e);
        }

                sendStatus("sensitive api hooks ready");
            } catch (e) {
                send({ type: "error", message: "hook bootstrap failed: " + e });
            }
        });
    } catch (e) {
        send({ type: "error", message: "Java.perform failed: " + e });
    }
}

// ============================================================================
// Agent 启动入口 —— 通过 setImmediate 立即调度 bootstrapHooks
// ============================================================================
// setImmediate 确保在 Frida 脚本加载完成后尽快执行，且不会阻塞脚本解析阶段。
// 传入 0 表示首次启动（retryCount = 0）。
setImmediate(function () {
    bootstrapHooks(0);
});