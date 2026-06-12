/**
 * Frida 动态 Hook 脚本 —— 敏感 API 拦截与隐私行为监控
 *
 * ======================== 功能概述 ========================
 * 本脚本基于 Frida 框架，注入目标 Android 应用进程后，实现对以下隐私行为的实时监控：
 * 1. 设备标识符读取（IMEI、IMSI、Android ID、MAC 地址、OAID 等）
 * 2. 位置信息获取（GPS、基站、Fused Location）
 * 3. 摄像头与麦克风调用
 * 4. 剪贴板读写
 * 5. 联系人/账户/短信/通话记录等敏感数据访问
 * 6. 应用安装列表查询
 * 7. 网络请求与文件读写
 * 8. AppOps 权限检查/使用记录（noteOp、checkOp 等）
 * 9. 反射调用（java.lang.reflect.Method.invoke）的拦截
 *
 * ======================== 架构设计 ========================
 * - bootstrapHooks()：带重试机制的引导函数，等待 Java Bridge 就绪
 * - Java.perform() 内部注册所有 Hook 逻辑
 * - hookMethod()：通用 Hook 注册函数，支持过滤器和数据增强
 * - classifyService() / classifyUri() / getAppOpsMeta()：分类器，将原始参数映射到隐私类别
 * - sendApi()：统一将拦截数据通过 send() 发送给 Frida 客户端（Python 端）
 *
 * ======================== 输出数据格式 ========================
 * 每个拦截事件通过 send() 以 JSON 格式发出，包含：
 * { type, timestamp, category, signal_key, api, description, args, return_value, stack }
 *
 * @requires Java Bridge（Frida 的 Java 运行时桥接）
 * @requires Frida >= 14.0
 */

"use strict";

/**
 * 带重试机制的引导函数 —— 等待 Java 运行时环境就绪
 *
 * 由于 Frida 注入后 Java Bridge 的初始化是异步的，本函数会以每秒一次的频率
 * 轮询检查 Java 对象和 Java.available 状态，最多重试 60 次（即 60 秒）。
 * 若 60 秒后仍未就绪，则发送错误消息并放弃。
 *
 * @param {number} retryCount - 当前重试次数，首次调用时传入 0
 */
function bootstrapHooks(retryCount) {
    // 检查 Java 全局对象是否存在（Frida 的 Java Bridge 入口）
    if (typeof Java === "undefined") {
        // 超过最大重试次数，放弃并上报错误
        if ((retryCount || 0) >= 60) {
            send({ type: "error", message: "Java bridge is not available." });
            return;
        }
        // 每 10 次重试上报一次等待状态，避免日志刷屏
        if ((retryCount || 0) % 10 === 0) {
            send({
                type: "status",
                message: "waiting for Java bridge",
                retry: retryCount || 0
            });
        }
        // 1 秒后递归重试
        setTimeout(function () { bootstrapHooks((retryCount || 0) + 1); }, 1000);
        return;
    }

    // 检查 Java 运行时是否可用（Android 环境为 true）
    if (!Java.available) {
        if ((retryCount || 0) >= 60) {
            send({ type: "error", message: "Java runtime is not available." });
            return;
        }
        if ((retryCount || 0) % 10 === 0) {
            send({
                type: "status",
                message: "waiting for Java runtime",
                retry: retryCount || 0
            });
        }
        setTimeout(function () { bootstrapHooks((retryCount || 0) + 1); }, 1000);
        return;
    }

    // Java 环境就绪，在 Java.perform() 上下文中注册所有 Hook
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        var Exception = Java.use("java.lang.Exception");

        /**
         * 安全地将任意值转换为字符串（用于日志输出）
         *
         * 处理 null/undefined 情况，限制输出长度为 280 字符以防止日志膨胀，
         * 对无法序列化的异常对象返回 "[unprintable]"。
         *
         * @param {*} v - 任意类型的值
         * @returns {string} 安全的字符串表示
         */
        function s(v) {
            try {
                if (v === null || v === undefined) return "";
                var t = String(v);
                // 限制最大长度，超长则截断并加省略号
                return t.length > 280 ? t.slice(0, 280) + "..." : t;
            } catch (e) {
                return "[unprintable]";
            }
        }

        /**
         * 获取当前调用栈的字符串表示
         *
         * 通过构造一个 java.lang.Exception 并调用 Log.getStackTraceString()
         * 来捕获 Java 层的完整调用栈，用于追踪敏感 API 的调用来源。
         *
         * @returns {string} 格式化的调用栈字符串
         */
        function stack() {
            try {
                return s(Log.getStackTraceString(Exception.$new()));
            } catch (e) {
                return "";
            }
        }

        /**
         * 向 Frida 客户端发送状态信息
         *
         * @param {string} message - 状态消息文本
         */
        function sendStatus(message) {
            send({ type: "status", timestamp: Date.now() / 1000, message: message });
        }

        /**
         * 向 Frida 客户端发送错误信息
         *
         * @param {string} message - 错误消息文本
         */
        function sendError(message) {
            send({ type: "error", timestamp: Date.now() / 1000, message: String(message) });
        }

        /**
         * 核心上报函数 —— 构建并发送敏感 API 调用事件
         *
         * 将拦截到的 API 调用的元信息（meta）、参数（args）、返回值（ret）以及
         * 调用栈打包为 JSON，通过 send() 发送给 Frida 客户端（Python 端）进行
         * 后续的隐私风险评估分析。
         *
         * @param {Object} meta - API 元信息，包含 category, signalKey, api, description 等
         * @param {Array} args - 被拦截方法的参数数组
         * @param {*} ret - 被拦截方法的返回值
         * @param {Object} [extra] - 可选的附加数据（如分类器产出的额外字段）
         */
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
            // 合并分类器等产出的额外字段（如 service_name、uri、app_op 等）
            if (extra) {
                Object.keys(extra).forEach(function (key) { payload[key] = extra[key]; });
            }
            send(payload);
        }

        /**
         * 检查文本中是否包含指定的关键词（不区分大小写）
         *
         * @param {string} text - 待检查的文本
         * @param {string[]} patterns - 关键词数组（小写）
         * @returns {boolean} 是否匹配到任意关键词
         */
        function has(text, patterns) {
            var normalized = s(text).toLowerCase();
            return patterns.some(function (item) { return normalized.indexOf(item) !== -1; });
        }

        /**
         * 通用 Hook 注册函数 —— 对指定类的指定方法的所有重载进行拦截
         *
         * 这是本脚本最核心的函数。对于目标类的目标方法，遍历其所有重载（overload），
         * 在每个重载上安装拦截器：
         * 1. 先调用原始方法获取返回值
         * 2. 通过 filter 回调判断是否需要上报
         * 3. 通过 enrich 回调收集附加数据
         * 4. 调用 sendApi() 将事件发送给分析端
         *
         * @param {string} className - 目标类的完整限定名，如 "android.telephony.TelephonyManager"
         * @param {string} methodName - 目标方法名，如 "getDeviceId"
         * @param {Object} meta - API 元信息（category, signalKey, api, description）
         * @param {Object} [options] - 可选配置
         * @param {Function} [options.filter] - 过滤函数 (args, ret) => boolean，返回 true 才上报
         * @param {Function} [options.enrich] - 数据增强函数 (args, ret) => Object，返回额外字段
         * @returns {boolean} 是否成功注册 Hook
         */
        function hookMethod(className, methodName, meta, options) {
            try {
                var Target = Java.use(className);
                if (!Target[methodName]) return false;
                // 遍历目标方法的所有重载变体（如不同参数签名）
                Target[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var ret;
                        // 先执行原始调用以保证应用正常功能
                        try {
                            ret = overload.call.apply(overload, [this].concat(args));
                        } catch (callError) {
                            // 原方法抛异常时也上报，标记 error: true
                            sendApi(meta, args, "[throw] " + callError, { error: true });
                            throw callError;
                        }
                        // 根据过滤条件和增强逻辑决定是否上报
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

        /**
         * Root 检测绕过 —— 隐藏 Frida 和 Root 相关痕迹
         *
         * 通过 Hook java.io.File.exists 和 java.lang.Runtime.exec 方法，
         * 拦截对 su 二进制、Magisk、Frida 相关文件和命令的检测，
         * 防止目标应用因检测到 Root/Frida 环境而拒绝运行或执行对抗代码。
         *
         * 工作原理：
         * - File.exists()：对包含 su/magisk/frida 等关键词的路径返回 false
         * - Runtime.exec()：对包含 su/which/magisk 的命令替换为无效命令
         */
        function installRootBypass() {
            try {
                var File = Java.use("java.io.File");
                var Runtime = Java.use("java.lang.Runtime");
                // 需要隐藏的敏感文件和关键词
                var suspicious = ["/system/bin/su", "/system/xbin/su", "/data/local/tmp/frida-server", "magisk", "frida"];
                var exists = File.exists.overload();
                exists.implementation = function () {
                    // 对可疑路径返回 false，假装文件不存在
                    return has(this.getAbsolutePath(), suspicious) ? false : exists.call(this);
                };
                var execString = Runtime.exec.overload("java.lang.String");
                execString.implementation = function (command) {
                    // 对可疑命令替换为无效命令
                    return has(command, ["su", "which", "magisk"]) ? execString.call(this, "invalid_command") : execString.call(this, command);
                };
                sendStatus("root bypass installed");
            } catch (e) {
                sendError("root bypass failed: " + e);
            }
        }

        /**
         * 批量注册简单的 API Hook（不带过滤器和数据增强）
         *
         * @param {Object[]} items - Hook 配置数组
         * @param {string} items[].className - 目标类名
         * @param {string} items[].methodName - 目标方法名
         * @param {Object} items[].meta - API 元信息
         * @param {Object} [items[].options] - 可选的过滤/增强配置
         */
        function hookSimple(items) {
            items.forEach(function (item) {
                hookMethod(item.className, item.methodName, item.meta, item.options);
            });
        }

        /**
         * 系统服务分类器 —— 根据 getSystemService 的 name 参数判断隐私类别
         *
         * Android 的 Context.getSystemService(name) 通过字符串参数指定获取哪类服务。
         * 本函数根据服务名推断该调用涉及的隐私类别，用于后续的上报分类。
         *
         * @param {string} name - 系统服务名称，如 "location"、"phone" 等
         * @returns {Object|null} 分类结果 { category, signalKey, description }，无法分类时返回 null
         */
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

        /**
         * ContentProvider URI 分类器 —— 根据 URI 判断访问的数据类型
         *
         * Android 的 ContentResolver 通过 content:// URI 访问不同数据源（联系人、
         * 短信、通话记录、日历、媒体文件等）。本函数根据 URI 中的关键词判断
         * 目标数据类别。
         *
         * @param {string} uriText - content:// URI 字符串
         * @returns {Object|null} 分类结果 { category, signalKey, description }，无法分类时返回 null
         */
        function classifyUri(uriText) {
            var uri = s(uriText).toLowerCase();
            if (has(uri, ["contacts", "com.android.contacts"])) return { category: "contacts", signalKey: "readContacts", description: "access contacts provider" };
            if (has(uri, ["sms", "mms", "mms-sms"])) return { category: "sms", signalKey: "readSms", description: "access sms provider" };
            if (has(uri, ["call_log", "calllog"])) return { category: "call_log", signalKey: "readCallLog", description: "access call log provider" };
            if (has(uri, ["calendar", "com.android.calendar"])) return { category: "calendar", signalKey: "accessCalendar", description: "access calendar provider" };
            if (has(uri, ["media", "external", "downloads"])) return { category: "storage", signalKey: "accessStorage", description: "access storage provider" };
            return null;
        }

        /**
         * AppOps 操作分类器 —— 将 AppOps 操作码或操作名字符串映射为隐私类别
         *
         * Android 的 AppOpsManager 通过操作码（如 0=粗略位置、26=相机）
         * 或操作名字符串（如 "android:camera"）来标识具体的隐私操作。
         *
         * 分类策略分三层：
         * 1. 数字操作码精确匹配（codeMap）
         * 2. 字符串操作名精确匹配（stringMap）
         * 3. 关键词模糊匹配（兜底）
         *
         * @param {number|string} opValue - AppOps 操作码或操作名
         * @returns {Object|null} 包含 opName、category、signalKey、description 的对象
         */
        function getAppOpsMeta(opValue) {
            var text = s(opValue).toLowerCase();
            var code = null;
            // 尝试将操作值解析为数字
            if (typeof opValue === "number") {
                code = opValue;
            } else if (/^-?\d+$/.test(text)) {
                code = parseInt(text, 10);
            }

            // 第一层：数字操作码精确映射表
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

            // 第二层：字符串操作名精确映射表
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

            // 第三层：关键词模糊匹配（兜底策略）
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

        /**
         * AppOps 附加数据构建器 —— 从 AppOpsManager 方法参数中提取分类信息
         *
         * 解析 AppOpsManager 方法（如 noteOp、checkOp）的参数，提取：
         * - 应用自身的操作码/操作名
         * - 目标应用包名（通常为第二个参数或后续包含 "." 的参数）
         *
         * @param {Array} args - AppOpsManager 方法的参数数组
         * @returns {Object} 包含 app_op、package_name、category 等字段的数据对象
         */
        function buildAppOpsExtra(args) {
            var meta = getAppOpsMeta(args && args.length > 0 ? args[0] : null) || {};
            var packageName = "";
            // 从第二个参数开始查找包名（包含 "." 且不以 "android:" 开头）
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

        // ======================== 1. 安装 Root 检测绕过 ========================
        installRootBypass();

        // ======================== 2. Hook AppOpsManager ========================
        // AppOpsManager 是 Android 权限管控的核心服务，记录和检查每次权限使用
        // 对 noteOp/checkOp/startOp 等 8 个关键方法进行拦截
        ["noteOp", "noteOpNoThrow", "noteProxyOp", "noteProxyOpNoThrow", "checkOp", "checkOpNoThrow", "startOp", "startOpNoThrow"].forEach(function (methodName) {
            hookMethod("android.app.AppOpsManager", methodName, {
                category: "app_ops",
                signalKey: "appOpsSensitiveAction",
                api: "android.app.AppOpsManager." + methodName,
                description: "observe AppOps sensitive action"
            }, {
                // 仅当第一个参数（操作码）能被识别为敏感操作时才上报
                filter: function (args) {
                    return args && args.length > 0 && getAppOpsMeta(args[0]) !== null;
                },
                // 提取操作码和包名作为附加数据
                enrich: function (args) {
                    return buildAppOpsExtra(args);
                }
            });
        });

        // ======================== 3. 批量注册隐私敏感 API Hook ========================
        // 涵盖六大类隐私敏感 API：
        // (1) 设备标识符：IMEI/IMSI/Android ID/MAC/OAID/Serial 等
        // (2) 位置信息：GPS/FusedLocation 的 getLastLocation/requestLocationUpdates 等
        // (3) 相机：Camera/Camera2/CameraX 的 open/takePicture
        // (4) 麦克风：MediaRecorder/AudioRecord/SpeechRecognizer
        // (5) 剪贴板/账户/包管理/网络/存储/短信
        // (6) 其他敏感 API
        hookSimple([
            { className: "android.telephony.TelephonyManager", methodName: "getDeviceId", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.telephony.TelephonyManager.getDeviceId", description: "read device IMEI or MEID" } },
            { className: "android.telephony.TelephonyManager", methodName: "getImei", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.telephony.TelephonyManager.getImei", description: "read IMEI" } },
            { className: "android.telephony.TelephonyManager", methodName: "getMeid", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.telephony.TelephonyManager.getMeid", description: "read MEID" } },
            { className: "android.telephony.TelephonyManager", methodName: "getSubscriberId", meta: { category: "device_identifier", signalKey: "getSubscriberId", api: "android.telephony.TelephonyManager.getSubscriberId", description: "read IMSI" } },
            { className: "android.telephony.TelephonyManager", methodName: "getSimSerialNumber", meta: { category: "device_identifier", signalKey: "getSubscriberId", api: "android.telephony.TelephonyManager.getSimSerialNumber", description: "read SIM serial" } },
            { className: "android.telephony.TelephonyManager", methodName: "getLine1Number", meta: { category: "device_identifier", signalKey: "getSubscriberId", api: "android.telephony.TelephonyManager.getLine1Number", description: "read phone number" } },
            { className: "android.provider.Settings$Secure", methodName: "getString", meta: { category: "device_identifier", signalKey: "getAndroidId", api: "android.provider.Settings$Secure.getString", description: "read Android ID" }, options: { filter: function (args) { return args.length > 1 && s(args[1]).toLowerCase() === "android_id"; } } },
            { className: "android.provider.Settings$System", methodName: "getString", meta: { category: "device_identifier", signalKey: "getAndroidId", api: "android.provider.Settings$System.getString", description: "read Android ID" }, options: { filter: function (args) { return args.length > 1 && s(args[1]).toLowerCase() === "android_id"; } } },
            { className: "android.os.Build", methodName: "getSerial", meta: { category: "device_identifier", signalKey: "getDeviceId", api: "android.os.Build.getSerial", description: "read device serial" } },
            { className: "android.net.wifi.WifiInfo", methodName: "getMacAddress", meta: { category: "device_identifier", signalKey: "getMacAddress", api: "android.net.wifi.WifiInfo.getMacAddress", description: "read MAC" } },
            { className: "android.bluetooth.BluetoothAdapter", methodName: "getAddress", meta: { category: "device_identifier", signalKey: "getMacAddress", api: "android.bluetooth.BluetoothAdapter.getAddress", description: "read Bluetooth MAC" } },
            { className: "android.location.LocationManager", methodName: "getLastKnownLocation", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.getLastKnownLocation", description: "read last location" } },
            { className: "android.location.LocationManager", methodName: "requestLocationUpdates", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.requestLocationUpdates", description: "request location updates" } },
            { className: "android.location.LocationManager", methodName: "requestSingleUpdate", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.requestSingleUpdate", description: "request single update" } },
            { className: "android.location.LocationManager", methodName: "getCurrentLocation", meta: { category: "location", signalKey: "getLocation", api: "android.location.LocationManager.getCurrentLocation", description: "request current location" } },
            { className: "com.google.android.gms.location.FusedLocationProviderClient", methodName: "getLastLocation", meta: { category: "location", signalKey: "getLocation", api: "com.google.android.gms.location.FusedLocationProviderClient.getLastLocation", description: "read fused location" } },
            { className: "com.google.android.gms.location.FusedLocationProviderClient", methodName: "requestLocationUpdates", meta: { category: "location", signalKey: "getLocation", api: "com.google.android.gms.location.FusedLocationProviderClient.requestLocationUpdates", description: "request fused updates" } },
            { className: "com.google.android.gms.location.FusedLocationProviderClient", methodName: "getCurrentLocation", meta: { category: "location", signalKey: "getLocation", api: "com.google.android.gms.location.FusedLocationProviderClient.getCurrentLocation", description: "request fused current location" } },
            { className: "android.hardware.Camera", methodName: "open", meta: { category: "camera", signalKey: "openCamera", api: "android.hardware.Camera.open", description: "open legacy camera" } },
            { className: "android.hardware.camera2.CameraManager", methodName: "openCamera", meta: { category: "camera", signalKey: "openCamera", api: "android.hardware.camera2.CameraManager.openCamera", description: "open Camera2 camera" } },
            { className: "androidx.camera.core.ImageCapture", methodName: "takePicture", meta: { category: "camera", signalKey: "openCamera", api: "androidx.camera.core.ImageCapture.takePicture", description: "capture photo by CameraX" } },
            { className: "android.media.MediaRecorder", methodName: "start", meta: { category: "microphone", signalKey: "startRecording", api: "android.media.MediaRecorder.start", description: "start recorder" } },
            { className: "android.media.MediaRecorder", methodName: "setAudioSource", meta: { category: "microphone", signalKey: "startRecording", api: "android.media.MediaRecorder.setAudioSource", description: "set audio source" } },
            { className: "android.media.AudioRecord", methodName: "startRecording", meta: { category: "microphone", signalKey: "startRecording", api: "android.media.AudioRecord.startRecording", description: "start audio record" } },
            { className: "android.speech.SpeechRecognizer", methodName: "startListening", meta: { category: "microphone", signalKey: "startRecording", api: "android.speech.SpeechRecognizer.startListening", description: "start speech recognizer" } },
            { className: "android.content.ClipboardManager", methodName: "getPrimaryClip", meta: { category: "clipboard", signalKey: "readClipboard", api: "android.content.ClipboardManager.getPrimaryClip", description: "read clipboard" } },
            { className: "android.content.ClipboardManager", methodName: "setPrimaryClip", meta: { category: "clipboard", signalKey: "readClipboard", api: "android.content.ClipboardManager.setPrimaryClip", description: "write clipboard" } },
            { className: "android.accounts.AccountManager", methodName: "getAccounts", meta: { category: "account", signalKey: "getAccount", api: "android.accounts.AccountManager.getAccounts", description: "read account list" } },
            { className: "android.accounts.AccountManager", methodName: "getAccountsByType", meta: { category: "account", signalKey: "getAccount", api: "android.accounts.AccountManager.getAccountsByType", description: "read accounts by type" } },
            { className: "android.accounts.AccountManager", methodName: "getAccountsByTypeAndFeatures", meta: { category: "account", signalKey: "getAccount", api: "android.accounts.AccountManager.getAccountsByTypeAndFeatures", description: "read accounts by features" } },
            { className: "android.app.ApplicationPackageManager", methodName: "getInstalledPackages", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.getInstalledPackages", description: "read installed packages" } },
            { className: "android.app.ApplicationPackageManager", methodName: "getInstalledApplications", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.getInstalledApplications", description: "read installed applications" } },
            { className: "android.app.ApplicationPackageManager", methodName: "queryIntentActivities", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.queryIntentActivities", description: "query intent activities" } },
            { className: "android.app.ApplicationPackageManager", methodName: "queryIntentServices", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.queryIntentServices", description: "query intent services" } },
            { className: "android.app.ApplicationPackageManager", methodName: "queryIntentReceivers", meta: { category: "package_manager", signalKey: "getInstalledPackages", api: "android.app.ApplicationPackageManager.queryIntentReceivers", description: "query intent receivers" } },
            { className: "java.net.URL", methodName: "openConnection", meta: { category: "network", signalKey: "accessStorage", api: "java.net.URL.openConnection", description: "open URL connection" } },
            { className: "java.net.Socket", methodName: "connect", meta: { category: "network", signalKey: "accessStorage", api: "java.net.Socket.connect", description: "open socket connection" } },
            { className: "okhttp3.OkHttpClient", methodName: "newCall", meta: { category: "network", signalKey: "accessStorage", api: "okhttp3.OkHttpClient.newCall", description: "start OkHttp call" } },
            { className: "android.content.ContextWrapper", methodName: "openFileInput", meta: { category: "storage", signalKey: "accessStorage", api: "android.content.ContextWrapper.openFileInput", description: "read internal file" } },
            { className: "android.content.ContextWrapper", methodName: "openFileOutput", meta: { category: "storage", signalKey: "accessStorage", api: "android.content.ContextWrapper.openFileOutput", description: "write internal file" } },
            { className: "android.os.Environment", methodName: "getExternalStorageDirectory", meta: { category: "storage", signalKey: "accessStorage", api: "android.os.Environment.getExternalStorageDirectory", description: "read external storage path" } },
            { className: "android.telephony.SmsManager", methodName: "sendTextMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendTextMessage", description: "send SMS" } },
            { className: "android.telephony.SmsManager", methodName: "sendMultipartTextMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendMultipartTextMessage", description: "send multipart SMS" } },
            { className: "android.telephony.SmsManager", methodName: "sendDataMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendDataMessage", description: "send data SMS" } }
        ]);

        // ======================== 4. Hook 设备厂商标识符（OAID/VAID/AAID/UDID） ========================
        // 不同手机厂商有各自的设备标识服务实现类，需要分别覆盖
        // - com.android.id.impl.IdProviderImpl（Android 官方）
        // - com.samsung.android.deviceidservice（三星）
        // - com.heytap.openid（OPPO/一加）
        // - com.zui.deviceidservice（联想 ZUI）
        ["com.android.id.impl.IdProviderImpl", "com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy", "repeackage.com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy", "com.heytap.openid.IOpenID$Stub$Proxy", "com.zui.deviceidservice.IDeviceidInterface$Stub$Proxy"].forEach(function (className) {
            ["getOAID", "getAAID", "getVAID", "getUDID"].forEach(function (methodName) {
                hookMethod(className, methodName, { category: "device_identifier", signalKey: "getOaid", api: className + "." + methodName, description: "read OAID or vendor identifier" });
            });
        });

        // ======================== 5. Hook getSystemService —— 拦截系统服务获取请求 ========================
        // Context.getSystemService(name) 是应用获取各类系统服务（位置、相机、电话等）的统一入口
        // 通过 classifyService() 分类器过滤和标注，仅上报与隐私相关的服务请求
        hookMethod("android.content.ContextWrapper", "getSystemService", { category: "system_service", signalKey: "getSystemService", api: "android.content.ContextWrapper.getSystemService", description: "request system service" }, {
            filter: function (args) { return classifyService(args && args.length > 0 ? args[0] : null) !== null; },
            enrich: function (args, ret) {
                var meta = classifyService(args && args.length > 0 ? args[0] : null) || {};
                var serviceClass = "";
                // 尝试获取返回的服务对象的实际类名
                try { serviceClass = ret && ret.getClass ? s(ret.getClass().getName()) : s(ret); } catch (e) {}
                return { service_name: s(args[0]), service_class: serviceClass, category: meta.category || "system_service", signal_key: meta.signalKey || "getSystemService", description: meta.description || "request system service" };
            }
        });

        // ======================== 6. Hook ContentResolver —— 拦截内容提供者访问 ========================
        // ContentResolver 的 query/insert/update/delete 方法用于访问联系人、短信、日历等敏感数据
        // 通过 classifyUri() 分类器过滤，仅上报涉及敏感数据源的访问
        ["query", "insert", "update", "delete"].forEach(function (methodName) {
            hookMethod("android.content.ContentResolver", methodName, { category: "content_provider", signalKey: "accessStorage", api: "android.content.ContentResolver." + methodName, description: "access content provider" }, {
                filter: function (args) { return args && args.length > 0 && classifyUri(args[0]) !== null; },
                enrich: function (args) {
                    var meta = classifyUri(args[0]) || {};
                    return { uri: s(args[0]), category: meta.category || "content_provider", signal_key: meta.signalKey || "accessStorage", description: meta.description || "access content provider" };
                }
            });
        });

        // ======================== 7. Hook 反射调用（java.lang.reflect.Method.invoke） ========================
        // 部分应用通过反射绕过直接 API 调用检测，因此需要拦截 Method.invoke
        // 仅上报签名中包含已知敏感方法名的调用（如 getDeviceId、getAccounts 等）
        try {
            var Method = Java.use("java.lang.reflect.Method");
            var invokeMethod = Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;");
            invokeMethod.implementation = function (receiver, args) {
                var declaringClass = "unknown";
                var methodName = "invoke";
                // 提取被反射调用的真实类名和方法名
                try {
                    declaringClass = s(this.getDeclaringClass().getName());
                    methodName = s(this.getName());
                } catch (e) {}
                var signature = declaringClass + "." + methodName;
                var ret = invokeMethod.call(this, receiver, args);
                // 仅当签名的类名+方法名包含已知敏感关键词时才上报
                if (has(signature, ["getdeviceid", "getimei", "getmeid", "getsubscriberid", "android_id", "oaid", "aaid", "vaid", "udid", "location", "camera", "audiorecord", "mediarecorder", "speechrecognizer", "getprimaryclip", "getinstalledpackages", "getinstalledapplications", "queryintentactivities", "queryintentservices", "contentresolver", "calllog", "sms", "calendar", "account", "openfile", "externalstorage", "sendtextmessage", "getaccounts", "getmacaddress", "getserial"])) {
                    sendApi({ category: "reflection", signalKey: "reflectionInvoke", api: "java.lang.reflect.Method.invoke", description: "reflective call " + signature }, [signature], ret, { reflected_method: signature, reflected_declaring_class: declaringClass });
                }
                return ret;
            };
            sendStatus("reflection hook installed");
        } catch (e) {
            sendError("reflection hook failed: " + e);
        }

        // 上报所有 Hook 安装完成
        sendStatus("sensitive api hooks ready");
    });
}

// 使用 setImmediate 确保在 Frida 消息循环就绪后再启动引导流程
setImmediate(function () {
    bootstrapHooks(0);
});
