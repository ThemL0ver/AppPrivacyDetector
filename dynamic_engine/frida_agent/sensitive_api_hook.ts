import Java from "frida-java-bridge";

"use strict";

var earlyNativeGuardState = {
    tracerPid: false,
    rootPath: false,
    systemProperty: false,
    bootstrapped: false
};

function resolveExport(moduleName, symbolName) {
    try {
        if (typeof Module !== "undefined" && Module) {
            if (typeof Module.getExportByName === "function") {
                try {
                    return Module.getExportByName(moduleName, symbolName);
                } catch (e) {}
            }
            if (typeof Module.findExportByName === "function") {
                try {
                    return Module.findExportByName(moduleName, symbolName);
                } catch (e) {}
            }
        }
    } catch (e) {}

    try {
        if (typeof Process !== "undefined" && Process && typeof Process.getModuleByName === "function") {
            var moduleObject = Process.getModuleByName(moduleName);
            if (moduleObject) {
                if (typeof moduleObject.getExportByName === "function") {
                    try {
                        return moduleObject.getExportByName(symbolName);
                    } catch (e) {}
                }
                if (typeof moduleObject.findExportByName === "function") {
                    try {
                        return moduleObject.findExportByName(symbolName);
                    } catch (e) {}
                }
            }
        }
    } catch (e) {}

    return null;
}

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

function isSuspiciousNativePath(pathText) {
    var normalized = String(pathText || "").toLowerCase();
    if (!normalized) return false;
    var keywords = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "magisk",
        "zygisk",
        "xposed",
        "busybox",
        "frida",
        "/proc/self/status",
        "/proc/",
        "superuser"
    ];
    return keywords.some(function (keyword) { return normalized.indexOf(keyword) !== -1; });
}

function installNativeTracerPidGuard() {
    if (earlyNativeGuardState.tracerPid) {
        return;
    }
    try {
        var fgetsPtr = resolveExport("libc.so", "fgets");
        if (!fgetsPtr || typeof Interceptor === "undefined" || typeof Interceptor.attach !== "function") {
            send({ type: "status", message: "native anti-debug skipped" });
            return;
        }
        Interceptor.attach(fgetsPtr, {
            onEnter: function (args) {
                this.buffer = args[0];
            },
            onLeave: function (retval) {
                try {
                    if (!this.buffer || retval.isNull()) return;
                    var line = Memory.readUtf8String(this.buffer);
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

function installNativeRootPathGuard() {
    if (earlyNativeGuardState.rootPath) {
        return;
    }
    try {
        if (typeof Interceptor === "undefined" || typeof Interceptor.attach !== "function") {
            send({ type: "status", message: "native root path guard skipped" });
            return;
        }

        var installedCount = 0;
        [
            { symbol: "access", pathIndex: 0 },
            { symbol: "stat", pathIndex: 0 },
            { symbol: "lstat", pathIndex: 0 },
            { symbol: "open", pathIndex: 0 },
            { symbol: "openat", pathIndex: 1 },
            { symbol: "faccessat", pathIndex: 1 }
        ].forEach(function (hookSpec) {
            var nativePtr = resolveExport("libc.so", hookSpec.symbol);
            if (!nativePtr) {
                return;
            }
            Interceptor.attach(nativePtr, {
                onEnter: function (args) {
                    this.targetPath = readNativeUtf8(args[hookSpec.pathIndex]);
                    this.shouldMask = isSuspiciousNativePath(this.targetPath);
                },
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

function installNativeSystemPropertyGuard() {
    if (earlyNativeGuardState.systemProperty) {
        return;
    }
    try {
        var propertyPtr = resolveExport("libc.so", "__system_property_get");
        if (!propertyPtr || typeof Interceptor === "undefined" || typeof Interceptor.attach !== "function") {
            send({ type: "status", message: "native system property guard skipped" });
            return;
        }
        Interceptor.attach(propertyPtr, {
            onEnter: function (args) {
                this.key = readNativeUtf8(args[0]).toLowerCase();
                this.valueBuffer = args[1];
            },
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

function installEarlyNativeGuards() {
    if (earlyNativeGuardState.bootstrapped) {
        return;
    }
    earlyNativeGuardState.bootstrapped = true;
    installNativeTracerPidGuard();
    installNativeRootPathGuard();
    installNativeSystemPropertyGuard();
}

function bootstrapHooks(retryCount) {
    if ((retryCount || 0) === 0) {
        send({ type: "status", message: "frida bootstrap entered" });
        installEarlyNativeGuards();
    }

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

    send({ type: "status", message: "java runtime detected" });
    var performWithJava = typeof Java.performNow === "function" ? Java.performNow.bind(Java) : Java.perform.bind(Java);
    try {
        performWithJava(function () {
            send({ type: "status", message: "java bridge ready" });
            try {
            var Log = Java.use("android.util.Log");
            var Exception = Java.use("java.lang.Exception");
            var bootstrapStartedAt = Date.now();

            function s(v) {
                try {
                    if (v === null || v === undefined) return "";
                    var t = String(v);
                    return t.length > 280 ? t.slice(0, 280) + "..." : t;
                } catch (e) {
                    return "[unprintable]";
                }
            }

            function stack() {
                try {
                    return s(Log.getStackTraceString(Exception.$new()));
                } catch (e) {
                    return "";
                }
            }

            function sendStatus(message) {
                send({ type: "status", timestamp: Date.now() / 1000, message: message });
            }

            function sendError(message) {
                send({ type: "error", timestamp: Date.now() / 1000, message: String(message) });
            }

            function safeStackLower() {
                try {
                    return stack().toLowerCase();
                } catch (e) {
                    return "";
                }
            }

            function withinStartupGuardWindow() {
                return Date.now() - bootstrapStartedAt <= 20000;
            }

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

            function sanitizeExecArg(value) {
                if (value === null || value === undefined) return value;
                if (typeof value === "string") {
                    return isSecurityProbeText(value) ? "invalid_command" : value;
                }
                try {
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

            function shouldBlockTermination(reasonText) {
                var stackText = safeStackLower();
                if (!withinStartupGuardWindow()) return false;
                return isSecurityProbeText(reasonText) || isSecurityStack(stackText);
            }

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
                if (extra) {
                    Object.keys(extra).forEach(function (key) { payload[key] = extra[key]; });
                }
                send(payload);
            }

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

            function has(text, patterns) {
                var normalized = s(text).toLowerCase();
                return patterns.some(function (item) { return normalized.indexOf(item) !== -1; });
            }

        function hookMethod(className, methodName, meta, options) {
            try {
                var Target = Java.use(className);
                if (!Target[methodName]) return false;
                Target[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var ret;
                        try {
                            ret = overload.call.apply(overload, [this].concat(args));
                        } catch (callError) {
                            sendApi(meta, args, "[throw] " + callError, { error: true });
                            throw callError;
                        }
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

        function installNativeAntiDebug() {
            installNativeTracerPidGuard();
            installNativeRootPathGuard();
            installNativeSystemPropertyGuard();
        }

        function installRootBypass() {
            try {
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
                var suspicious = ["/system/bin/su", "/system/xbin/su", "/data/local/tmp/frida-server", "magisk", "frida"];
                var suspiciousPackages = [
                    "com.topjohnwu.magisk",
                    "eu.chainfire.supersu",
                    "com.thirdparty.superuser",
                    "com.koushikdutta.superuser",
                    "de.robv.android.xposed.installer",
                    "io.github.vvb2060.magisk"
                ];
                var exists = File.exists.overload();
                exists.implementation = function () {
                    var absolutePath = s(this.getAbsolutePath());
                    if (has(absolutePath, suspicious)) {
                        sendAntiAnalysisProbe("java.io.File.exists", "probe suspicious path: " + absolutePath, { path: absolutePath });
                        return false;
                    }
                    return exists.call(this);
                };
                Runtime.exec.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var joinedCommand = s(args);
                        if (isSecurityProbeText(joinedCommand)) {
                            sendAntiAnalysisProbe("java.lang.Runtime.exec", "runtime exec security probe", { command: joinedCommand });
                        }
                        for (var i = 0; i < args.length; i++) {
                            args[i] = sanitizeExecArg(args[i]);
                        }
                        return overload.call.apply(overload, [this].concat(args));
                    };
                });
                try {
                    var startProcessBuilder = ProcessBuilder.start.overload();
                    startProcessBuilder.implementation = function () {
                        try {
                            var commandList = this.command();
                            var joined = s(commandList);
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
                Debug.isDebuggerConnected.implementation = function () {
                    return false;
                };
                Debug.waitingForDebugger.implementation = function () {
                    return false;
                };
                try {
                    var getProperty = SystemProperties.get.overload("java.lang.String");
                    getProperty.implementation = function (key) {
                        var normalized = s(key).toLowerCase();
                        if (normalized === "ro.debuggable" || normalized === "ro.secure" || normalized === "ro.build.tags") {
                            sendAntiAnalysisProbe("android.os.SystemProperties.get", "system property probe: " + normalized, { property_key: normalized });
                        }
                        if (normalized === "ro.debuggable") return "0";
                        if (normalized === "ro.secure") return "1";
                        if (normalized === "ro.build.tags") return "release-keys";
                        return getProperty.call(this, key);
                    };
                } catch (e) {}
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

        function hookSimple(items) {
            items.forEach(function (item) {
                hookMethod(item.className, item.methodName, item.meta, item.options);
            });
        }

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

        function classifyUri(uriText) {
            var uri = s(uriText).toLowerCase();
            if (has(uri, ["contacts", "com.android.contacts"])) return { category: "contacts", signalKey: "readContacts", description: "access contacts provider" };
            if (has(uri, ["sms", "mms", "mms-sms"])) return { category: "sms", signalKey: "readSms", description: "access sms provider" };
            if (has(uri, ["call_log", "calllog"])) return { category: "call_log", signalKey: "readCallLog", description: "access call log provider" };
            if (has(uri, ["calendar", "com.android.calendar"])) return { category: "calendar", signalKey: "accessCalendar", description: "access calendar provider" };
            if (has(uri, ["media", "external", "downloads"])) return { category: "storage", signalKey: "accessStorage", description: "access storage provider" };
            return null;
        }

        function getAppOpsMeta(opValue) {
            var text = s(opValue).toLowerCase();
            var code = null;
            if (typeof opValue === "number") {
                code = opValue;
            } else if (/^-?\d+$/.test(text)) {
                code = parseInt(text, 10);
            }

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

        function buildAppOpsExtra(args) {
            var meta = getAppOpsMeta(args && args.length > 0 ? args[0] : null) || {};
            var packageName = "";
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

        installNativeAntiDebug();
        installRootBypass();

        ["noteOp", "noteOpNoThrow", "noteProxyOp", "noteProxyOpNoThrow", "checkOp", "checkOpNoThrow", "startOp", "startOpNoThrow"].forEach(function (methodName) {
            hookMethod("android.app.AppOpsManager", methodName, {
                category: "app_ops",
                signalKey: "appOpsSensitiveAction",
                api: "android.app.AppOpsManager." + methodName,
                description: "observe AppOps sensitive action"
            }, {
                filter: function (args) {
                    return args && args.length > 0 && getAppOpsMeta(args[0]) !== null;
                },
                enrich: function (args) {
                    return buildAppOpsExtra(args);
                }
            });
        });

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
            { className: "android.app.Activity", methodName: "requestPermissions", meta: { category: "permission", signalKey: "permissionRequest", api: "android.app.Activity.requestPermissions", description: "request Android runtime permissions" } },
            { className: "androidx.core.app.ActivityCompat", methodName: "requestPermissions", meta: { category: "permission", signalKey: "permissionRequest", api: "androidx.core.app.ActivityCompat.requestPermissions", description: "request AndroidX runtime permissions" } },
            { className: "android.content.ContextWrapper", methodName: "checkSelfPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "android.content.ContextWrapper.checkSelfPermission", description: "check runtime permission" } },
            { className: "android.content.pm.PackageManager", methodName: "checkPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "android.content.pm.PackageManager.checkPermission", description: "check package permission" } },
            { className: "androidx.core.content.ContextCompat", methodName: "checkSelfPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "androidx.core.content.ContextCompat.checkSelfPermission", description: "check AndroidX runtime permission" } },
            { className: "androidx.core.content.PermissionChecker", methodName: "checkSelfPermission", meta: { category: "permission", signalKey: "permissionCheck", api: "androidx.core.content.PermissionChecker.checkSelfPermission", description: "check permission by PermissionChecker" } },
            { className: "android.webkit.WebView", methodName: "loadUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.loadUrl", description: "navigate WebView URL" } },
            { className: "android.webkit.WebView", methodName: "postUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.postUrl", description: "post WebView URL" } },
            { className: "android.webkit.WebView", methodName: "loadDataWithBaseURL", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.loadDataWithBaseURL", description: "load WebView data with base URL" } },
            { className: "android.webkit.WebView", methodName: "evaluateJavascript", meta: { category: "webview", signalKey: "webViewNavigation", api: "android.webkit.WebView.evaluateJavascript", description: "evaluate WebView JavaScript" } },
            { className: "com.tencent.smtt.sdk.WebView", methodName: "loadUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.tencent.smtt.sdk.WebView.loadUrl", description: "navigate X5 WebView URL" } },
            { className: "com.tencent.smtt.sdk.WebView", methodName: "postUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.tencent.smtt.sdk.WebView.postUrl", description: "post X5 WebView URL" } },
            { className: "com.uc.webview.export.WebView", methodName: "loadUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.uc.webview.export.WebView.loadUrl", description: "navigate UC WebView URL" } },
            { className: "com.uc.webview.export.WebView", methodName: "postUrl", meta: { category: "webview", signalKey: "webViewNavigation", api: "com.uc.webview.export.WebView.postUrl", description: "post UC WebView URL" } },
            { className: "android.webkit.CookieManager", methodName: "getCookie", meta: { category: "webview", signalKey: "cookieAccess", api: "android.webkit.CookieManager.getCookie", description: "read WebView cookie" } },
            { className: "android.webkit.CookieManager", methodName: "setCookie", meta: { category: "webview", signalKey: "cookieAccess", api: "android.webkit.CookieManager.setCookie", description: "write WebView cookie" } },
            { className: "java.net.URL", methodName: "openConnection", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.URL.openConnection", description: "open URL connection" } },
            { className: "java.net.URLConnection", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.URLConnection.connect", description: "connect URL connection" } },
            { className: "java.net.HttpURLConnection", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.HttpURLConnection.connect", description: "connect HTTP URL connection" } },
            { className: "javax.net.ssl.HttpsURLConnection", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "javax.net.ssl.HttpsURLConnection.connect", description: "connect HTTPS URL connection" } },
            { className: "java.net.Socket", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.Socket.connect", description: "open socket connection" } },
            { className: "okhttp3.OkHttpClient", methodName: "newCall", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.OkHttpClient.newCall", description: "start OkHttp call" } },
            { className: "okhttp3.RealCall", methodName: "execute", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.RealCall.execute", description: "execute OkHttp call" } },
            { className: "okhttp3.RealCall", methodName: "enqueue", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.RealCall.enqueue", description: "enqueue OkHttp call" } },
            { className: "android.content.ContextWrapper", methodName: "openFileInput", meta: { category: "storage", signalKey: "accessStorage", api: "android.content.ContextWrapper.openFileInput", description: "read internal file" } },
            { className: "android.content.ContextWrapper", methodName: "openFileOutput", meta: { category: "storage", signalKey: "accessStorage", api: "android.content.ContextWrapper.openFileOutput", description: "write internal file" } },
            { className: "android.os.Environment", methodName: "getExternalStorageDirectory", meta: { category: "storage", signalKey: "accessStorage", api: "android.os.Environment.getExternalStorageDirectory", description: "read external storage path" } },
            { className: "android.telephony.SmsManager", methodName: "sendTextMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendTextMessage", description: "send SMS" } },
            { className: "android.telephony.SmsManager", methodName: "sendMultipartTextMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendMultipartTextMessage", description: "send multipart SMS" } },
            { className: "android.telephony.SmsManager", methodName: "sendDataMessage", meta: { category: "sms", signalKey: "sendSms", api: "android.telephony.SmsManager.sendDataMessage", description: "send data SMS" } }
        ]);

        ["com.android.id.impl.IdProviderImpl", "com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy", "repeackage.com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy", "com.heytap.openid.IOpenID$Stub$Proxy", "com.zui.deviceidservice.IDeviceidInterface$Stub$Proxy"].forEach(function (className) {
            ["getOAID", "getAAID", "getVAID", "getUDID"].forEach(function (methodName) {
                hookMethod(className, methodName, { category: "device_identifier", signalKey: "getOaid", api: className + "." + methodName, description: "read OAID or vendor identifier" });
            });
        });

        hookMethod("android.content.ContextWrapper", "getSystemService", { category: "system_service", signalKey: "getSystemService", api: "android.content.ContextWrapper.getSystemService", description: "request system service" }, {
            filter: function (args) { return classifyService(args && args.length > 0 ? args[0] : null) !== null; },
            enrich: function (args, ret) {
                var meta = classifyService(args && args.length > 0 ? args[0] : null) || {};
                var serviceClass = "";
                try { serviceClass = ret && ret.getClass ? s(ret.getClass().getName()) : s(ret); } catch (e) {}
                return { service_name: s(args[0]), service_class: serviceClass, category: meta.category || "system_service", signal_key: meta.signalKey || "getSystemService", description: meta.description || "request system service" };
            }
        });

        ["query", "insert", "update", "delete"].forEach(function (methodName) {
            hookMethod("android.content.ContentResolver", methodName, { category: "content_provider", signalKey: "accessStorage", api: "android.content.ContentResolver." + methodName, description: "access content provider" }, {
                filter: function (args) { return args && args.length > 0 && classifyUri(args[0]) !== null; },
                enrich: function (args) {
                    var meta = classifyUri(args[0]) || {};
                    return { uri: s(args[0]), category: meta.category || "content_provider", signal_key: meta.signalKey || "accessStorage", description: meta.description || "access content provider" };
                }
            });
        });

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

setImmediate(function () {
    bootstrapHooks(0);
});
