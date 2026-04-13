import Java from "frida-java-bridge";

"use strict";

function bootstrapHooks(retryCount) {
    if ((retryCount || 0) === 0) {
        send({ type: "status", message: "frida bootstrap entered" });
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

        function installRootBypass() {
            try {
                var File = Java.use("java.io.File");
                var Runtime = Java.use("java.lang.Runtime");
                var suspicious = ["/system/bin/su", "/system/xbin/su", "/data/local/tmp/frida-server", "magisk", "frida"];
                var exists = File.exists.overload();
                exists.implementation = function () {
                    return has(this.getAbsolutePath(), suspicious) ? false : exists.call(this);
                };
                var execString = Runtime.exec.overload("java.lang.String");
                execString.implementation = function (command) {
                    return has(command, ["su", "which", "magisk"]) ? execString.call(this, "invalid_command") : execString.call(this, command);
                };
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
            { className: "java.net.URL", methodName: "openConnection", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.URL.openConnection", description: "open URL connection" } },
            { className: "java.net.Socket", methodName: "connect", meta: { category: "network", signalKey: "accessNetwork", api: "java.net.Socket.connect", description: "open socket connection" } },
            { className: "okhttp3.OkHttpClient", methodName: "newCall", meta: { category: "network", signalKey: "accessNetwork", api: "okhttp3.OkHttpClient.newCall", description: "start OkHttp call" } },
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
