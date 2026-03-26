// ================================================================
// APP 隐私权限动态监控脚本 (反Root检测加固 + 敏感API捕获)
// ================================================================
Java.perform(function () {
    console.log("\n========================================");
    console.log("[Hook] 注入成功，开始部署全覆盖反检测盾牌...");
    console.log("========================================\n");

    // ============================================================
    // 第一优先级: 反 Root 环境检测 (必须在所有其他 Hook 之前执行)
    // ============================================================
    
    // [防线1] Hook 文件系统检测 —— 拦截对 su/magisk/frida 文件路径的探测
    try {
        var File = Java.use("java.io.File");
        var BLOCKED_PATHS = [
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su", "/su/bin",
            "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
            "/system/app/Magisk.apk",
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
            "/cache/.disable_selinux", "/proc/net/xt_qtaguid/ctrl",
            "magisk", "frida", "frida-server", "re.frida.server",
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
        ];
    
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < BLOCKED_PATHS.length; i++) {
                if (path.toLowerCase().indexOf(BLOCKED_PATHS[i].toLowerCase()) !== -1) {
                    return false; // 欺骗 APP：这个文件不存在
                }
            }
            return this.exists();
        };
    
        File.canExecute.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < BLOCKED_PATHS.length; i++) {
                if (path.toLowerCase().indexOf(BLOCKED_PATHS[i].toLowerCase()) !== -1) {
                    return false;
                }
            }
            return this.canExecute();
        };
        
        File.listFiles.overload().implementation = function () {
            var result = this.listFiles();
            if (!result) return result;
            var filtered = result.filter(function(f) {
                var name = f.getName().toLowerCase();
                return name.indexOf('magisk') === -1 && name.indexOf('frida') === -1;
            });
            return filtered;
        };
        console.log("[防线1] ✅ 文件系统探测拦截器已部署");
    } catch (e) {
        console.log("[防线1] ⚠️ 文件系统拦截部署失败: " + e);
    }
    
    // [防线2] Hook Runtime.exec —— 拦截 shell 命令执行检测 (which su / su -c id 等)
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var BLOCKED_COMMANDS = ["su", "which", "busybox", "magisk", "frida"];
        
        var blockCommand = function(cmd) {
            if (typeof cmd === 'string') {
                for (var i = 0; i < BLOCKED_COMMANDS.length; i++) {
                    if (cmd.indexOf(BLOCKED_COMMANDS[i]) !== -1) {
                        return true;
                    }
                }
            }
            return false;
        };
    
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (blockCommand(cmd)) {
                // 返回一个执行失败的假进程
                return this.exec.overload('java.lang.String').call(this, "echo no_root");
            }
            return this.exec.overload('java.lang.String').call(this, cmd);
        };
    
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            if (cmds && cmds.length > 0 && blockCommand(cmds[0])) {
                return this.exec.overload('java.lang.String').call(this, "echo no_root");
            }
            return this.exec.overload('[Ljava.lang.String;').call(this, cmds);
        };
    
        Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File').implementation = function (cmds, envp, dir) {
            if (cmds && cmds.length > 0 && blockCommand(cmds[0])) {
                return this.exec.overload('java.lang.String').call(this, "echo no_root");
            }
            return this.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File').call(this, cmds, envp, dir);
        };
        console.log("[防线2] ✅ Shell命令执行拦截器已部署");
    } catch (e) {
        console.log("[防线2] ⚠️ 命令拦截部署失败: " + e);
    }
    
    // [防线3] Hook PackageManager —— 拦截对 Root 管理应用包名的枚举查询
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        var ROOT_PACKAGES = [
            "com.topjohnwu.magisk",     // Magisk
            "eu.chainfire.supersu",      // SuperSU
            "com.noshufou.android.su",   // Superuser
            "com.noshufou.android.su.elite",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingouser.com",         // Kingo Root
            "com.mgyun.shua",
            "com.touchwiz.systemmanager",
            "com.ubuntuone.android.files",
            "com.keramidas.TitaniumBackup",
            "re.frida.server",           // Frida Server
        ];
    
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkgName, flags) {
            for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                if (pkgName === ROOT_PACKAGES[i]) {
                    var NotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                    throw NotFoundException;
                }
            }
            return this.getPackageInfo(pkgName, flags);
        };
        console.log("[防线3] ✅ Root应用包名枚举拦截器已部署");
    } catch (e) {
        console.log("[防线3] ⚠️ 包名枚举拦截部署失败: " + e);
    }
    
    // [防线4] Hook Build 属性 —— 伪造系统签名类型，隐藏 test-keys 标识
    try {
        var Build = Java.use("android.os.Build");
        if (Build.TAGS && Build.TAGS.value && Build.TAGS.value.indexOf("test-keys") !== -1) {
            Build.TAGS.value = "release-keys";
        }
        
        // 部分 APP 检测 Build.FINGERPRINT 中的 "generic" 或 "unknown" 特征
        if (Build.FINGERPRINT && Build.FINGERPRINT.value) {
            var fp = Build.FINGERPRINT.value;
            if (fp.indexOf("generic") !== -1 || fp.indexOf("unknown") !== -1) {
                Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
            }
        }
        console.log("[防线4] ✅ 系统Build属性伪装已部署");
    } catch (e) {
        console.log("[防线4] ⚠️ Build属性伪装部署失败: " + e);
    }
    
    // [防线5] Hook /proc/net/tcp 端口扫描 —— 阻止 APP 通过读取网络端口列表来发现 Frida Server (默认监听27042端口)
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        var FRIDA_PORT_HEX = "699A"; // 27042 的十六进制
        
        BufferedReader.readLine.implementation = function () {
            var line = this.readLine();
            // 过滤掉包含 Frida 默认端口特征的行
            if (line !== null && line.indexOf(FRIDA_PORT_HEX) !== -1) {
                return this.readLine(); // 跳过该行，继续读下一行
            }
            return line;
        };
        console.log("[防线5] ✅ Frida端口扫描反侦察已部署 (端口: 27042)");
    } catch (e) {
        console.log("[防线5] ⚠️ 端口扫描反侦察部署失败: " + e);
    }
    
    // [防线6] Hook System.getProperty —— 拦截通过系统属性读取 root 信息
    try {
        var SystemClass = Java.use("java.lang.System");
        SystemClass.getProperty.overload('java.lang.String').implementation = function (key) {
            var value = this.getProperty(key);
            if (key === "ro.debuggable" && value === "1") return "0";
            if (key === "ro.secure" && value === "0") return "1";
            if (key === "service.adb.root" && value === "1") return "0";
            return value;
        };
        console.log("[防线6] ✅ 系统属性查询拦截器已部署");
    } catch (e) {
        console.log("[防线6] ⚠️ 系统属性拦截部署失败: " + e);
    }
    
    console.log("\n[Hook] 反检测盾牌部署完毕！开始挂载敏感API捕获探针...\n");
    
    // ============================================================
    // 第二优先级: 敏感 API 调用捕获探针
    // ============================================================
    
    // 统一发送函数，防止栈溢出
    function safeSend(apiName, args, retVal) {
        try {
            send({
                api: apiName,
                args: args || [],
                return_value: retVal || ""
            });
        } catch(e) { /* 忽略发送失败 */ }
    }
    
    // [探针A] 设备标识符 API
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        
        TelephonyManager.getDeviceId.overload().implementation = function () {
            var ret = "FAKEDEVICE0000000";
            safeSend("TelephonyManager.getDeviceId()", [], ret);
            return ret;
        };
        
        if (TelephonyManager.getImei) {
            TelephonyManager.getImei.overload().implementation = function () {
                var ret = "000000000000000";
                safeSend("TelephonyManager.getImei()", [], ret);
                return ret;
            };
        }
        
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            var ret = "FAKE_IMSI";
            safeSend("TelephonyManager.getSubscriberId()", [], ret);
            return ret;
        };
        
        TelephonyManager.getSimSerialNumber.overload().implementation = function () {
            var ret = "FAKE_SIM_SERIAL";
            safeSend("TelephonyManager.getSimSerialNumber()", [], ret);
            return ret;
        };
        
        TelephonyManager.getLine1Number.overload().implementation = function () {
            var ret = "FAKE_PHONE_NUMBER";
            safeSend("TelephonyManager.getLine1Number()", [], ret);
            return ret;
        };
        console.log("[探针A] ✅ 设备标识符探针挂载成功");
    } catch (e) {
        console.log("[探针A] ⚠️ 设备标识符探针挂载失败: " + e);
    }
    
    // [探针B] 位置信息 API
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        
        LocationManager.requestLocationUpdates.overloads.forEach(function(overload) {
            overload.implementation = function() {
                safeSend("LocationManager.requestLocationUpdates()", [String(arguments[0])], "void");
                return this.requestLocationUpdates.apply(this, arguments);
            };
        });
        
        if (LocationManager.getLastKnownLocation) {
            LocationManager.getLastKnownLocation.overload("java.lang.String").implementation = function(provider) {
                safeSend("LocationManager.getLastKnownLocation()", [provider], "null");
                return this.getLastKnownLocation(provider);
            };
        }
        console.log("[探针B] ✅ 位置信息探针挂载成功");
    } catch (e) {
        console.log("[探针B] ⚠️ 位置信息探针挂载失败: " + e);
    }
    
    // [探针C] 联系人/短信数据库查询 API
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overloads.forEach(function(overload) {
            overload.implementation = function() {
                var uri = String(arguments[0]);
                if (uri.indexOf("contacts") !== -1 || uri.indexOf("sms") !== -1 || uri.indexOf("mms") !== -1 || uri.indexOf("call_log") !== -1) {
                    safeSend("ContentResolver.query()", [uri], "Cursor");
                }
                return this.query.apply(this, arguments);
            };
        });
        console.log("[探针C] ✅ 联系人/短信查询探针挂载成功");
    } catch (e) {
        console.log("[探针C] ⚠️ 联系人/短信查询探针挂载失败: " + e);
    }
    
    // [探针D] 相机 API
    try {
        var Camera = Java.use("android.hardware.Camera");
        if (Camera.open) {
            Camera.open.overload().implementation = function() {
                safeSend("Camera.open()", [], "Camera");
                return this.open();
            };
        }
        
        var CameraManager = Java.use("android.hardware.camera2.CameraManager");
        if (CameraManager.openCamera) {
            CameraManager.openCamera.overload("java.lang.String", "android.hardware.camera2.CameraDevice$StateCallback", "android.os.Handler").implementation = function(id, cb, handler) {
                safeSend("CameraManager.openCamera()", [id], "void");
                return this.openCamera(id, cb, handler);
            };
        }
        console.log("[探针D] ✅ 相机访问探针挂载成功");
    } catch (e) {
        console.log("[探针D] ⚠️ 相机访问探针挂载失败: " + e);
    }
    
    // [探针E] 录音 API
    try {
        var MediaRecorder = Java.use("android.media.MediaRecorder");
        if (MediaRecorder.start) {
            MediaRecorder.start.overload().implementation = function() {
                safeSend("MediaRecorder.start()", [], "void");
                return this.start();
            };
        }
        if (MediaRecorder.setAudioSource) {
            MediaRecorder.setAudioSource.overload("int").implementation = function(src) {
                safeSend("MediaRecorder.setAudioSource()", [src], "void");
                return this.setAudioSource(src);
            };
        }
        
        var AudioRecord = Java.use("android.media.AudioRecord");
        if (AudioRecord.startRecording) {
            AudioRecord.startRecording.overload().implementation = function() {
                safeSend("AudioRecord.startRecording()", [], "void");
                return this.startRecording();
            };
        }
        console.log("[探针E] ✅ 录音API探针挂载成功");
    } catch (e) {
        console.log("[探针E] ⚠️ 录音探针挂载失败: " + e);
    }
    
    // [探针F] 存储访问 API
    try {
        var Environment = Java.use("android.os.Environment");
        if (Environment.getExternalStorageDirectory) {
            Environment.getExternalStorageDirectory.overload().implementation = function() {
                safeSend("Environment.getExternalStorageDirectory()", [], "/sdcard");
                return this.getExternalStorageDirectory();
            };
        }
        console.log("[探针F] ✅ 外部存储探针挂载成功");
    } catch (e) {
        console.log("[探针F] ⚠️ 外部存储探针挂载失败: " + e);
    }
    
    // [探针G] 网络通信 API
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            safeSend("URL.openConnection()", [this.toString()], "URLConnection");
            return this.openConnection();
        };
        console.log("[探针G] ✅ 网络通信探针挂载成功");
    } catch (e) {
        console.log("[探针G] ⚠️ 网络通信探针挂载失败: " + e);
    }
    
    // [探针H] 应用列表枚举 API（隐私合规的重要检测项）
    try {
        var PackageManagerH = Java.use("android.app.ApplicationPackageManager");
        PackageManagerH.getInstalledApplications.overload('int').implementation = function(flags) {
            safeSend("PackageManager.getInstalledApplications()", [flags], "List<ApplicationInfo>");
            return this.getInstalledApplications(flags);
        };
        
        PackageManagerH.getInstalledPackages.overload('int').implementation = function(flags) {
            safeSend("PackageManager.getInstalledPackages()", [flags], "List<PackageInfo>");
            return this.getInstalledPackages(flags);
        };
        console.log("[探针H] ✅ 应用列表枚举探针挂载成功");
    } catch (e) {
        console.log("[探针H] ⚠️ 应用列表探针挂载失败: " + e);
    }
    
    // [探针I] 剪贴板 API（隐私数据窃取高危项）
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function() {
            safeSend("ClipboardManager.getPrimaryClip()", [], "ClipData");
            return this.getPrimaryClip();
        };
        console.log("[探针I] ✅ 剪贴板访问探针挂载成功");
    } catch (e) {
        console.log("[探针I] ⚠️ 剪贴板探针挂载失败: " + e);
    }
    
    // [探针J] 账号信息 API
    try {
        var AccountManager = Java.use("android.accounts.AccountManager");
        AccountManager.getAccounts.overload().implementation = function() {
            safeSend("AccountManager.getAccounts()", [], "Account[]");
            return this.getAccounts();
        };
        AccountManager.getAccountsByType.overload('java.lang.String').implementation = function(type) {
            safeSend("AccountManager.getAccountsByType()", [type], "Account[]");
            return this.getAccountsByType(type);
        };
        console.log("[探针J] ✅ 账号信息探针挂载成功");
    } catch (e) {
        console.log("[探针J] ⚠️ 账号信息探针挂载失败: " + e);
    }
    
    console.log("\n========================================");
    console.log("[Hook] ✅ 所有探针部署完成！系统进入监控状态...");
    console.log("========================================\n");
});