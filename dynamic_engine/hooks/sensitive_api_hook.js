// 敏感API Hook脚本 - Frida
Java.perform(function () {
    console.log("[Hook] 开始Hook敏感API...");

    // ==========================================
    // 0. 通用 Root 和 环境检测绕过 (Bypass Root & Emulator)
    // ==========================================
    console.log("[Hook] 开始加载Root检测和环境检测绕过...");
    try {
        var File = Java.use("java.io.File");
        var Runtime = Java.use("java.lang.Runtime");
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        var StringClass = Java.use("java.lang.String");

        // 常见 Root 文件和 Frida 文件特征
        var rootFiles = [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/data/local/tmp/frida-server",
            "/data/local/tmp/frida-server-17.7.3-android-x86_64", // 针对你当前使用的版本
            "frida",
            "magisk"
        ];

        // Hook File.exists()
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootFiles.length; i++) {
                if (path.indexOf(rootFiles[i]) !== -1) {
                    // console.log("[Bypass] 拦截到 Root 文件检测: " + path);
                    return false; // 欺骗应用，告诉它文件不存在
                }
            }
            return this.exists();
        };

        // Hook Runtime.exec() 拦截 shell 命令如 `su` 和 `which su`
        Runtime.exec.overload('java.lang.String').implementation = function (command) {
            if (command.indexOf("su") !== -1 || command.indexOf("which") !== -1 || command.indexOf("magisk") !== -1) {
                // console.log("[Bypass] 拦截到命令执行: " + command);
                command = "invalid_command"; // 替换为一个无效命令
            }
            return this.exec.overload('java.lang.String').call(this, command);
        };

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdarray) {
            if (cmdarray.length > 0 && (cmdarray[0].indexOf("su") !== -1 || cmdarray[0].indexOf("which") !== -1)) {
                // console.log("[Bypass] 拦截到命令执行数组: " + cmdarray[0]);
                cmdarray[0] = "invalid_command";
            }
            return this.exec.overload('[Ljava.lang.String;').call(this, cmdarray);
        };

        // Hook PackageManager.getPackageInfo 拦截 Root 管理软件的包名检测
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkgName, flags) {
            var rootPackages = [
                "com.noshufou.android.su",
                "eu.chainfire.supersu",
                "com.topjohnwu.magisk",
                "com.koushikdutta.superuser"
            ];
            for (var i = 0; i < rootPackages.length; i++) {
                if (pkgName == rootPackages[i]) {
                    // console.log("[Bypass] 拦截到包名检测: " + pkgName);
                    var NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
                    throw NameNotFoundException.$new("Package not found");
                }
            }
            return this.getPackageInfo(pkgName, flags);
        };

        // 绕过 Build 属性检测 (如 test-keys 检测)
        var Build = Java.use("android.os.Build");
        if (Build.TAGS.value.indexOf("test-keys") !== -1) {
            Build.TAGS.value = "release-keys";
        }
        console.log("[Hook] Root检测绕过逻辑加载完成。");
    } catch (e) {
        console.log("[Hook] Root检测绕过逻辑加载失败: " + e);
    }
    // ==========================================


    // 1. 设备标识符相关API
    console.log("[Hook] 开始Hook设备标识符API...");
    
    // TelephonyManager
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        
        // getDeviceId
        if (TelephonyManager.getDeviceId) {
            TelephonyManager.getDeviceId.overload().implementation = function () {
                send({
                    api: "TelephonyManager.getDeviceId()",
                    args: [],
                    return_value: "FAKE_DEVICE_ID",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return "FAKE_DEVICE_ID";
            };
        }
        
        // getImei
        if (TelephonyManager.getImei) {
            TelephonyManager.getImei.overload().implementation = function () {
                send({
                    api: "TelephonyManager.getImei()",
                    args: [],
                    return_value: "FAKE_IMEI",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return "FAKE_IMEI";
            };
        }
        
        // getSubscriberId (IMSI)
        if (TelephonyManager.getSubscriberId) {
            TelephonyManager.getSubscriberId.overload().implementation = function () {
                send({
                    api: "TelephonyManager.getSubscriberId()",
                    args: [],
                    return_value: "FAKE_IMSI",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return "FAKE_IMSI";
            };
        }
        
        // getSimSerialNumber
        if (TelephonyManager.getSimSerialNumber) {
            TelephonyManager.getSimSerialNumber.overload().implementation = function () {
                send({
                    api: "TelephonyManager.getSimSerialNumber()",
                    args: [],
                    return_value: "FAKE_SIM_SERIAL",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return "FAKE_SIM_SERIAL";
            };
        }
    } catch (e) {
        console.log("[Hook] 无法Hook TelephonyManager: " + e);
    }
    
    // Build类 (获取设备信息)
    try {
        var Build = Java.use("android.os.Build");
        
        // 修改设备信息属性
        Object.getOwnPropertyNames(Build.class).forEach(function(name) {
            if (name !== "$class" && name !== "$super" && typeof Build[name] === "string" && name !== "TAGS") {
                Object.defineProperty(Build.class, name, {
                    get: function() {
                        send({
                            api: "Build." + name,
                            args: [],
                            return_value: "FAKE_" + name.toUpperCase(),
                            stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                        });
                        return "FAKE_" + name.toUpperCase();
                    }
                });
            }
        });
    } catch (e) {
        console.log("[Hook] 无法Hook Build: " + e);
    }
    
    // 2. 位置信息相关API
    console.log("[Hook] 开始Hook位置信息API...");
    
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        
        // requestLocationUpdates
        var overloads = LocationManager.requestLocationUpdates.overloads;
        overloads.forEach(function(overload) {
            overload.implementation = function() {
                var args = Array.from(arguments);
                send({
                    api: "LocationManager.requestLocationUpdates()",
                    args: args.map(arg => String(arg)),
                    return_value: "void",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.requestLocationUpdates.apply(this, arguments);
            };
        });
        
        // getLastKnownLocation
        if (LocationManager.getLastKnownLocation) {
            LocationManager.getLastKnownLocation.overload("java.lang.String").implementation = function(provider) {
                send({
                    api: "LocationManager.getLastKnownLocation()",
                    args: [provider],
                    return_value: "null",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return null;
            };
        }
    } catch (e) {
        console.log("[Hook] 无法Hook LocationManager: " + e);
    }
    
    // 3. 存储访问相关API
    console.log("[Hook] 开始Hook存储访问API...");
    
    try {
        var Context = Java.use("android.content.Context");
        
        // getExternalFilesDir
        if (Context.getExternalFilesDir) {
            Context.getExternalFilesDir.overload("java.lang.String").implementation = function(type) {
                send({
                    api: "Context.getExternalFilesDir()",
                    args: [type],
                    return_value: "FAKE_FILE_PATH",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.getExternalFilesDir(type);
            };
        }
        
        // getExternalStorageDirectory
        var Environment = Java.use("android.os.Environment");
        if (Environment.getExternalStorageDirectory) {
            Environment.getExternalStorageDirectory.overload().implementation = function() {
                send({
                    api: "Environment.getExternalStorageDirectory()",
                    args: [],
                    return_value: "FAKE_STORAGE_DIR",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.getExternalStorageDirectory();
            };
        }
    } catch (e) {
        console.log("[Hook] 无法Hook存储API: " + e);
    }
    
    // 4. 相机相关API
    console.log("[Hook] 开始Hook相机API...");
    
    try {
        var Camera = Java.use("android.hardware.Camera");
        
        // open
        if (Camera.open) {
            Camera.open.overload().implementation = function() {
                send({
                    api: "Camera.open()",
                    args: [],
                    return_value: "FAKE_CAMERA",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.open();
            };
        }
        
        // CameraManager (Android 5.0+)
        var CameraManager = Java.use("android.hardware.camera2.CameraManager");
        if (CameraManager.openCamera) {
            CameraManager.openCamera.overload("java.lang.String", "android.hardware.camera2.CameraDevice$StateCallback", "android.os.Handler").implementation = function(cameraId, callback, handler) {
                send({
                    api: "CameraManager.openCamera()",
                    args: [cameraId, "Callback", "Handler"],
                    return_value: "void",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.openCamera(cameraId, callback, handler);
            };
        }
    } catch (e) {
        console.log("[Hook] 无法Hook相机API: " + e);
    }
    
    // 5. 麦克风/音频录制相关API
    console.log("[Hook] 开始Hook音频录制API...");
    
    try {
        var MediaRecorder = Java.use("android.media.MediaRecorder");
        
        // start
        if (MediaRecorder.start) {
            MediaRecorder.start.overload().implementation = function() {
                send({
                    api: "MediaRecorder.start()",
                    args: [],
                    return_value: "void",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.start();
            };
        }
        
        // setAudioSource
        if (MediaRecorder.setAudioSource) {
            MediaRecorder.setAudioSource.overload("int").implementation = function(source) {
                send({
                    api: "MediaRecorder.setAudioSource()",
                    args: [source],
                    return_value: "void",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.setAudioSource(source);
            };
        }
    } catch (e) {
        console.log("[Hook] 无法Hook音频API: " + e);
    }
    
    // 6. 联系人相关API
    console.log("[Hook] 开始Hook联系人API...");
    
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        
        // query
        var queryOverloads = ContentResolver.query.overloads;
        queryOverloads.forEach(function(overload) {
            overload.implementation = function() {
                var args = Array.from(arguments);
                // 检查是否查询联系人
                if (args.length > 0 && String(args[0]).includes("contacts")) {
                    send({
                        api: "ContentResolver.query()",
                        args: args.map(arg => String(arg)),
                        return_value: "FAKE_CURSOR",
                        stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                    });
                }
                return this.query.apply(this, arguments);
            };
        });
    } catch (e) {
        console.log("[Hook] 无法Hook联系人API: " + e);
    }
    
    // 7. 自定义权限相关API
    console.log("[Hook] 开始Hook自定义权限API...");
    
    // Asus MSA (SupplementaryDID)
    try {
        // 尝试Hook Asus MSA相关类
        var AsusMSA = Java.use("com.asus.msa.SupplementaryDID");
        if (AsusMSA) {
            // Hook所有方法
            var methods = AsusMSA.class.getDeclaredMethods();
            methods.forEach(function(method) {
                var methodName = method.getName();
                if (AsusMSA[methodName]) {
                    var overloads = AsusMSA[methodName].overloads;
                    overloads.forEach(function(overload) {
                        overload.implementation = function() {
                            var args = Array.from(arguments);
                            send({
                                api: "com.asus.msa.SupplementaryDID." + methodName + "()",
                                args: args.map(arg => String(arg)),
                                return_value: "FAKE_VALUE",
                                stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                            });
                            return this[methodName].apply(this, arguments);
                        };
                    });
                }
            });
        }
    } catch (e) {
        console.log("[Hook] 无法Hook Asus MSA: " + e);
    }
    
    // 8. 网络相关API
    console.log("[Hook] 开始Hook网络API...");
    
    try {
        var URL = Java.use("java.net.URL");
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        // URL.openConnection
        if (URL.openConnection) {
            URL.openConnection.overload().implementation = function() {
                send({
                    api: "URL.openConnection()",
                    args: [],
                    return_value: "FAKE_CONNECTION",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.openConnection();
            };
        }
        
        // HttpURLConnection.connect
        if (HttpURLConnection.connect) {
            HttpURLConnection.connect.overload().implementation = function() {
                send({
                    api: "HttpURLConnection.connect()",
                    args: [],
                    return_value: "void",
                    stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
                });
                return this.connect();
            };
        }
    } catch (e) {
        console.log("[Hook] 无法Hook网络API: " + e);
    }
    
    console.log("[Hook] 敏感API Hook初始化完成！");
});
