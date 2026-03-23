# 使用 Xposed 模块实现 Frida Hook 的详细步骤

## 方法一：使用 Xposed 模块加载 Frida Gadget

### 步骤 1：安装 Xposed 框架
1. **确保设备已 root**：Xposed 框架需要 root 权限
2. **安装 Xposed Installer**：
   - 对于 Android 5.0-8.1：安装 Xposed Installer APK
   - 对于 Android 9.0+：安装 EdXposed 或 LSPosed
3. **激活 Xposed 框架**：按照 Xposed Installer 的提示进行安装和激活

### 步骤 2：创建 Xposed 模块项目
1. **创建 Android 项目**：
   - 使用 Android Studio 创建一个新的 Android 项目
   - 最小 SDK 版本建议设置为 21+

2. **添加 Xposed 依赖**：
   - 在 `build.gradle` 文件中添加 Xposed 依赖
   ```gradle
   repositories {
       mavenCentral()
   }
   
   dependencies {
       // Xposed API
       compileOnly 'de.robv.android.xposed:api:82'
       compileOnly 'de.robv.android.xposed:api:82:sources'
   }
   ```

3. **配置 AndroidManifest.xml**：
   ```xml
   <manifest xmlns:android="http://schemas.android.com/apk/res/android"
       package="com.example.fridademo">
       
       <application
           android:label="Frida Xposed Module"
           android:icon="@mipmap/ic_launcher">
           
           <meta-data
               android:name="xposedmodule"
               android:value="true" />
           <meta-data
               android:name="xposeddescription"
               android:value="Load Frida Gadget for any app" />
           <meta-data
               android:name="xposedminversion"
               android:value="82" />
       </application>
   </manifest>
   ```

### 步骤 3：实现 Xposed 模块逻辑
1. **创建 Xposed 入口类**：
   ```java
   package com.example.fridademo;
   
   import de.robv.android.xposed.IXposedHookLoadPackage;
   import de.robv.android.xposed.XC_MethodHook;
   import de.robv.android.xposed.XposedHelpers;
   import de.robv.android.xposed.callbacks.XC_LoadPackage;
   
   public class FridaLoader implements IXposedHookLoadPackage {
       @Override
       public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
           // 目标应用包名
           String targetPackage = "com.android.contacts";
           
           if (lpparam.packageName.equals(targetPackage)) {
               // 加载 Frida Gadget
               loadFridaGadget(lpparam.classLoader);
           }
       }
       
       private void loadFridaGadget(ClassLoader classLoader) {
           try {
               // 加载 Frida Gadget 库
               System.loadLibrary("frida-gadget");
               XposedHelpers.findAndHookMethod(
                   "android.app.Application",
                   classLoader,
                   "onCreate",
                   new XC_MethodHook() {
                       @Override
                       protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                           // 在应用启动时初始化 Frida Gadget
                           System.out.println("Frida Gadget loaded!");
                       }
                   }
               );
           } catch (Exception e) {
               XposedBridge.log("Failed to load Frida Gadget: " + e.getMessage());
           }
       }
   }
   ```

2. **创建 xposed_init 文件**：
   - 在 `assets` 目录下创建 `xposed_init` 文件
   - 内容为你的 Xposed 入口类的完整路径：
     ```
     com.example.fridademo.FridaLoader
     ```

### 步骤 4：添加 Frida Gadget 库
1. **下载 Frida Gadget**：
   - 从 Frida 官方网站下载对应架构的 Frida Gadget
   - 地址：https://github.com/frida/frida/releases
   - 下载 `frida-gadget-{version}-android-{arch}.so` 文件

2. **添加到项目**：
   - 在 `app/src/main/jniLibs/{arch}/` 目录下添加下载的 so 文件
   - 例如：`app/src/main/jniLibs/arm64-v8a/libfrida-gadget.so`

### 步骤 5：构建和安装模块
1. **构建 APK**：使用 Android Studio 构建项目
2. **安装 APK**：将构建的 APK 安装到设备上
3. **激活模块**：在 Xposed Installer 中激活你的模块
4. **重启设备**：激活模块后需要重启设备

## 方法二：直接修改 APK 注入 Frida Gadget

### 步骤 1：准备工具
1. **APKTool**：用于反编译和重新编译 APK
2. **Frida Gadget**：下载对应架构的 Frida Gadget
3. **签名工具**：用于重新签名 APK

### 步骤 2：反编译 APK
```bash
apktool d target_app.apk -o target_app
```

### 步骤 3：注入 Frida Gadget
1. **添加 Frida Gadget 库**：
   - 将 `libfrida-gadget.so` 复制到 `target_app/lib/{arch}/` 目录

2. **修改 Application 类**：
   - 在 `AndroidManifest.xml` 中找到 Application 类
   - 在该类的 `onCreate` 方法中添加：
     ```java
     static {
         System.loadLibrary("frida-gadget");
     }
     ```

### 步骤 4：重新编译和签名
1. **重新编译 APK**：
   ```bash
   apktool b target_app -o modified_app.apk
   ```

2. **签名 APK**：
   ```bash
   jarsigner -keystore mykeystore.jks -signedjar signed_app.apk modified_app.apk alias_name
   ```

3. **安装签名后的 APK**：
   ```bash
   adb install -r signed_app.apk
   ```

## 方法三：使用 Frida Server with Root

如果设备已 root，可以尝试以下步骤：

1. **确保 frida-server 以 root 权限运行**：
   ```bash
   adb shell su -c './data/local/tmp/frida-server-17.7.3-android-x86_64 &'
   ```

2. **尝试使用 root 权限附加**：
   ```bash
   frida -U -f com.android.contacts --no-pause
   ```

3. **如果仍然失败，尝试修改 HookManager 代码**：
   - 在 `hook_manager.py` 中添加更多的错误处理和调试信息
   - 尝试使用不同的附加方式

## 常见问题解决方案

1. **"unable to connect to remote frida-server: closed"**：
   - 确保 frida-server 正在运行
   - 检查设备是否正确连接
   - 尝试重启 frida-server

2. **"need Gadget to attach on jailed Android"**：
   - 使用上述 Xposed 模块或 APK 修改方法
   - 确保设备已 root

3. **Frida Gadget 加载失败**：
   - 确保使用了正确架构的 Frida Gadget
   - 检查权限设置
   - 查看 logcat 中的错误信息

## 测试步骤

1. **启动目标应用**：
   ```bash
   adb shell am start -n com.android.contacts/.MainActivity
   ```

2. **使用 Frida 附加**：
   ```bash
   frida -U com.android.contacts
   ```

3. **测试 Hook**：
   ```javascript
   Java.perform(function() {
       var Activity = Java.use("android.app.Activity");
       Activity.onCreate.implementation = function(bundle) {
           console.log("onCreate called");
           this.onCreate(bundle);
       };
   });
   ```

通过以上方法，你应该能够成功在目标应用上实现 Frida hook，即使在 "jailed Android" 环境中。