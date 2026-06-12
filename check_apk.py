"""
APK 文件结构诊断工具。

该脚本用于快速检查目标 APK 文件的基本信息，包括：
1. 验证 APK 文件是否存在
2. 列出 APK（ZIP 格式）内部的所有文件
3. 检查 AndroidManifest.xml 是否存在及其大小/首字节内容

用途：在正式分析前确认 APK 文件的完整性和可读性。
      由于 APK 本质上是 ZIP 压缩包，可以直接使用 zipfile 模块读取。
"""

import zipfile
import os

# 待检查的 APK 文件路径（使用 samples 目录下的测试 APK）
apk_path = 'samples/Uu.apk'

# ======================== 步骤1：检查文件是否存在 ========================
print(f"检查APK文件: {apk_path}")
print(f"文件存在: {os.path.exists(apk_path)}")

if os.path.exists(apk_path):
    try:
        # 以只读方式打开 APK（ZIP 格式）
        with zipfile.ZipFile(apk_path, 'r') as zf:
            # ======================== 步骤2：列出 APK 内所有文件 ========================
            print(f"\nAPK文件中的文件列表:")
            for file in zf.namelist():
                print(f"  - {file}")
            
            # ======================== 步骤3：检查 AndroidManifest.xml ========================
            # AndroidManifest.xml 是 Android 应用的核心配置文件
            # 包含权限声明、组件注册等关键信息
            if 'AndroidManifest.xml' in zf.namelist():
                print("\nAndroidManifest.xml 存在")
                with zf.open('AndroidManifest.xml') as f:
                    data = f.read()
                    print(f"文件大小: {len(data)} bytes")
                    # 打印前 100 个字节，帮助判断文件是否为二进制格式（AXML）
                    print(f"前100个字节: {data[:100]}")
            else:
                print("\nAndroidManifest.xml 不存在")
    except Exception as e:
        print(f"读取APK文件失败: {e}")
