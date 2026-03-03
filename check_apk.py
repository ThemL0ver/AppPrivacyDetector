import zipfile
import os

apk_path = 'samples/Uu.apk'

print(f"检查APK文件: {apk_path}")
print(f"文件存在: {os.path.exists(apk_path)}")

if os.path.exists(apk_path):
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            print(f"\nAPK文件中的文件列表:")
            for file in zf.namelist():
                print(f"  - {file}")
            
            if 'AndroidManifest.xml' in zf.namelist():
                print("\nAndroidManifest.xml 存在")
                with zf.open('AndroidManifest.xml') as f:
                    data = f.read()
                    print(f"文件大小: {len(data)} bytes")
                    print(f"前100个字节: {data[:100]}")
            else:
                print("\nAndroidManifest.xml 不存在")
    except Exception as e:
        print(f"读取APK文件失败: {e}")
