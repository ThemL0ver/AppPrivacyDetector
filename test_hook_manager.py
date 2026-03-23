# 测试 HookManager 连接设备
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dynamic_engine.hook_manager import HookManager

if __name__ == "__main__":
    # 测试 HookManager 连接设备
    package_name = "com.android.contacts"
    print("=" * 60)
    print(f"测试 HookManager 连接到 {package_name}")
    print("=" * 60)
    
    hm = HookManager(package_name)
    
    # 连接设备
    if not hm.connect_device():
        print("无法连接设备")
        sys.exit(1)
    
    print("设备连接成功！")
    print(f"设备对象: {hm.device}")
    
    # 测试 frida-ps 命令
    print("\n测试 frida-ps 命令...")
    import subprocess
    result = subprocess.run(["frida-ps", "-U"], capture_output=True, text=True)
    print(f"frida-ps 输出: {result.stdout[:500]}...")
    
    # 尝试启动 Hook
    success, pid = hm.start()
    if success:
        print(f"Hook 启动成功！PID: {pid}")
        
        # 加载简单脚本
        script_path = "dynamic_engine/hooks/sensitive_api_hook.js"
        if not hm.load_script(script_path, pid):
            print("无法加载Hook脚本")
            hm.stop()
            sys.exit(1)
        
        print("脚本加载成功！")
        
        # 等待一会儿
        import time
        print("等待 5 秒...")
        time.sleep(5)
        
        # 停止 Hook
        hm.stop()
        print("Hook 已停止")
    else:
        print("Hook 启动失败")
