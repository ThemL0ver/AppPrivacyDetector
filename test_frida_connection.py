# 调试Frida连接问题的脚本
import frida
import time
import subprocess

def find_main_activity(package_name):
    """查找应用的主Activity"""
    print(f"查找应用 {package_name} 的主Activity...")
    try:
        # 使用dumpsys命令获取应用信息
        result = subprocess.run(
            ["adb", "shell", "dumpsys", "package", package_name],
            capture_output=True, 
            text=True,
            timeout=15
        )
        
        if result.stdout:
            # 查找主Activity
            # 匹配格式: android.intent.action.MAIN:
            #     3473f0a com.example/.MainActivity filter ...
            import re
            pattern = r'android\.intent\.action\.MAIN:\s*\n\s+([^\s]+)'
            match = re.search(pattern, result.stdout)
            if match:
                activity_info = match.group(1)
                # 提取Activity名称，格式通常是 com.example/.MainActivity
                if '/' in activity_info:
                    activity = activity_info.split('/')[-1]
                    print(f"找到主Activity: {activity}")
                    return activity
        
        # 如果找不到，尝试使用更通用的方式
        print("未找到具体的主Activity，使用通用方式启动")
        return None
    except Exception as e:
        print(f"查找主Activity失败: {e}")
        return None

def start_app(package_name):
    """启动应用"""
    print(f"尝试启动应用: {package_name}")
    
    # 尝试多种启动方式
    methods = [
        # 方法1：使用monkey启动（最通用）
        ["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        # 方法2：使用am start启动（不带具体Activity）
        ["adb", "shell", "am", "start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "-p", package_name],
        # 方法3：使用简单的monkey命令
        ["adb", "shell", "monkey", "-p", package_name, "1"]
    ]
    
    for i, method in enumerate(methods):
        print(f"尝试启动方法 {i+1}: {' '.join(method)}")
        try:
            result = subprocess.run(
                method,
                capture_output=True, 
                text=True,
                timeout=15
            )
            
            print(f"启动结果: {result.returncode}")
            if result.stdout:
                print(f"输出: {result.stdout}")
            if result.stderr:
                print(f"错误: {result.stderr}")
            
            # 等待应用启动
            time.sleep(5)
            
            # 检查应用是否在运行
            pid = get_app_pid(package_name)
            if pid:
                print(f"应用已成功启动，PID: {pid}")
                return True
        except Exception as e:
            print(f"启动失败: {e}")
    
    print("所有启动方法都失败了")
    return False

def get_app_pid(package_name):
    """获取应用的PID"""
    try:
        result = subprocess.run(
            ["adb", "shell", "ps"],
            capture_output=True, 
            text=True,
            timeout=10
        )
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if package_name in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            print(f"找到应用PID: {pid}")
                            return pid
                        except ValueError:
                            continue
    except Exception as e:
        print(f"获取PID失败: {e}")
    return None

def test_frida_connection(package_name):
    """测试Frida连接到应用的情况"""
    print(f"测试Frida连接到应用: {package_name}")
    
    # 先启动应用
    if not start_app(package_name):
        print("无法启动应用，测试失败")
        return False
    
    # 获取应用PID
    pid = get_app_pid(package_name)
    if not pid:
        print("无法找到应用进程，测试失败")
        return False
    
    try:
        # 1. 获取USB设备
        print("\n1. 尝试获取设备...")
        device = frida.get_usb_device(timeout=10)
        print(f"成功获取设备: {device}")
        
        # 2. 尝试通过PID附加到应用
        print(f"\n2. 尝试通过PID {pid} 附加到应用...")
        try:
            session = device.attach(pid)
            print("成功附加到应用")
            
            # 3. 加载简单脚本
            print("3. 尝试加载简单脚本...")
            script = session.create_script('console.log("Hello from Frida!");')
            script.load()
            print("成功加载脚本")
            
            # 等待一会儿
            time.sleep(5)
            
            # 4. 清理
            session.detach()
            print("测试成功！")
            return True
        except Exception as e:
            print(f"附加失败: {e}")
            
            # 尝试使用包名附加
            print("\n尝试使用包名附加到应用...")
            try:
                session = device.attach(package_name)
                print("成功附加到应用")
                
                # 加载简单脚本
                script = session.create_script('console.log("Hello from Frida!");')
                script.load()
                print("成功加载脚本")
                
                # 等待一会儿
                time.sleep(5)
                
                # 清理
                session.detach()
                print("测试成功！")
                return True
            except Exception as e2:
                print(f"附加到已运行应用失败: {e2}")
                
    except frida.ServerNotRunningError:
        print("错误: Frida Server 未在设备上启动")
    except frida.TimedOutError:
        print("错误: 连接设备超时，请检查USB连接")
    except Exception as e:
        print(f"发生未知错误: {str(e)}")
    
    return False

if __name__ == "__main__":
    # 测试去哪儿旅行应用
    package_name = "com.Qunar"
    print("=" * 60)
    print(f"测试 Frida 连接到 {package_name}")
    print("=" * 60)
    
    success = test_frida_connection(package_name)
    
    if success:
        print("\n测试成功！Frida 可以正常连接到应用")
    else:
        print("\n测试失败！请检查上述错误信息")
