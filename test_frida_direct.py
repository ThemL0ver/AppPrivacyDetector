# 直接测试Frida连接
import frida
import time

print("=" * 60)
print("直接测试 Frida 连接")
print("=" * 60)

try:
    # 获取设备
    print("1. 获取设备...")
    # 使用与 hook_manager.py 相同的方式获取设备
    try:
        # 尝试连接夜神模拟器
        device = frida.get_device_manager().add_remote_device("127.0.0.1:62026")
        print(f"成功连接到夜神模拟器: {device}")
    except Exception as e:
        print(f"连接夜神模拟器失败: {e}")
        # 尝试使用USB设备
        device = frida.get_usb_device(timeout=10)
        print(f"成功获取USB设备: {device}")
    
    # 尝试列出所有进程
    print("\n2. 列出所有进程...")
    processes = device.enumerate_processes()
    print(f"找到 {len(processes)} 个进程")
    
    # 查找包含 Qunar 的进程
    qunar_processes = [p for p in processes if "Qunar" in p.name or "qunar" in p.name]
    if qunar_processes:
        print("\n找到包含 Qunar 的进程:")
        for p in qunar_processes:
            print(f"  PID: {p.pid}, 名称: {p.name}")
        
        # 尝试附加到第一个找到的进程
        target_process = qunar_processes[0]
        print(f"\n3. 尝试附加到进程 {target_process.name} (PID: {target_process.pid})...")
        session = device.attach(target_process.pid)
        print("成功附加到进程")
        
        # 加载简单脚本
        print("4. 加载简单脚本...")
        script = session.create_script('console.log("Hello from Frida!");')
        script.load()
        print("成功加载脚本")
        
        # 等待一会儿
        time.sleep(5)
        
        # 清理
        session.detach()
        print("测试成功！")
    else:
        print("\n未找到包含 Qunar 的进程")
        
        # 尝试使用包名附加
        print("\n尝试使用包名附加到应用...")
        try:
            session = device.attach("com.Qunar")
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
        except Exception as e:
            print(f"附加失败: {e}")
            
            # 尝试使用 spawn 方式
            print("\n尝试使用 spawn 方式启动应用...")
            try:
                pid = device.spawn(["com.Qunar"])
                print(f"成功 spawn 应用，PID: {pid}")
                session = device.attach(pid)
                print("成功附加到进程")
                
                # 加载简单脚本
                script = session.create_script('console.log("Hello from Frida!");')
                script.load()
                print("成功加载脚本")
                
                # 恢复进程
                device.resume(pid)
                print("进程已恢复")
                
                # 等待一会儿
                time.sleep(5)
                
                # 清理
                session.detach()
                print("测试成功！")
            except Exception as e2:
                print(f"spawn 方式失败: {e2}")

except frida.ServerNotRunningError:
    print("错误: Frida Server 未在设备上启动")
except frida.TimedOutError:
    print("错误: 连接设备超时，请检查USB连接")
except Exception as e:
    print(f"发生未知错误: {str(e)}")
