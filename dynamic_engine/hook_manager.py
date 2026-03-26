# Frida Hook管理器 - 动态行为监控引擎 (反检测加固版)
import frida
import sys
import json
import time
import subprocess
from typing import Dict, List, Optional

class HookManager:
    def __init__(self, package_name):
        self.package_name = package_name
        self.device = None
        self.session = None
        self.script = None
        self.hooked_apis = []
        self.call_logs = []
        self.is_running = False
        self.spawned_pid = None  # 记录 spawn 启动的 PID
        
    def connect_device(self) -> bool:
        """
        连接到 Frida 设备。
        关键原则：必须通过 127.0.0.1:27042 (frida-server端口) 连接，
        而非 ADB 端口 62026。端口转发已在 analyzer._start_frida_server 中完成。
        """
        print("[HookManager] 正在连接设备...")

        # -------------------------------------------------------
        # 方案A: 通过 127.0.0.1:27042 连接（端口转发模式，最稳定）
        # 前提: analyzer.py 已执行 adb forward tcp:27042 tcp:27042
        # -------------------------------------------------------
        try:
            mgr = frida.get_device_manager()
            self.device = mgr.add_remote_device("127.0.0.1:27042")
            # 通过列举进程来验证连接是否真正有效（不只是建立了socket）
            self.device.enumerate_processes()
            print(f"[HookManager] ✅ 成功通过端口转发连接到 frida-server (27042)")
            return True
        except Exception as e:
            print(f"[HookManager] 方案A (端口转发27042) 失败: {e}")

        # -------------------------------------------------------
        # 方案B: USB 设备（真机或支持USB调试的模拟器）
        # -------------------------------------------------------
        try:
            self.device = frida.get_usb_device(timeout=5)
            self.device.enumerate_processes()
            print(f"[HookManager] ✅ 成功连接到 USB 设备")
            return True
        except Exception as e:
            print(f"[HookManager] 方案B (USB) 失败: {e}")

        # -------------------------------------------------------
        # 方案C: 本机 frida-server（Frida 直接监听本地端口的场景）
        # -------------------------------------------------------
        try:
            self.device = frida.get_local_device()
            print(f"[HookManager] ✅ 成功连接到本地 Frida 设备")
            return True
        except Exception as e:
            print(f"[HookManager] 方案C (本地) 失败: {e}")

        print("[HookManager] ❌ 所有连接方案均失败。")
        print("[HookManager]    排查建议:")
        print("[HookManager]    1. 确认 frida-server 在模拟器中正在运行: adb shell pgrep -f frida-server")
        print("[HookManager]    2. 确认端口转发已建立: adb forward --list")
        print("[HookManager]    3. 确认 Frida 版本匹配: PC端 frida 版本应与设备端 frida-server 版本一致")
        return False

    def start(self, spawn: bool = True) -> tuple:
        """
        启动 Frida 会话。
        重要：默认强制使用 spawn 模式，以确保在 APP 执行 Root 检测代码之前完成注入。
        """
        print(f"[HookManager] 准备以 {'Spawn(注入优先)' if spawn else 'Attach(附加)'} 模式启动...")
        
        # 优先尝试 Spawn 模式（绕过反调试的核心）
        if spawn:
            result = self._try_spawn()
            if result[0]:
                return result
        
        # Spawn 失败后才降级尝试 Attach 模式
        print("[HookManager] Spawn 模式失败，尝试 Attach 模式（注意: 可能被反Root检测拦截）...")
        return self._try_attach()

    def _try_spawn(self) -> tuple:
        """
        Spawn 模式：Frida 接管 APP 的启动过程，在任何应用代码运行前完成注入。
        这是绕过启动阶段 Root 检测的唯一可靠方式。
        """
        try:
            print(f"[HookManager] [Spawn] 正在接管启动进程: {self.package_name}...")
            
            # 先确保目标 APP 没有残留进程
            self._kill_existing_process()
            time.sleep(1)
            
            # 核心: device.spawn() 让 Frida 控制 APP 的启动
            pid = self.device.spawn([self.package_name])
            print(f"[HookManager] [Spawn] APP进程已创建，PID: {pid}")
            
            # 在 APP 主线程 resume 前完成 session 建立
            self.session = self.device.attach(pid)
            self.spawned_pid = pid
            
            print(f"[HookManager] [Spawn] Session 建立成功，等待脚本注入...")
            self.is_running = True
            # 注意：此时 APP 处于暂停(suspended)状态，必须在 load_script() 中 resume
            return True, pid
            
        except Exception as e:
            print(f"[HookManager] [Spawn] 模式失败: {e}")
            return False, None

    def _try_attach(self) -> tuple:
        """Attach 模式：附加到已运行的 APP 进程（反Root检测可能已触发）"""
        try:
            # 确保 APP 在运行
            if not self._ensure_app_running():
                return False, None
            
            # 通过包名或 PID 附加
            try:
                self.session = self.device.attach(self.package_name)
                print("[HookManager] [Attach] 通过包名附加成功")
                self.is_running = True
                return True, None
            except Exception:
                pid = self._get_app_pid()
                if pid:
                    self.session = self.device.attach(pid)
                    print(f"[HookManager] [Attach] 通过PID {pid} 附加成功")
                    self.is_running = True
                    return True, None
        except Exception as e:
            print(f"[HookManager] [Attach] 模式失败: {e}")
        
        return False, None

    def load_script(self, js_path: str, pid: int = None) -> bool:
        """加载 Hook 脚本，并在 Spawn 模式下在加载完成后才恢复 APP 进程"""
        if not self.session:
            print("[HookManager] 没有有效的 Session，无法加载脚本。")
            return False
        try:
            with open(js_path, 'r', encoding='utf-8') as f:
                js_code = f.read()
            
            # 给脚本包裹顶层异常处理，防止单个 Hook 失败导致整个脚本崩溃
            wrapped_js = f'''
            try {{
                {js_code}
            }} catch (e) {{
                console.error('[HookManager] 脚本顶层错误: ' + e.message + '\n' + e.stack);
            }}
            '''
            
            self.script = self.session.create_script(wrapped_js)
            self.script.on('message', self._on_message)
            self.script.load()
            print(f"[HookManager] 脚本加载成功: {js_path}")
            
            # 关键：脚本注入完成后，才 resume APP 进程继续执行
            # 这保证了 APP 的每一行代码都运行在我们的 Hook 之下
            target_pid = pid if pid is not None else self.spawned_pid
            if target_pid is not None:
                self.device.resume(target_pid)
                print(f"[HookManager] APP进程已恢复执行 (PID: {target_pid})")
            
            return True
        except Exception as e:
            print(f"[HookManager] 脚本加载失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _kill_existing_process(self):
        """在 Spawn 前清理已存在的 APP 进程残留"""
        try:
            subprocess.run(
                ["adb", "shell", "am", "force-stop", self.package_name],
                capture_output=True, timeout=5
            )
            print(f"[HookManager] 已清理残留进程: {self.package_name}")
        except Exception:
            pass

    def _ensure_app_running(self) -> bool:
        """检查 APP 是否在运行，如果没有则尝试启动"""
        if self._get_app_pid():
            return True
        
        print(f"[HookManager] APP 未运行，尝试启动...")
        try:
            subprocess.run(
                ["adb", "shell", "monkey", "-p", self.package_name, "-c",
                 "android.intent.category.LAUNCHER", "1"],
                capture_output=True, timeout=15
            )
            time.sleep(5)
            return self._get_app_pid() is not None
        except Exception as e:
            print(f"[HookManager] 启动 APP 失败: {e}")
            return False

    def _get_app_pid(self) -> Optional[int]:
        """通过 ADB 获取 APP 的 PID"""
        try:
            result = subprocess.run(
                ["adb", "shell", "pidof", self.package_name],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                pids = result.stdout.strip().split()
                return int(pids[0])
        except Exception:
            pass
        
        try:
            result = subprocess.run(
                ["adb", "shell", "ps", "-A"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if self.package_name in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
        except Exception:
            pass
        return None

    def _on_message(self, message, data):
        """处理从 Frida 脚本发来的消息"""
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict):
                api = payload.get('api', '')
                # 过滤空记录（初始化时产生的空占位）
                if api:
                    print(f"[HOOK] 捕获: {api}")
                    self.call_logs.append({
                        'timestamp': time.time(),
                        'api': api,
                        'args': payload.get('args', []),
                        'return_value': str(payload.get('return_value', '')),
                        'stack': payload.get('stack', '')
                    })
                    if api not in self.hooked_apis:
                        self.hooked_apis.append(api)
        elif message['type'] == 'error':
            print(f"[HookManager] JS错误: {message.get('description', '')} @ {message.get('fileName', '')}:{message.get('lineNumber', '')}")

    def get_hooked_apis(self) -> List[str]:
        return [api for api in self.hooked_apis if api]

    def get_call_logs(self) -> List[Dict]:
        return [log for log in self.call_logs if log.get('api')]

    def stop(self):
        """清理 Frida 会话和脚本资源"""
        if self.script:
            try:
                self.script.unload()
                print("[HookManager] 脚本已卸载")
            except Exception as e:
                print(f"[HookManager] 卸载脚本失败: {e}")
        
        if self.session:
            try:
                self.session.detach()
                print("[HookManager] Session 已分离")
            except Exception as e:
                print(f"[HookManager] 分离 Session 失败: {e}")
        
        self.is_running = False
        self.spawned_pid = None

    def is_connected(self) -> bool:
        return self.device is not None

# 示例用法
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    hm = HookManager(package_name)
    
    if not hm.connect_device():
        print("无法连接设备")
        sys.exit(1)
    
    if not hm.start():
        print("无法启动Hook")
        sys.exit(1)
    
    # 加载敏感API Hook脚本
    script_path = "dynamic_engine/hooks/sensitive_api_hook.js"
    if not hm.load_script(script_path):
        print("无法加载Hook脚本")
        hm.stop()
        sys.exit(1)
    
    print("[*] 正在监听敏感API调用... 按 Ctrl+C 停止")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 停止监听")
    finally:
        hm.stop()
        
        # 保存调用日志
        if hm.get_call_logs():
            log_file = f"hook_logs_{package_name}_{int(time.time())}.json"
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(hm.get_call_logs(), f, ensure_ascii=False, indent=2)
            print(f"[*] 调用日志已保存到: {log_file}")
        
        print(f"[*] 已hook的API: {hm.get_hooked_apis()}")
        print("[*] Hook已停止")