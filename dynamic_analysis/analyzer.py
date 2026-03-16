#动态分析模块 - 基于ADB的模拟器测试
import os
import subprocess
import time
import json
from typing import Dict, List, Optional
import re
from tqdm import tqdm

# 尝试导入 frida 分析器，如果失败则设置为 None
try:
    from dynamic_engine.frida_analyzer import EnhancedDynamicAnalyzer
    frida_available = True
except ImportError:
    print("警告: Frida 模块未安装，将跳过 Frida 分析")
    frida_available = False

class DynamicAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = "output"):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.package_name = self._extract_package_name_from_apk()  # 预提取包名，避免重复提取
        self.adb_path = self._find_adb()
        self.sensitive_apis = self._load_sensitive_apis()
        self.monitoring_logs = []
        self.frida_analyzer = EnhancedDynamicAnalyzer(apk_path, output_dir) if frida_available else None
        self.device_id = None
        self.app_pid = None
        
    def _find_adb(self) -> str:
        """查找ADB工具路径"""
        # 优先使用夜神模拟器的ADB工具，再检查环境变量中的ADB
        adb_paths = [
            r"E:\\Nox\\bin\\nox_adb.exe",  # 用户提供的夜神模拟器路径
            r"C:\\Program Files (x86)\\Nox\\bin\\adb.exe",  # 夜神模拟器默认路径
        ]
        
        for path in adb_paths:
            try:
                subprocess.run([path, "version"], capture_output=True, check=True, timeout=5)
                print(f"找到ADB: {path}")
                return path
            except (subprocess.SubprocessError, FileNotFoundError):
                continue

         # 再尝试环境变量中的 adb
        try:
            subprocess.run(["adb", "version"], capture_output=True, check=True, timeout=5)
            print("找到系统ADB: adb")
            return "adb"
        except:
            pass
        
        print("警告: 未找到ADB，请确保ADB已添加到环境变量或夜神模拟器已安装")
        return "adb"
    
    def _load_sensitive_apis(self) -> Dict[str, str]:
        """加载敏感API列表"""
        return {
            "getDeviceId": "设备标识",
            "getSubscriberId": "SIM卡标识",
            "getMacAddress": "MAC地址",
            "getLocation": "位置信息",
            "openCamera": "相机访问",
            "startRecording": "音频录制",
            "readContacts": "读取联系人",
            "readSms": "读取短信",
            "accessStorage": "存储访问",
            "getInstalledPackages": "应用列表",
            "getAccount": "账号信息"
        }
    
    def _run_adb_command(self, command: List[str], timeout: int = 10) -> Optional[str]:
        try:
            full_command = [self.adb_path] + command
            proc = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                print(f"ADB命令超时，已终止: {' '.join(full_command)}")
                return None
            if proc.returncode != 0:
                print(f"ADB命令返回错误: {stderr.strip()}")
                return None
            return stdout.strip()
        except Exception as e:
            print(f"执行ADB命令异常: {e}")
            return None
    
    def check_device_connected(self) -> bool:
        """检查设备是否连接"""
        output = self._run_adb_command(["devices"])
        if output and "device" in output:
            # 提取设备ID
            lines = output.strip().split('\n')
            for line in lines[1:]:  # 跳过第一行标题
                if "device" in line:
                    self.device_id = line.split('\t')[0]
                    print(f"设备已连接: {self.device_id}")
                    return True
        else:
            print("设备未连接，请确保夜神模拟器已启动")
            return False
    
    def _check_device_with_retry(self) -> bool:
        print("开始检查设备连接...")
        # 先直接检查设备是否已连接
        if self.check_device_connected():
            print("设备已连接，无需重启ADB")
            return True

        # 如果未连接，再尝试重启ADB服务
        print("设备未连接，尝试重启ADB服务...")
        self._run_adb_command(["kill-server"])
        time.sleep(2)
        self._run_adb_command(["start-server"], timeout=30)  # 增加超时到30秒
        time.sleep(3)

        # 主动连接夜神模拟器端口（根据你的实际端口修改）
        simulator_port = "62026"  # 可从配置文件读取
        self._run_adb_command(["connect", f"127.0.0.1:{simulator_port}"])
        time.sleep(2)

        max_retries = 3
        for i in range(max_retries):
            print(f"尝试连接设备 ({i+1}/{max_retries})...")
            if self.check_device_connected():
                return True
            time.sleep(2)

        print("无法连接到设备，请确保夜神模拟器已启动并授权调试")
        return False
    
    def install_apk(self, timeout=120): # 增加超时时间
        print(f"正在安装 APK: {self.apk_path}")
        try:
            # 增加 -t 和 -g 参数 (允许测试版本和授予所有运行权限)
            cmd = [self.adb_path, 'install', '-r', '-t', '-g', self.apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0:
                print("安装成功")
                return True
            else:
                print(f"安装失败: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print(f"安装超时 (超过 {timeout} 秒)，请检查设备连接或 APK 大小")
            return False
    
    def _find_aapt(self):
        """查找 aapt 工具路径"""
        # 从环境变量 ANDROID_HOME 构建常见路径
        android_home = os.environ.get("ANDROID_HOME")
        if android_home:
            build_tools = os.path.join(android_home, "build-tools")
            if os.path.exists(build_tools):
                for version in sorted(os.listdir(build_tools), reverse=True):
                    aapt_path = os.path.join(build_tools, version, "aapt.exe")
                    if os.path.exists(aapt_path):
                        return aapt_path
        # 常见安装路径（可根据您的环境调整）
        common_paths = [
            r"E:\\Nox\\bin\\nox_aapt.exe",
            "aapt"  # 最后尝试环境变量
        ]
        for path in common_paths:
            if os.path.exists(path) or (path == "aapt" and self._check_command_exists("aapt")):
                return path
        return None

    def _check_command_exists(self, cmd):
        """检查命令是否存在"""
        try:
            subprocess.run([cmd, "--version"], capture_output=True, check=True, timeout=5)
            return True
        except:
            return False
    
    def _extract_package_name_from_apk(self):
        """从 APK 文件中提取包名"""
        aapt = self._find_aapt()
        if not aapt:
            print("警告: 未找到 aapt 工具，无法提取包名")
            return None
        try:
            result = subprocess.run(
                [aapt, "dump", "badging", self.apk_path],
                capture_output=True, text=True, timeout=10
            )
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                package = match.group(1)
                print(f"从 APK 提取到包名: {package}")
                return package
        except Exception as e:
            print(f"aapt 提取包名失败: {e}")
        return None
    
    def _get_package_name_from_device(self):
        """从设备上获取已安装应用的包名"""
        print("尝试从设备获取包名...")
        
        # 方法1：使用pm install命令的输出获取包名
        print("方法1: 尝试从pm install输出获取包名...")
        # 重新运行安装命令，捕获更详细的输出
        try:
            result = subprocess.run(
                [self.adb_path, "install", "-r", self.apk_path],
                capture_output=True, text=True, timeout=20
            )
            print(f"安装命令返回码: {result.returncode}")
            print(f"安装命令输出: {result.stdout}")
            print(f"安装命令错误: {result.stderr}")
            
            # 尝试从安装输出中提取包名
            if "Success" in result.stdout:
                # 安装成功，尝试使用pm path命令获取包名
                apk_filename = os.path.basename(self.apk_path)
                print(f"尝试使用pm path命令获取包名...")
                # 遍历所有包名，找到对应APK的包名
                packages_output = self._run_adb_command(["shell", "pm", "list", "packages", "-f"])
                if packages_output:
                    for line in packages_output.split('\n'):
                        if line and apk_filename in line:
                            # 匹配格式: package:/data/app/.../package.name-1/base.apk=package.name
                            match = re.search(r'=(.*)$', line)
                            if match:
                                package_name = match.group(1)
                                self.package_name = package_name
                                print(f"从pm path输出获取到包名: {package_name}")
                                # 更新Frida分析器的包名
                                if self.frida_analyzer:
                                    self.frida_analyzer.set_package_name(package_name)
                                return package_name
        except Exception as e:
            print(f"重新安装时出错: {e}")
        
        # 方法2：获取所有已安装的包名
        print("方法2: 尝试获取所有已安装的包名...")
        output = self._run_adb_command(["shell", "pm", "list", "packages"])
        if output:
            # 修复f-string语法错误
            lines = output.split('\n')
            print(f"获取到的包数量: {len(lines)}")
            # 打印前10个包名作为参考
            first_ten_lines = lines[:10]
            print("前10个包名:")
            for line in first_ten_lines:
                if line:
                    print(f"  {line}")
            
            # 获取APK文件名（不含扩展名）
            apk_filename = os.path.basename(self.apk_path).replace('.apk', '')
            print(f"APK文件名: {apk_filename}")
            
            # 遍历所有包名，尝试匹配
            for line in output.split('\n'):
                if line.startswith('package:'):
                    package_name = line.split(':')[1].strip()
                    # 直接检查包名是否包含APK文件名
                    if apk_filename.lower() in package_name.lower():
                        self.package_name = package_name
                        print(f"从设备获取到包名: {package_name}")
                        # 更新Frida分析器的包名
                        if self.frida_analyzer:
                            self.frida_analyzer.set_package_name(package_name)
                        return package_name
            
            # 方法3：尝试获取最近安装的应用
            print("方法3: 尝试获取最近安装的应用...")
            # 使用pm list packages -3获取第三方应用
            packages_output = self._run_adb_command(["shell", "pm", "list", "packages", "-3"])
            if packages_output:
                third_party_packages = [line.split(':')[1].strip() for line in packages_output.split('\n') if line.startswith('package:')]
                print(f"第三方应用数量: {len(third_party_packages)}")
                if third_party_packages:
                    # 打印所有第三方应用
                    print("第三方应用列表:")
                    for pkg in third_party_packages:
                        print(f"  {pkg}")
                    # 尝试找到与APK文件名相关的包名
                    for pkg in third_party_packages:
                        if apk_filename.lower() in pkg.lower():
                            self.package_name = pkg
                            print(f"获取到匹配的第三方应用包名: {self.package_name}")
                            # 更新Frida分析器的包名
                            if self.frida_analyzer:
                                self.frida_analyzer.set_package_name(self.package_name)
                            return self.package_name
                    # 如果没有匹配的，取最后一个第三方应用（假设是刚安装的）
                    if third_party_packages:
                        self.package_name = third_party_packages[-1]
                        print(f"获取到最近的第三方应用包名: {self.package_name}")
                        # 更新Frida分析器的包名
                        if self.frida_analyzer:
                            self.frida_analyzer.set_package_name(self.package_name)
                        return self.package_name
        
        print("无法从设备获取包名")
        return None


    def start_app(self) -> bool:
        # 如果包名未知，尝试从设备获取
        if not self.package_name:
            print("包名未知，尝试从设备获取...")
            self._get_package_name_from_device()
            if not self.package_name:
                print("无法获取包名，无法启动应用")
                return False

        print(f"启动应用: {self.package_name}")

        # 清空 logcat 缓存，以便后续只捕获本次启动的日志
        self._run_adb_command(["shell", "logcat", "-c"])

        # 尝试方法1：使用 monkey 启动（最通用）
        print("尝试使用 monkey 启动...")
        monkey_result = self._run_adb_command(["shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"])
        if monkey_result and "monkey" in monkey_result.lower():
            print("monkey 命令已执行，等待应用启动...")
            time.sleep(5)  # 增加等待时间
            # 检查进程是否存在
            if self._is_app_running():
                print("应用已成功启动 (通过 monkey)")
                return True
            else:
                print("monkey 启动后应用进程未出现，尝试其他方法")

        # 尝试方法2：直接启动主 Activity
        print("尝试通过主 Activity 启动...")
        main_activity = self._find_main_activity()
        if main_activity:
            print(f"找到主 Activity: {main_activity}")
            cmd = ["shell", "am", "start", "-n", f"{self.package_name}/{main_activity}"]
            result = self._run_adb_command(cmd)
            if result and ("Starting:" in result or "Error" not in result):
                print("am start 命令已执行")
                time.sleep(5)  # 增加等待时间
                if self._is_app_running():
                    print("应用已成功启动 (通过 am start)")
                    return True
            else:
                print(f"am start 失败，输出: {result}")

        # 尝试方法3：使用 monkey 仅带包名（旧方式）
        print("尝试使用简单 monkey 命令...")
        self._run_adb_command(["shell", "monkey", "-p", self.package_name, "1"])
        time.sleep(5)  # 增加等待时间
        if self._is_app_running():
            print("应用已成功启动 (简单 monkey)")
            return True

        # 尝试方法4：使用 am start 直接启动应用
        print("尝试使用 am start 直接启动...")
        result = self._run_adb_command(["shell", "am", "start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "-n", f"{self.package_name}/.MainActivity"])
        time.sleep(5)
        if self._is_app_running():
            print("应用已成功启动 (通过 am start 直接启动)")
            return True

        # 尝试方法5：使用 am start 不带具体 Activity
        print("尝试使用 am start 不带具体 Activity...")
        result = self._run_adb_command(["shell", "am", "start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "-p", self.package_name])
        time.sleep(5)
        if self._is_app_running():
            print("应用已成功启动 (通过 am start 不带具体 Activity)")
            return True

        # 所有方法都失败，输出 logcat 以便分析
        print("\n所有启动方法均失败，获取最近 20 行 logcat 日志:")
        logcat = self._run_adb_command(["shell", "logcat", "-d", "-t", "20"])
        if logcat:
            print(logcat)
        else:
            print("无法获取 logcat 日志")

        # 检查logcat中是否有应用启动的迹象
        if logcat:
            # 检查包名是否在日志中
            if self.package_name in logcat:
                print("从logcat中检测到应用启动迹象，认为启动成功")
                return True
            # 检查是否有应用启动相关的关键词
            start_keywords = ["ActivityManager: Displayed", "ActivityManager: Start proc", "ActivityManager: Launching"]
            for keyword in start_keywords:
                if keyword in logcat:
                    print(f"从logcat中检测到应用启动关键词 '{keyword}'，认为启动成功")
                    return True

        # 最后尝试：直接检查应用是否在运行（可能之前的检查时机不对）
        print("最后尝试：再次检查应用是否在运行...")
        if self._is_app_running():
            print("应用已成功启动（最后检查）")
            return True

        return False

    def _find_main_activity(self) -> Optional[str]:
        """从设备上已安装的包信息中查找主 Activity"""
        if not self.package_name:
            return None
        output = self._run_adb_command(["shell", "dumpsys", "package", self.package_name])
        if output:
            # 查找 MAIN 的 activity
            # 匹配类似:  android.intent.action.MAIN:
            #     3473f0a com.example/.MainActivity filter ...
            pattern = r'android\.intent\.action\.MAIN:\s*\n\s+([^\s]+)'
            match = re.search(pattern, output)
            if match:
                return match.group(1).split('/')[-1]  # 提取类名部分
            # 另一种匹配方式
            match = re.search(r'Activity Resolver Table.*?\n\s+([^\s]+) filter', output, re.DOTALL)
            if match:
                act = match.group(1)
                if act.startswith(self.package_name):
                    return act[len(self.package_name)+1:]  # 去掉包名和点
        return None

    def _is_app_running(self) -> bool:
        """检查应用进程是否正在运行"""
        # 方法1：使用ps命令检查进程
        output = self._run_adb_command(["shell", "ps"])
        if output:
            for line in output.split('\n'):
                # 检查包名是否在进程列表中
                if self.package_name in line:
                    # 提取PID
                    parts = line.split()
                    if len(parts) >= 2:
                        self.app_pid = parts[1]
                        print(f"应用正在运行，PID: {self.app_pid}")
                    return True
        
        # 方法2：使用ps命令的grep功能（更可靠）
        output = self._run_adb_command(["shell", "ps", "|", "grep", self.package_name])
        if output and self.package_name in output:
            print(f"应用正在运行（通过grep）")
            return True
        
        # 方法3：检查logcat中是否有应用启动成功的信息
        logcat = self._run_adb_command(["shell", "logcat", "-d", "-t", "10"])
        if logcat and f"Displayed {self.package_name}/" in logcat:
            print(f"应用已启动成功（通过logcat）")
            return True
        
        return False
    
    def simulate_user_interactions(self) -> bool:
        """模拟用户交互"""
        print("开始模拟用户交互")
        
        # 模拟点击操作
        interactions = [
            # 点击屏幕中央
            ["shell", "input", "tap", "500", "500"],
            # 等待2秒
            None,
            # 滑动操作
            ["shell", "input", "swipe", "500", "800", "500", "300", "500"],
            # 等待2秒
            None,
            # 再次点击
            ["shell", "input", "tap", "500", "500"],
            # 等待2秒
            None
        ]
        
        for action in interactions:
            if action:
                self._run_adb_command(action)
            else:
                time.sleep(2)
        
        print("用户交互模拟完成")
        return True
    
    def monitor_sensitive_api_calls(self, duration: int = 60) -> Dict:
        """监控敏感API调用"""
        print(f"开始监控敏感API调用，持续 {duration} 秒")
        
        # 清空之前的日志
        self._run_adb_command(["logcat", "-c"])
        
        # 启动日志监控
        process = subprocess.Popen(
            [self.adb_path, "logcat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        start_time = time.time()
        detected_apis = {}
        
        # 增强的敏感API模式
        sensitive_patterns = {
            "getDeviceId": ["getDeviceId", "DEVICE_ID", "imei", "MEID"],
            "getSubscriberId": ["getSubscriberId", "IMSI"],
            "getMacAddress": ["getMacAddress", "MAC_ADDR"],
            "getLocation": ["getLastKnownLocation", "requestLocationUpdates", "LocationManager"],
            "openCamera": ["Camera.open", "CameraManager"],
            "startRecording": ["MediaRecorder", "recordAudio"],
            "readContacts": ["ContactsContract", "getContacts"],
            "readSms": ["SmsManager", "readSms"],
            "accessStorage": ["openFileOutput", "openFileInput", "Environment.getExternalStorage"],
            "getInstalledPackages": ["getInstalledPackages", "queryIntentActivities"],
            "getAccount": ["AccountManager", "getAccounts"]
        }
        
        try:
            # 使用tqdm显示监控进度
            with tqdm(total=duration, desc="监控敏感API调用", unit="秒") as pbar:
                while time.time() - start_time < duration:
                    line = process.stdout.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    # 检查敏感API调用
                    for api, patterns in sensitive_patterns.items():
                        for pattern in patterns:
                            if pattern.lower() in line.lower():
                                if api not in detected_apis:
                                    detected_apis[api] = {
                                        "description": self.sensitive_apis.get(api, api),
                                        "count": 0,
                                        "logs": []
                                    }
                                detected_apis[api]["count"] += 1
                                detected_apis[api]["logs"].append(line.strip())
                                self.monitoring_logs.append(line.strip())
                                
                                print(f"检测到敏感API调用: {self.sensitive_apis.get(api, api)}")
                    
                    # 更新进度条
                    elapsed = time.time() - start_time
                    pbar.update(min(1, duration - elapsed))
                    time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        print("敏感API调用监控完成")
        return detected_apis
    
    def get_network_traffic(self) -> List[str]:
        """获取网络流量信息"""
        print("获取网络流量信息")
        
        # 使用netstat命令获取网络连接
        output = self._run_adb_command(["shell", "netstat", "-tunap"])
        
        if output:
            # 过滤出与应用相关的连接
            connections = []
            for line in output.split('\n'):
                if self.package_name and self.package_name in line:
                    connections.append(line.strip())
            return connections
        return []
    
    def get_battery_usage(self) -> Optional[str]:
        """获取电池使用情况"""
        print("获取电池使用情况")
        
        output = self._run_adb_command(["shell", "dumpsys", "battery"])
        return output
    
    def get_memory_usage(self) -> Optional[str]:
        """获取内存使用情况"""
        print("获取内存使用情况")
        
        if self.package_name:
            output = self._run_adb_command(["shell", "dumpsys", "meminfo", self.package_name])
            return output
        return None
    
    def get_cpu_usage(self) -> Optional[str]:
        """获取CPU使用情况"""
        print("获取CPU使用情况")
        
        if self.app_pid:
            output = self._run_adb_command(["shell", "top", "-n", "1", "-p", self.app_pid])
            return output
        return None
    
    def get_app_info(self) -> Optional[Dict]:
        """获取应用信息"""
        print("获取应用信息")
        
        if not self.package_name:
            return None
        
        app_info = {}
        
        # 获取应用基本信息
        package_info = self._run_adb_command(["shell", "dumpsys", "package", self.package_name])
        if package_info:
            app_info["package_info"] = package_info
        
        # 获取应用签名信息
        signature_info = self._run_adb_command(["shell", "dumpsys", "package", "--check-signatures", self.package_name])
        if signature_info:
            app_info["signature_info"] = signature_info
        
        return app_info
    
    def get_app_permissions(self) -> Optional[List[str]]:
        """获取应用已授予的权限"""
        print("获取应用已授予的权限")
        
        if not self.package_name:
            return None
        
        output = self._run_adb_command(["shell", "pm", "list", "permissions", "-d", "-g"])
        if output:
            permissions = []
            for line in output.split('\n'):
                if self.package_name in line:
                    permissions.append(line.strip())
            return permissions
        return None
    
    def _perform_frida_analysis(self) -> Dict:
        """执行Frida动态行为分析"""
        print("开始Frida动态行为监控...")
        
        if not self.package_name:
            return {"error": "包名未知，无法执行Frida分析"}
        
        if not self.frida_analyzer:
            return {"error": "Frida 模块未安装，跳过 Frida 分析"}
        
        try:
            # 即使 _is_app_running() 返回 False，也不要直接退出
            # 因为在 Nox 模拟器上，某些进程检查方法可能不准
            if not self._is_app_running():
                print("应用未运行，尝试启动应用...")
                self.start_app() # 尝试启动
                time.sleep(3) # 等待缓冲
            
            # 调用 frida_analyzer 的执行方法
            # 注意：这里我们让 frida_analyzer 内部处理进程是否存在的问题
            frida_results = self.frida_analyzer.perform_frida_analysis(duration=30)
            
            frida_summary = self.frida_analyzer.get_frida_summary()
            return {
                "results": frida_results,
                "summary": frida_summary
            }
        except Exception as e:
            print(f"执行Frida分析时出错: {e}")
            return {"error": str(e)}
    
    def perform_dynamic_analysis(self) -> Dict:
        """执行完整的动态分析"""
        print("=" * 60)
        print("开始动态分析")
        print("=" * 60)
        
        analysis_result = {
            "device_connected": False,
            "apk_installed": False,
            "app_started": False,
            "user_interactions": False,
            "sensitive_api_calls": {},
            "network_traffic": [],
            "battery_usage": None,
            "memory_usage": None,
            "cpu_usage": None,
            "app_info": None,
            "app_permissions": None,
            "errors": []
        }
        
        # 定义分析步骤
        steps = [
            ("检查设备连接", self._check_device_with_retry),
            ("安装APK", self.install_apk),
            ("启动应用", self.start_app),
            ("模拟用户交互", self.simulate_user_interactions),
            ("监控敏感API调用", lambda: self.monitor_sensitive_api_calls()),
            ("Frida动态行为监控", self._perform_frida_analysis),
            ("获取网络流量", self.get_network_traffic),
            ("获取电池使用情况", self.get_battery_usage),
            ("获取内存使用情况", self.get_memory_usage),
            ("获取CPU使用情况", self.get_cpu_usage),
            ("获取应用信息", self.get_app_info),
            ("获取应用权限", self.get_app_permissions)
        ]
        
        # 执行分析步骤
        for step_name, step_func in tqdm(steps, desc="动态分析进度", unit="步骤"):
            try:
                if step_name == "检查设备连接":
                    if not step_func():
                        analysis_result["errors"].append("设备未连接")
                        break
                    analysis_result["device_connected"] = True
                elif step_name == "安装APK":
                    if not step_func():
                        analysis_result["errors"].append("APK安装失败")
                        break
                    analysis_result["apk_installed"] = True
                elif step_name == "启动应用":
                    if not step_func():
                        analysis_result["errors"].append("应用启动失败")
                        break
                    analysis_result["app_started"] = True
                elif step_name == "模拟用户交互":
                    if not step_func():
                        analysis_result["errors"].append("用户交互模拟失败")
                    analysis_result["user_interactions"] = True
                elif step_name == "监控敏感API调用":
                    analysis_result["sensitive_api_calls"] = step_func()
                elif step_name == "Frida动态行为监控":
                    analysis_result["frida_analysis"] = step_func()
                elif step_name == "获取网络流量":
                    analysis_result["network_traffic"] = step_func()
                elif step_name == "获取电池使用情况":
                    analysis_result["battery_usage"] = step_func()
                elif step_name == "获取内存使用情况":
                    analysis_result["memory_usage"] = step_func()
                elif step_name == "获取CPU使用情况":
                    analysis_result["cpu_usage"] = step_func()
                elif step_name == "获取应用信息":
                    analysis_result["app_info"] = step_func()
                elif step_name == "获取应用权限":
                    analysis_result["app_permissions"] = step_func()
            except Exception as e:
                print(f"执行{step_name}时出错: {e}")
                analysis_result["errors"].append(f"{step_name}失败: {str(e)}")
                continue
        
        print("=" * 60)
        print("动态分析完成")
        print("=" * 60)
        
        return analysis_result
    
    def save_result(self, output_file: str):
        """保存分析结果"""
        result = self.perform_dynamic_analysis()
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"动态分析结果已保存到: {output_file}")
        return result


class DynamicBatchAnalyzer:
    def __init__(self, samples_dir: str, results_dir: str = "results"):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
    
    def analyze_all(self) -> List[Dict]:
        """批量分析所有APK文件"""
        results = []
        apk_files = [f for f in os.listdir(self.samples_dir) if f.endswith('.apk')]
        
        print(f"找到 {len(apk_files)} 个APK文件")
        
        for apk_file in apk_files:
            apk_path = os.path.join(self.samples_dir, apk_file)
            print(f"\n分析: {apk_file}")
            
            analyzer = DynamicAnalyzer(apk_path)
            result_file = os.path.join(self.results_dir, f"{apk_file}_dynamic_analysis.json")
            
            try:
                result = analyzer.save_result(result_file)
                result['apk_file'] = apk_file
                results.append(result)
            except Exception as e:
                print(f"分析失败: {e}")
                import traceback
                traceback.print_exc()
        
        self.save_summary(results)
        return results
    
    def save_summary(self, results: List[Dict]):
        """保存批量分析摘要"""
        summary = {
            'total_analyzed': len(results),
            'successfully_analyzed': sum(1 for r in results if r['app_started']),
            'results': results
        }
        
        summary_file = os.path.join(self.results_dir, 'dynamic_analysis_summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"\n批量动态分析摘要已保存到: {summary_file}")

if __name__ == "__main__":
    samples_dir = "../samples"
    results_dir = "../results"
    
    batch_analyzer = DynamicBatchAnalyzer(samples_dir, results_dir)
    results = batch_analyzer.analyze_all()
    
    print(f"\n动态分析完成！共分析 {len(results)} 个APK文件")