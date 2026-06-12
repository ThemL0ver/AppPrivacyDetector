# ============================================================
# 动态分析模块 - 基于Android模拟器的API调用监控
# ============================================================
# 功能概述：
#   本模块通过在Android模拟器中安装并运行目标APK，实时监控应用的
#   行为活动变化，从而检测应用在运行时触发了哪些敏感API调用。
#   整体架构分为三层：
#     1. AndroidEmulatorManager - 模拟器管理（ADB通信）
#     2. APIHookMonitor        - API行为监控与用户操作模拟
#     3. DynamicAnalyzer        - 动态分析流程编排
# ============================================================

import subprocess
import time
import json
import os
import re
from typing import Dict, List, Optional
from datetime import datetime

class AndroidEmulatorManager:
    """
    Android模拟器管理器
    
    通过ADB（Android Debug Bridge）与模拟器或真机进行通信，
    提供设备检测、APK安装/卸载、应用启动等基础操作。
    是所有动态分析操作的底层支撑模块。
    """
    
    def __init__(self):
        """
        初始化模拟器管理器
        
        设置ADB路径和设备标识符的初始值。
        emulator_id为None表示尚未检测到可用设备。
        """
        # 当前连接的设备序列号，通过check_device()方法自动获取
        self.emulator_id = None
        # ADB可执行文件路径，默认使用系统PATH中的adb
        self.adb_path = "adb"
    
    def check_device(self) -> bool:
        """
        检测并连接可用的Android设备
        
        通过adb devices命令列出所有已连接设备，自动选择第一个
        在线设备作为操作目标。设备标识符会保存在self.emulator_id中。
        
        Returns:
            bool: 如果检测到至少一台在线设备返回True，否则返回False
        """
        try:
            # 执行 adb devices 命令获取设备列表
            result = subprocess.run([self.adb_path, 'devices'], 
                                  capture_output=True, text=True)
            # 按行分割输出结果
            lines = result.stdout.split('\n')
            # 从第二行开始解析（第一行是标题"List of devices attached"）
            # 筛选状态为"device"的行，提取设备序列号
            devices = [line.split()[0] for line in lines[1:] 
                      if line.strip() and 'device' in line]
            if devices:
                # 取第一个在线设备作为操作目标
                self.emulator_id = devices[0]
                print(f"检测到设备: {self.emulator_id}")
                return True
            return False
        except Exception as e:
            print(f"检查设备失败: {e}")
            return False
    
    def install_apk(self, apk_path: str) -> bool:
        """
        安装APK到目标设备
        
        使用adb install -r命令安装APK文件，-r参数表示
        如果应用已存在则覆盖安装（保留数据）。
        
        Args:
            apk_path: APK文件的本地路径
        
        Returns:
            bool: 安装成功返回True，否则返回False
        """
        # 前置检查：确保已有设备连接
        if not self.emulator_id:
            print("未检测到设备")
            return False
        
        try:
            print(f"安装APK: {apk_path}")
            # 执行 adb install -r 命令进行覆盖安装
            result = subprocess.run([self.adb_path, '-s', self.emulator_id, 
                                    'install', '-r', apk_path],
                                   capture_output=True, text=True)
            # 判断输出中是否包含"Success"字样
            if 'Success' in result.stdout:
                print("APK安装成功")
                return True
            print(f"APK安装失败: {result.stdout}")
            return False
        except Exception as e:
            print(f"安装APK失败: {e}")
            return False
    
    def launch_app(self, package_name: str, activity_name: str) -> bool:
        """
        启动目标应用
        
        通过adb shell am start命令启动指定的Activity。
        需要同时提供包名和Activity名以构造完整的组件名称。
        
        Args:
            package_name: 应用的包名，如 "com.example.app"
            activity_name: 启动的Activity名，如 ".MainActivity"
        
        Returns:
            bool: 启动成功返回True，否则返回False
        """
        # 前置检查：确保已有设备连接
        if not self.emulator_id:
            return False
        
        try:
            # 构造完整的组件名称：包名/Activity名
            component = f"{package_name}/{activity_name}"
            # 通过 am start -n 命令启动指定的Activity
            result = subprocess.run([self.adb_path, '-s', self.emulator_id,
                                    'shell', 'am', 'start', '-n', component],
                                   capture_output=True, text=True)
            print(f"启动应用: {component}")
            return True
        except Exception as e:
            print(f"启动应用失败: {e}")
            return False
    
    def uninstall_app(self, package_name: str) -> bool:
        """
        卸载目标应用
        
        使用adb uninstall命令根据包名卸载应用。
        在动态分析结束后调用，用于清理测试环境。
        
        Args:
            package_name: 要卸载的应用包名
        
        Returns:
            bool: 卸载成功返回True，否则返回False
        """
        # 前置检查：确保已有设备连接
        if not self.emulator_id:
            return False
        
        try:
            # 执行 adb uninstall 命令卸载应用
            subprocess.run([self.adb_path, '-s', self.emulator_id,
                          'uninstall', package_name],
                         capture_output=True, text=True)
            print(f"卸载应用: {package_name}")
            return True
        except Exception as e:
            print(f"卸载应用失败: {e}")
            return False

class APIHookMonitor:
    """
    API行为监控器
    
    负责监控目标应用在运行时的行为变化，包括：
    1. 通过logcat采集应用运行日志
    2. 通过dumpsys周期性获取当前Activity切换信息
    3. 模拟用户操作以触发更多应用行为
    
    内置了需要重点监控的隐私敏感API列表（monitored_apis），
    涵盖电话、位置、摄像头、麦克风、网络等权限相关接口。
    """
    
    def __init__(self, emulator_manager: AndroidEmulatorManager):
        """
        初始化API监控器
        
        Args:
            emulator_manager: AndroidEmulatorManager实例，用于ADB通信
        """
        # 持有模拟器管理器的引用，用于执行ADB命令
        self.emulator = emulator_manager
        # 需要监控的隐私敏感API清单
        # key为Android系统类名，value为该类中需要监控的方法列表
        self.monitored_apis = {
            # 电话管理器 - 可获取设备IMEI、SIM卡序列号等唯一标识
            'android.telephony.TelephonyManager': [
                'getDeviceId',        # 获取设备IMEI/MEID
                'getSimSerialNumber', # 获取SIM卡序列号
                'getLine1Number',     # 获取手机号码
                'getSubscriberId'     # 获取IMSI
            ],
            # 位置管理器 - 可获取用户地理位置
            'android.location.LocationManager': [
                'requestLocationUpdates',  # 请求位置更新
                'getLastKnownLocation'     # 获取最后已知位置
            ],
            # 内容提供器 - 可读取/写入系统数据（通讯录、短信等）
            'android.content.ContentResolver': [
                'query',   # 查询数据
                'insert',  # 插入数据
                'update',  # 更新数据
                'delete'   # 删除数据
            ],
            # 摄像头 - 可调用相机硬件
            'android.hardware.Camera': [
                'open',       # 打开摄像头
                'takePicture' # 拍照
            ],
            # 音频录制 - 可录制麦克风音频
            'android.media.AudioRecord': [
                'startRecording', # 开始录音
                'read'            # 读取音频数据
            ],
            # 网络连接管理器 - 可获取网络状态信息
            'android.net.ConnectivityManager': [
                'getNetworkInfo',       # 获取网络信息
                'getActiveNetworkInfo'  # 获取当前活动网络信息
            ]
        }
        # 存储监控过程中捕获到的所有API调用记录
        self.api_calls = []
    
    def start_logcat_monitor(self, package_name: str) -> bool:
        """
        启动logcat日志监控进程
        
        通过adb logcat命令实时采集Android系统日志，过滤出
        ActivityManager、System.out和DEBUG级别的日志，
        用于后续分析应用行为。
        
        Args:
            package_name: 目标应用的包名（当前版本中用于日志标识）
        
        Returns:
            bool: 启动成功返回True，否则返回False
        """
        # 前置检查：确保已有设备连接
        if not self.emulator.emulator_id:
            return False
        
        try:
            print(f"开始监控应用: {package_name}")
            # 构造logcat命令：
            #   -v time: 输出带时间戳格式
            #   *:S: 默认静默所有tag
            #   ActivityManager:I / System.out:I / DEBUG:I: 只显示指定tag的Info及以上级别日志
            logcat_cmd = [self.emulator.adb_path, '-s', self.emulator.emulator_id,
                         'logcat', '-v', 'time', '*:S', 'ActivityManager:I', 
                         'System.out:I', 'DEBUG:I']
            
            # 使用Popen异步启动logcat进程，持续采集日志
            self.logcat_process = subprocess.Popen(logcat_cmd, 
                                                   stdout=subprocess.PIPE, 
                                                   stderr=subprocess.PIPE,
                                                   text=True)
            return True
        except Exception as e:
            print(f"启动logcat监控失败: {e}")
            return False
    
    def stop_logcat_monitor(self):
        """
        停止logcat日志监控进程
        
        终止之前通过start_logcat_monitor启动的后台logcat子进程，
        释放系统资源。通常在动态分析结束时调用。
        """
        # 检查logcat进程是否存在，存在则终止
        if hasattr(self, 'logcat_process'):
            self.logcat_process.terminate()
            print("停止logcat监控")
    
    def monitor_api_calls(self, duration: int = 60) -> List[Dict]:
        """
        在指定时间内持续监控应用行为
        
        每秒通过dumpsys activity top获取当前前台Activity，
        记录Activity切换事件。这是一种轻量级的行为追踪方式，
        通过Activity变化可以推断应用的功能调用路径。
        
        Args:
            duration: 监控持续时间，单位秒，默认60秒
        
        Returns:
            List[Dict]: API调用记录列表，每条记录包含：
                - timestamp: 调用时间戳
                - activity: 当前Activity名
                - type: 事件类型（固定为'activity_change'）
        """
        # 记录监控开始时间
        start_time = time.time()
        # 初始化本次监控的调用记录列表
        api_calls = []
        
        print(f"开始监控API调用，持续时间: {duration}秒")
        
        # 循环采集，直到达到指定时长
        while time.time() - start_time < duration:
            # 每秒采集一次，避免过度轮询
            time.sleep(1)
            
            try:
                # 执行 dumpsys activity top 获取当前顶层Activity信息
                result = subprocess.run([self.emulator.adb_path, '-s', 
                                       self.emulator.emulator_id,
                                       'shell', 'dumpsys', 'activity', 'top'],
                                      capture_output=True, text=True)
                
                # 从dumpsys输出中提取当前Activity名称
                current_activity = self._extract_current_activity(result.stdout)
                
                # 当成功提取到Activity信息时，记录一条调用事件
                if current_activity:
                    api_call = {
                        'timestamp': datetime.now().isoformat(),
                        'activity': current_activity,
                        'type': 'activity_change'
                    }
                    api_calls.append(api_call)
                    
            except Exception as e:
                # 单次采集失败不影响后续监控，跳过继续
                continue
        
        # 将采集结果保存到实例变量中
        self.api_calls = api_calls
        return api_calls
    
    def _extract_current_activity(self, dumpsys_output: str) -> Optional[str]:
        """
        从dumpsys activity top输出中提取当前Activity名称
        
        通过正则表达式匹配mFocusedActivity字段，该字段标识了
        当前获得焦点的（即用户可见的）Activity。
        
        Args:
            dumpsys_output: dumpsys activity top命令的原始输出
        
        Returns:
            Optional[str]: 提取到的Activity名称（不含包名前缀），
                          如果未匹配到则返回None
        """
        # 正则匹配 mFocusedActivity 行
        # 示例输出: mFocusedActivity: ActivityRecord{abc123 u0 com.example/.MainActivity t42}
        # 提取花括号内的最后一个空格分隔的部分（即完整组件名）
        pattern = r'mFocusedActivity: ActivityRecord\{[^}]+ ([^}]+)\}'
        match = re.search(pattern, dumpsys_output)
        if match:
            # 取组件名中'/'后面的部分作为Activity名
            return match.group(1).split('/')[-1]
        return None
    
    def simulate_user_actions(self, package_name: str) -> bool:
        """
        模拟用户操作以触发更多应用行为
        
        通过adb shell input命令在模拟器上执行一系列预定义操作：
        包括点击（tap）、滑动（swipe）和按键（keyevent）。
        目的是模拟真实用户使用场景，触发应用中更多的代码执行路径，
        从而捕获更全面的API调用行为。
        
        Args:
            package_name: 目标应用包名（当前版本中预留参数）
        
        Returns:
            bool: 模拟操作完成返回True
        """
        # 前置检查：确保已有设备连接
        if not self.emulator.emulator_id:
            return False
        
        # 预定义的用户操作序列
        # 每个元组第一个元素为操作类型，后续为参数
        actions = [
            ('tap', 500, 800),                    # 点击坐标(500, 800)
            ('tap', 500, 1000),                   # 点击坐标(500, 1000)
            ('swipe', 500, 1000, 500, 500),       # 从(500,1000)滑动到(500,500)
            ('key', 'KEYCODE_BACK'),               # 按下返回键
            ('tap', 500, 600)                     # 点击坐标(500, 600)
        ]
        
        for action in actions:
            try:
                # 根据操作类型执行对应的ADB命令
                if action[0] == 'tap':
                    # 模拟点击：adb shell input tap x y
                    subprocess.run([self.emulator.adb_path, '-s', 
                                   self.emulator.emulator_id,
                                   'shell', 'input', 'tap', 
                                   str(action[1]), str(action[2])],
                                  capture_output=True)
                elif action[0] == 'swipe':
                    # 模拟滑动：adb shell input swipe x1 y1 x2 y2
                    subprocess.run([self.emulator.adb_path, '-s', 
                                   self.emulator.emulator_id,
                                   'shell', 'input', 'swipe',
                                   str(action[1]), str(action[2]),
                                   str(action[3]), str(action[4])],
                                  capture_output=True)
                elif action[0] == 'key':
                    # 模拟按键：adb shell input keyevent KEYCODE
                    subprocess.run([self.emulator.adb_path, '-s', 
                                   self.emulator.emulator_id,
                                   'shell', 'input', 'keyevent', action[1]],
                                  capture_output=True)
                
                # 每个操作之间等待2秒，模拟真实操作间隔
                time.sleep(2)
                
            except Exception as e:
                print(f"执行操作失败: {e}")
                # 单个操作失败不影响后续操作，继续执行
                continue
        
        print("用户操作模拟完成")
        return True
    
    def get_monitoring_result(self) -> Dict:
        """
        获取监控结果汇总
        
        将本次监控过程中采集的所有数据打包成一个结构化字典，
        便于后续分析和持久化存储。
        
        Returns:
            Dict: 监控结果字典，包含：
                - total_api_calls: 捕获的API调用总数
                - api_calls: 详细的API调用记录列表
                - monitored_apis: 本次监控覆盖的API清单
                - timestamp: 结果生成时间戳
        """
        return {
            'total_api_calls': len(self.api_calls),
            'api_calls': self.api_calls,
            'monitored_apis': self.monitored_apis,
            'timestamp': datetime.now().isoformat()
        }

class DynamicAnalyzer:
    """
    动态分析器（编排层）
    
    作为动态分析流程的总控制器，协调AndroidEmulatorManager和
    APIHookMonitor两个模块协同工作。负责执行完整的分析流程：
    
    1. 检测设备  →  2. 安装APK  →  3. 启动应用
    →  4. 启动日志监控  →  5. 模拟用户操作
    →  6. 监控API调用  →  7. 停止监控  →  8. 清理卸载
    
    支持批量分析多个APK并统一保存结果。
    """
    
    def __init__(self):
        """
        初始化动态分析器
        
        创建模拟器管理器和API监控器实例，准备分析环境。
        results列表用于存储多次分析的结果。
        """
        # 创建模拟器管理器，负责设备通信
        self.emulator_manager = AndroidEmulatorManager()
        # 创建API监控器，传入模拟器管理器引用
        self.api_monitor = APIHookMonitor(self.emulator_manager)
        # 分析结果列表，支持多次分析结果的累积存储
        self.results = []
    
    def analyze_apk(self, apk_path: str, package_name: str, 
                   activity_name: str, monitor_duration: int = 60) -> Dict:
        """
        对单个APK执行完整的动态分析流程
        
        按照固定的八个步骤依次执行，每步之间设置适当延时
        以确保操作生效。任一步骤失败都会立即终止并返回错误信息。
        
        Args:
            apk_path: APK文件的本地路径
            package_name: 目标应用的包名
            activity_name: 启动入口Activity名
            monitor_duration: API监控持续时间（秒），默认60秒
        
        Returns:
            Dict: 分析结果字典，成功时包含：
                - apk_file: APK文件名
                - package_name: 应用包名
                - activity_name: 启动Activity
                - monitoring_result: API监控结果详情
                - analysis_timestamp: 分析时间戳
                失败时包含：
                - error: 错误描述信息
        """
        print(f"\n开始动态分析: {apk_path}")
        
        # 步骤1: 检测设备连接状态
        if not self.emulator_manager.check_device():
            return {'error': '未检测到设备'}
        
        # 步骤2: 安装APK到设备
        if not self.emulator_manager.install_apk(apk_path):
            return {'error': 'APK安装失败'}
        
        # 等待3秒，确保安装操作完成
        time.sleep(3)
        
        # 步骤3: 启动应用
        if not self.emulator_manager.launch_app(package_name, activity_name):
            return {'error': '应用启动失败'}
        
        # 等待2秒，确保应用完全启动
        time.sleep(2)
        
        # 步骤4: 启动logcat日志监控（后台运行）
        self.api_monitor.start_logcat_monitor(package_name)
        
        # 步骤5: 模拟用户操作，触发应用行为
        self.api_monitor.simulate_user_actions(package_name)
        
        # 步骤6: 在指定时长内监控API调用
        api_calls = self.api_monitor.monitor_api_calls(monitor_duration)
        
        # 步骤7: 停止logcat日志监控
        self.api_monitor.stop_logcat_monitor()
        
        # 等待2秒，确保监控进程完全终止
        time.sleep(2)
        
        # 步骤8: 卸载应用，清理测试环境
        self.emulator_manager.uninstall_app(package_name)
        
        # 组装完整的分析结果
        result = {
            'apk_file': os.path.basename(apk_path),
            'package_name': package_name,
            'activity_name': activity_name,
            'monitoring_result': self.api_monitor.get_monitoring_result(),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # 将结果追加到结果列表中
        self.results.append(result)
        return result
    
    def save_results(self, output_dir: str):
        """
        将所有分析结果保存为JSON文件
        
        为每次分析生成独立的JSON文件（命名格式：dynamic_analysis_{序号}.json），
        同时生成一个汇总文件（dynamic_analysis_summary.json），
        包含所有分析结果的索引信息。
        
        使用ensure_ascii=False确保中文内容正常显示，
        indent=2提供良好的可读性。
        
        Args:
            output_dir: 结果输出目录路径，如果不存在则自动创建
        """
        # 自动创建输出目录（如果不存在）
        os.makedirs(output_dir, exist_ok=True)
        
        # 为每次分析结果生成独立的JSON文件
        for i, result in enumerate(self.results):
            output_file = os.path.join(output_dir, 
                                      f"dynamic_analysis_{i}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                # ensure_ascii=False 保留中文字符
                # indent=2 美化JSON格式输出
                json.dump(result, f, ensure_ascii=False, indent=2)
        
        # 生成汇总文件，包含所有分析结果的概览
        summary_file = os.path.join(output_dir, 'dynamic_analysis_summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump({
                'total_analyzed': len(self.results),
                'results': self.results
            }, f, ensure_ascii=False, indent=2)
        
        print(f"动态分析结果已保存到: {output_dir}")

# ============================================================
# 主程序入口
# ============================================================
# 演示完整的动态分析流程：
#   1. 创建DynamicAnalyzer实例
#   2. 加载samples目录下的Uu.apk
#   3. 执行30秒的动态监控
#   4. 将结果保存到results目录
# ============================================================
if __name__ == "__main__":
    # 实例化动态分析器
    analyzer = DynamicAnalyzer()
    
    # 执行动态分析：指定APK路径、包名、入口Activity和监控时长
    result = analyzer.analyze_apk(
        apk_path="../samples/Uu.apk",
        package_name="com.example.app",
        activity_name=".MainActivity",
        monitor_duration=30
    )
    
    # 将分析结果保存为JSON文件
    analyzer.save_results("../results")
