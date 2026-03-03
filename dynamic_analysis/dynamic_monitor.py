#动态分析模块 - 基于模拟器的API调用监控
import subprocess
import time
import json
import os
import re
from typing import Dict, List, Optional
from datetime import datetime

class AndroidEmulatorManager:
    def __init__(self):
        self.emulator_id = None
        self.adb_path = "adb"
    
    def check_device(self) -> bool:
        try:
            result = subprocess.run([self.adb_path, 'devices'], 
                                  capture_output=True, text=True)
            lines = result.stdout.split('\n')
            devices = [line.split()[0] for line in lines[1:] 
                      if line.strip() and 'device' in line]
            if devices:
                self.emulator_id = devices[0]
                print(f"检测到设备: {self.emulator_id}")
                return True
            return False
        except Exception as e:
            print(f"检查设备失败: {e}")
            return False
    
    def install_apk(self, apk_path: str) -> bool:
        if not self.emulator_id:
            print("未检测到设备")
            return False
        
        try:
            print(f"安装APK: {apk_path}")
            result = subprocess.run([self.adb_path, '-s', self.emulator_id, 
                                    'install', '-r', apk_path],
                                   capture_output=True, text=True)
            if 'Success' in result.stdout:
                print("APK安装成功")
                return True
            print(f"APK安装失败: {result.stdout}")
            return False
        except Exception as e:
            print(f"安装APK失败: {e}")
            return False
    
    def launch_app(self, package_name: str, activity_name: str) -> bool:
        if not self.emulator_id:
            return False
        
        try:
            component = f"{package_name}/{activity_name}"
            result = subprocess.run([self.adb_path, '-s', self.emulator_id,
                                    'shell', 'am', 'start', '-n', component],
                                   capture_output=True, text=True)
            print(f"启动应用: {component}")
            return True
        except Exception as e:
            print(f"启动应用失败: {e}")
            return False
    
    def uninstall_app(self, package_name: str) -> bool:
        if not self.emulator_id:
            return False
        
        try:
            subprocess.run([self.adb_path, '-s', self.emulator_id,
                          'uninstall', package_name],
                         capture_output=True, text=True)
            print(f"卸载应用: {package_name}")
            return True
        except Exception as e:
            print(f"卸载应用失败: {e}")
            return False

class APIHookMonitor:
    def __init__(self, emulator_manager: AndroidEmulatorManager):
        self.emulator = emulator_manager
        self.monitored_apis = {
            'android.telephony.TelephonyManager': [
                'getDeviceId',
                'getSimSerialNumber',
                'getLine1Number',
                'getSubscriberId'
            ],
            'android.location.LocationManager': [
                'requestLocationUpdates',
                'getLastKnownLocation'
            ],
            'android.content.ContentResolver': [
                'query',
                'insert',
                'update',
                'delete'
            ],
            'android.hardware.Camera': [
                'open',
                'takePicture'
            ],
            'android.media.AudioRecord': [
                'startRecording',
                'read'
            ],
            'android.net.ConnectivityManager': [
                'getNetworkInfo',
                'getActiveNetworkInfo'
            ]
        }
        self.api_calls = []
    
    def start_logcat_monitor(self, package_name: str) -> bool:
        if not self.emulator.emulator_id:
            return False
        
        try:
            print(f"开始监控应用: {package_name}")
            logcat_cmd = [self.emulator.adb_path, '-s', self.emulator.emulator_id,
                         'logcat', '-v', 'time', '*:S', 'ActivityManager:I', 
                         'System.out:I', 'DEBUG:I']
            
            self.logcat_process = subprocess.Popen(logcat_cmd, 
                                                   stdout=subprocess.PIPE, 
                                                   stderr=subprocess.PIPE,
                                                   text=True)
            return True
        except Exception as e:
            print(f"启动logcat监控失败: {e}")
            return False
    
    def stop_logcat_monitor(self):
        if hasattr(self, 'logcat_process'):
            self.logcat_process.terminate()
            print("停止logcat监控")
    
    def monitor_api_calls(self, duration: int = 60) -> List[Dict]:
        start_time = time.time()
        api_calls = []
        
        print(f"开始监控API调用，持续时间: {duration}秒")
        
        while time.time() - start_time < duration:
            time.sleep(1)
            
            try:
                result = subprocess.run([self.emulator.adb_path, '-s', 
                                       self.emulator.emulator_id,
                                       'shell', 'dumpsys', 'activity', 'top'],
                                      capture_output=True, text=True)
                
                current_activity = self._extract_current_activity(result.stdout)
                
                if current_activity:
                    api_call = {
                        'timestamp': datetime.now().isoformat(),
                        'activity': current_activity,
                        'type': 'activity_change'
                    }
                    api_calls.append(api_call)
                    
            except Exception as e:
                continue
        
        self.api_calls = api_calls
        return api_calls
    
    def _extract_current_activity(self, dumpsys_output: str) -> Optional[str]:
        pattern = r'mFocusedActivity: ActivityRecord\{[^}]+ ([^}]+)\}'
        match = re.search(pattern, dumpsys_output)
        if match:
            return match.group(1).split('/')[-1]
        return None
    
    def simulate_user_actions(self, package_name: str) -> bool:
        if not self.emulator.emulator_id:
            return False
        
        actions = [
            ('tap', 500, 800),
            ('tap', 500, 1000),
            ('swipe', 500, 1000, 500, 500),
            ('key', 'KEYCODE_BACK'),
            ('tap', 500, 600)
        ]
        
        for action in actions:
            try:
                if action[0] == 'tap':
                    subprocess.run([self.emulator.adb_path, '-s', 
                                   self.emulator.emulator_id,
                                   'shell', 'input', 'tap', 
                                   str(action[1]), str(action[2])],
                                  capture_output=True)
                elif action[0] == 'swipe':
                    subprocess.run([self.emulator.adb_path, '-s', 
                                   self.emulator.emulator_id,
                                   'shell', 'input', 'swipe',
                                   str(action[1]), str(action[2]),
                                   str(action[3]), str(action[4])],
                                  capture_output=True)
                elif action[0] == 'key':
                    subprocess.run([self.emulator.adb_path, '-s', 
                                   self.emulator.emulator_id,
                                   'shell', 'input', 'keyevent', action[1]],
                                  capture_output=True)
                
                time.sleep(2)
                
            except Exception as e:
                print(f"执行操作失败: {e}")
                continue
        
        print("用户操作模拟完成")
        return True
    
    def get_monitoring_result(self) -> Dict:
        return {
            'total_api_calls': len(self.api_calls),
            'api_calls': self.api_calls,
            'monitored_apis': self.monitored_apis,
            'timestamp': datetime.now().isoformat()
        }

class DynamicAnalyzer:
    def __init__(self):
        self.emulator_manager = AndroidEmulatorManager()
        self.api_monitor = APIHookMonitor(self.emulator_manager)
        self.results = []
    
    def analyze_apk(self, apk_path: str, package_name: str, 
                   activity_name: str, monitor_duration: int = 60) -> Dict:
        print(f"\n开始动态分析: {apk_path}")
        
        if not self.emulator_manager.check_device():
            return {'error': '未检测到设备'}
        
        if not self.emulator_manager.install_apk(apk_path):
            return {'error': 'APK安装失败'}
        
        time.sleep(3)
        
        if not self.emulator_manager.launch_app(package_name, activity_name):
            return {'error': '应用启动失败'}
        
        time.sleep(2)
        
        self.api_monitor.start_logcat_monitor(package_name)
        
        self.api_monitor.simulate_user_actions(package_name)
        
        api_calls = self.api_monitor.monitor_api_calls(monitor_duration)
        
        self.api_monitor.stop_logcat_monitor()
        
        time.sleep(2)
        
        self.emulator_manager.uninstall_app(package_name)
        
        result = {
            'apk_file': os.path.basename(apk_path),
            'package_name': package_name,
            'activity_name': activity_name,
            'monitoring_result': self.api_monitor.get_monitoring_result(),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        self.results.append(result)
        return result
    
    def save_results(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        
        for i, result in enumerate(self.results):
            output_file = os.path.join(output_dir, 
                                      f"dynamic_analysis_{i}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
        
        summary_file = os.path.join(output_dir, 'dynamic_analysis_summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump({
                'total_analyzed': len(self.results),
                'results': self.results
            }, f, ensure_ascii=False, indent=2)
        
        print(f"动态分析结果已保存到: {output_dir}")

if __name__ == "__main__":
    analyzer = DynamicAnalyzer()
    
    result = analyzer.analyze_apk(
        apk_path="../samples/Uu.apk",
        package_name="com.example.app",
        activity_name=".MainActivity",
        monitor_duration=30
    )
    
    analyzer.save_results("../results")