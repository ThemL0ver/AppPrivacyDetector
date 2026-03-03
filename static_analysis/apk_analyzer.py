#静态分析模块 - APK分析器
import os
import json
import pandas as pd
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from androguard.core import apk

class APKAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = "output"):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.permissions = []
        self.package_name = None
        self.activities = []
        self.services = []
        self.receivers = []
        self.providers = []
        self.permission_risk_map = self._load_permission_risk_map()
    
    def _load_permission_risk_map(self) -> Dict[str, str]:
        """加载权限风险等级映射"""
        risk_map = {}
        excel_path = 'docs/apk系统权限与风险.xlsx'
        
        print(f"尝试加载权限风险文件: {excel_path}")
        print(f"文件是否存在: {os.path.exists(excel_path)}")
        
        try:
            df = pd.read_excel(excel_path)
            print(f"Excel文件读取成功，共 {len(df)} 行数据")
            print(f"列名: {df.columns.tolist()}")
            
            if '权限名' in df.columns and '风险等级' in df.columns:
                for _, row in df.iterrows():
                    permission = row['权限名']
                    risk_level = row['风险等级']
                    if pd.notna(risk_level) and pd.notna(permission):
                        # 去除权限名称中的空格和换行符
                        permission_stripped = str(permission).strip()
                        risk_level_stripped = str(risk_level).strip()
                        risk_map[permission_stripped] = risk_level_stripped
            print(f"加载权限风险等级映射成功，共 {len(risk_map)} 条记录")
            # 打印前10条记录
            print("前10条权限风险映射:")
            for i, (perm, level) in enumerate(list(risk_map.items())[:10]):
                print(f"  {i+1}. {perm}: {level}")
                
            # 检查特定权限是否存在
            test_permissions = [
                'android.permission.CAMERA',
                'android.permission.READ_PHONE_STATE',
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.INTERNET'
            ]
            print("\n检查特定权限:")
            for perm in test_permissions:
                if perm in risk_map:
                    print(f"  {perm}: {risk_map[perm]}")
                else:
                    print(f"  {perm}: 未找到")
                    # 尝试匹配类似的权限
                    for key in risk_map.keys():
                        if perm in key:
                            print(f"  类似权限: {key}: {risk_map[key]}")
        except Exception as e:
            print(f"加载权限风险等级映射失败: {e}")
            import traceback
            traceback.print_exc()
        
        return risk_map
        
    def parse_manifest(self) -> bool:
        try:
            # 使用androguard解析APK文件
            a = apk.APK(self.apk_path)
            
            # 获取包名
            self.package_name = a.get_package()
            
            # 获取权限列表
            self.permissions = a.get_permissions()
            
            # 获取组件信息
            self.activities = a.get_activities()
            self.services = a.get_services()
            self.receivers = a.get_receivers()
            self.providers = a.get_providers()
            
            print(f"解析成功: 包名={self.package_name}, 权限数={len(self.permissions)}")
            return True
        except Exception as e:
            print(f"解析AndroidManifest.xml失败: {e}")
            return False
    
    def _auto_detect_risk_level(self, permission: str) -> str:
        """自动检测权限风险等级
        
        根据权限名称特征自动判断风险等级
        """
        perm_lower = permission.lower()
        
        # 极高风险特征
        if any(keyword in perm_lower for keyword in [
            'camera', 'microphone', 'record_audio', 'read_phone_state', 
            'read_logs', 'accessibility', 'notification_listener',
            'install', 'uninstall', 'vpn', 'access_fine_location',
            'biometric', 'face', 'fingerprint', 'health', 'sms',
            'imei', 'mac', 'oaid', 'msa', 'device_id'
        ]):
            return '极高（自动检测）'
        
        # 高风险特征
        elif any(keyword in perm_lower for keyword in [
            'read_external_storage', 'write_external_storage',
            'read_contacts', 'write_contacts', 'read_calendar',
            'write_calendar', 'read_call_log', 'write_call_log',
            'access_coarse_location', 'get_accounts'
        ]):
            return '高（自动检测）'
        
        # 中高风险特征
        elif any(keyword in perm_lower for keyword in [
            'system_alert_window', 'draw_overlays', 'modify_system_settings',
            'download', 'mock_location', 'read_audio'
        ]):
            return '中高（自动检测）'
        
        # 中风险特征
        elif any(keyword in perm_lower for keyword in [
            'get_tasks', 'get_package_size', 'query_all_packages',
            'boot_completed', 'ignore_battery_optimizations',
            'install_shortcut'
        ]):
            return '中（自动检测）'
        
        # 低风险特征
        elif any(keyword in perm_lower for keyword in [
            'internet', 'vibrate', 'flashlight', 'change_wifi_state',
            'access_network_state', 'access_wifi_state', 'change_network_state',
            'foreground_service'
        ]):
            return '低（自动检测）'
        
        # 厂商/应用自定义权限
        elif '.' in permission and not permission.startswith('android.permission.'):
            # 检查是否包含敏感关键词
            if any(keyword in perm_lower for keyword in [
                'push', 'notification', 'ads', 'tracking', 'analytics',
                'device_id', 'unique', 'identifier', 'location', 'camera',
                'microphone', 'storage', 'contacts', 'sms', 'call'
            ]):
                return '中高（自定义权限）'
            else:
                return '中（自定义权限）'
        
        # 默认低风险
        else:
            return '低（自动检测）'
    
    def analyze_permissions(self) -> Dict:
        dangerous_permissions = [
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ADD_VOICEMAIL',
            'android.permission.USE_SIP',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CELL_BROADCASTS',
            'android.permission.BODY_SENSORS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_HISTORY_BOOKMARKS',
            'android.permission.WRITE_HISTORY_BOOKMARKS'
        ]
        
        dangerous = [p for p in self.permissions if p in dangerous_permissions]
        normal = [p for p in self.permissions if p not in dangerous_permissions]
        
        # 按风险等级分类
        risk_levels = {
            '低': [],
            '中': [],
            '中高': [],
            '高': [],
            '极高': []
        }
        
        permission_details = []
        
        print(f"分析权限: {len(self.permissions)} 个权限")
        print(f"权限风险映射大小: {len(self.permission_risk_map)}")
        
        for permission in self.permissions:
            print(f"检查权限: {permission}")
            # 尝试直接匹配
            risk_level = self.permission_risk_map.get(permission, '未知')
            
            # 如果未找到，尝试去除空格和换行符后匹配
            if risk_level == '未知':
                permission_stripped = permission.strip()
                risk_level = self.permission_risk_map.get(permission_stripped, '未知')
                if risk_level != '未知':
                    print(f"  去除空格后匹配成功: {permission_stripped}")
            
            # 如果仍未找到，自动检测风险等级
            if risk_level == '未知':
                risk_level = self._auto_detect_risk_level(permission)
                print(f"  自动检测风险等级: {risk_level}")
            else:
                print(f"  风险等级: {risk_level}")
            
            # 提取风险等级的主要级别
            main_risk_level = risk_level
            if '（' in risk_level:
                main_risk_level = risk_level.split('（')[0]
            
            # 分类到对应风险等级
            if main_risk_level in risk_levels:
                risk_levels[main_risk_level].append(permission)
            else:
                risk_levels['低'].append(permission)  # 默认为低风险
            
            # 记录详细信息
            permission_details.append({
                'name': permission,
                'risk_level': risk_level,
                'main_risk_level': main_risk_level,
                'is_dangerous': permission in dangerous_permissions
            })
        
        # 计算高风险权限（中高、高、极高）
        high_risk_permissions = risk_levels['中高'] + risk_levels['高'] + risk_levels['极高']
        
        print(f"高风险权限数量: {len(high_risk_permissions)}")
        print(f"各风险等级权限数量: {risk_levels}")
        
        return {
            'all_permissions': self.permissions,
            'dangerous_permissions': dangerous,
            'normal_permissions': normal,
            'risk_levels': risk_levels,
            'high_risk_permissions': high_risk_permissions,
            'permission_details': permission_details
        }
    
    def get_analysis_result(self) -> Dict:
        return {
            'package_name': self.package_name,
            'permissions': self.permissions,
            'activities': self.activities,
            'services': self.services,
            'receivers': self.receivers,
            'providers': self.providers,
            'total_permissions': len(self.permissions),
            'permission_analysis': self.analyze_permissions()
        }
    
    def save_result(self, output_file: str):
        result = self.get_analysis_result()
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"分析结果已保存到: {output_file}")
    


class APKBatchAnalyzer:
    def __init__(self, samples_dir: str, results_dir: str = "results"):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
    
    def analyze_all(self) -> List[Dict]:
        results = []
        apk_files = [f for f in os.listdir(self.samples_dir) if f.endswith('.apk')]
        
        print(f"找到 {len(apk_files)} 个APK文件")
        
        for apk_file in apk_files:
            apk_path = os.path.join(self.samples_dir, apk_file)
            print(f"\n分析: {apk_file}")
            
            output_dir = os.path.join(self.results_dir, f"{apk_file}_temp")
            analyzer = APKAnalyzer(apk_path, output_dir)
            
            if analyzer.parse_manifest():
                result = analyzer.get_analysis_result()
                result['apk_file'] = apk_file
                
                result_file = os.path.join(self.results_dir, f"{apk_file}_analysis.json")
                analyzer.save_result(result_file)
                
                results.append(result)
            else:
                print(f"分析失败: {apk_file}")
        
        self.save_summary(results)
        return results
    
    def save_summary(self, results: List[Dict]):
        summary = {
            'total_analyzed': len(results),
            'total_permissions': sum(r['total_permissions'] for r in results),
            'high_risk_apps': [r['apk_file'] for r in results 
                             if len(r['permission_analysis']['dangerous_permissions']) >= 5],
            'results': results
        }
        
        summary_file = os.path.join(self.results_dir, 'batch_analysis_summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"\n批量分析摘要已保存到: {summary_file}")

if __name__ == "__main__":
    samples_dir = "../samples"
    results_dir = "../results"
    
    batch_analyzer = APKBatchAnalyzer(samples_dir, results_dir)
    results = batch_analyzer.analyze_all()
    
    print(f"\n分析完成！共分析 {len(results)} 个APK文件")