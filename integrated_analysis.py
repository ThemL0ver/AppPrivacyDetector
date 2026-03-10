#综合分析系统 - 静态和动态分析
import json
import os
from typing import Dict, List, Optional
from static_analysis.apk_analyzer import APKAnalyzer, APKBatchAnalyzer
from dynamic_analysis.analyzer import DynamicAnalyzer, DynamicBatchAnalyzer

class IntegratedAnalyzer:
    def __init__(self, samples_dir: str, results_dir: str = "results"):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        
        self.static_analyzer = APKBatchAnalyzer(samples_dir, results_dir)
        self.dynamic_analyzer = DynamicBatchAnalyzer(samples_dir, results_dir)
        
        self.risk_levels = {
            'high': 5,
            'medium': 3,
            'low': 1
        }
    
    def perform_static_analysis(self) -> List[Dict]:
        print("=" * 50)
        print("开始静态分析")
        print("=" * 50)
        
        static_results = self.static_analyzer.analyze_all()
        
        print(f"\n静态分析完成，共分析 {len(static_results)} 个APK")
        return static_results
    
    def perform_dynamic_analysis(self) -> List[Dict]:
        print("=" * 50)
        print("开始动态分析")
        print("=" * 50)
        
        dynamic_results = self.dynamic_analyzer.analyze_all()
        
        print(f"\n动态分析完成，共分析 {len(dynamic_results)} 个APK")
        return dynamic_results
    
    def calculate_risk_score(self, static_result: Dict, dynamic_result: Optional[Dict] = None) -> Dict:
        # 基于静态分析计算风险评分
        dangerous_perms = static_result['permission_analysis']['dangerous_permissions']
        high_risk_perms = static_result['permission_analysis']['high_risk_permissions']
        
        # 危险权限每个2分，高风险权限每个1分
        static_score = len(dangerous_perms) * 2 + len(high_risk_perms) * 1
        
        # 动态分析评分
        dynamic_score = 0
        if dynamic_result:
            # 检测到的敏感API调用每个3分
            sensitive_api_count = sum(len(calls) for calls in dynamic_result.get('sensitive_api_calls', {}).values())
            dynamic_score = sensitive_api_count * 3
            
            # 网络流量异常每个2分
            network_traffic_count = len(dynamic_result.get('network_traffic', []))
            dynamic_score += network_traffic_count * 2
        
        total_score = static_score + dynamic_score
        
        if total_score >= 15:
            risk_level = 'high'
        elif total_score >= 8:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'static_score': static_score,
            'dynamic_score': dynamic_score,
            'total_score': total_score,
            'risk_level': risk_level
        }
    
    def generate_integrated_report(self, static_results: List[Dict], dynamic_results: List[Dict]) -> Dict:
        print("\n" + "=" * 50)
        print("生成综合分析报告")
        print("=" * 50)
        
        # 创建动态结果映射，便于查找
        dynamic_result_map = {result['apk_file']: result for result in dynamic_results}
        
        integrated_results = []
        
        for static_result in static_results:
            apk_file = static_result['apk_file']
            dynamic_result = dynamic_result_map.get(apk_file)
            
            risk_assessment = self.calculate_risk_score(static_result, dynamic_result)
            
            integrated_result = {
                'apk_file': static_result['apk_file'],
                'package_name': static_result['package_name'],
                'static_analysis': static_result,
                'dynamic_analysis': dynamic_result,
                'risk_assessment': risk_assessment
            }
            
            integrated_results.append(integrated_result)
        
        report = {
            'analysis_date': None,
            'total_analyzed': len(integrated_results),
            'high_risk_apps': [r['apk_file'] for r in integrated_results 
                             if r['risk_assessment']['risk_level'] == 'high'],
            'medium_risk_apps': [r['apk_file'] for r in integrated_results 
                               if r['risk_assessment']['risk_level'] == 'medium'],
            'low_risk_apps': [r['apk_file'] for r in integrated_results 
                            if r['risk_assessment']['risk_level'] == 'low'],
            'results': integrated_results
        }
        
        report_file = os.path.join(self.results_dir, 'integrated_analysis_report.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        print(f"综合分析报告已保存到: {report_file}")
        
        self.print_summary(report)
        
        return report
    
    def print_summary(self, report: Dict):
        print("\n" + "=" * 50)
        print("分析摘要")
        print("=" * 50)
        print(f"总分析数量: {report['total_analyzed']}")
        print(f"高风险应用: {len(report['high_risk_apps'])}")
        print(f"中风险应用: {len(report['medium_risk_apps'])}")
        print(f"低风险应用: {len(report['low_risk_apps'])}")
        
        if report['high_risk_apps']:
            print("\n高风险应用列表:")
            for app in report['high_risk_apps']:
                print(f"  - {app}")
        
        print("=" * 50)
    
    def run_full_analysis(self, skip_dynamic: bool = False):
        static_results = self.perform_static_analysis()
        
        if skip_dynamic:
            print("跳过动态分析")
            dynamic_results = []
        else:
            dynamic_results = self.perform_dynamic_analysis()
        
        report = self.generate_integrated_report(static_results, dynamic_results)
        
        return report

if __name__ == "__main__":
    samples_dir = "samples"
    results_dir = "results"
    
    analyzer = IntegratedAnalyzer(samples_dir, results_dir)
    report = analyzer.run_full_analysis()
    
    print("\n分析完成！")