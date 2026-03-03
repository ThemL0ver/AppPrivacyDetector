#综合分析系统 - 专注于静态分析
import json
import os
from typing import Dict, List
from static_analysis.apk_analyzer import APKAnalyzer, APKBatchAnalyzer

class IntegratedAnalyzer:
    def __init__(self, samples_dir: str, results_dir: str = "results"):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        
        self.static_analyzer = APKBatchAnalyzer(samples_dir, results_dir)
        
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
    
    def calculate_risk_score(self, static_result: Dict) -> Dict:
        # 基于静态分析计算风险评分
        dangerous_perms = static_result['permission_analysis']['dangerous_permissions']
        high_risk_perms = static_result['permission_analysis']['high_risk_permissions']
        
        # 危险权限每个2分，高风险权限每个1分
        static_score = len(dangerous_perms) * 2 + len(high_risk_perms) * 1
        
        if static_score >= 10:
            risk_level = 'high'
        elif static_score >= 5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'static_score': static_score,
            'total_score': static_score,
            'risk_level': risk_level
        }
    
    def generate_integrated_report(self, static_results: List[Dict]) -> Dict:
        print("\n" + "=" * 50)
        print("生成综合分析报告")
        print("=" * 50)
        
        integrated_results = []
        
        for static_result in static_results:
            risk_assessment = self.calculate_risk_score(static_result)
            
            integrated_result = {
                'apk_file': static_result['apk_file'],
                'package_name': static_result['package_name'],
                'static_analysis': static_result,
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
    
    def run_full_analysis(self):
        static_results = self.perform_static_analysis()
        report = self.generate_integrated_report(static_results)
        
        return report

if __name__ == "__main__":
    samples_dir = "samples"
    results_dir = "results"
    
    analyzer = IntegratedAnalyzer(samples_dir, results_dir)
    report = analyzer.run_full_analysis()
    
    print("\n分析完成！")