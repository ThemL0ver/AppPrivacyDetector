import os
import sys
import argparse
from integrated_analysis import IntegratedAnalyzer

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='APP隐私权限检测与风险预警系统')
    parser.add_argument('--skip-dynamic', action='store_true', help='跳过动态分析')
    args = parser.parse_args()
    
    print("=" * 60)
    print("APP隐私权限检测与风险预警系统")
    print("=" * 60)
    
    samples_dir = "samples"
    results_dir = "results"
    
    if not os.path.exists(samples_dir):
        print(f"错误: 样本目录不存在: {samples_dir}")
        print("请将APK文件放入samples目录")
        return
    
    print("\n开始系统初始化...")
    print(f"样本目录: {samples_dir}")
    print(f"结果目录: {results_dir}")
    
    analyzer = IntegratedAnalyzer(samples_dir, results_dir)
    
    print("\n开始执行完整分析流程...")
    report = analyzer.run_full_analysis(skip_dynamic=args.skip_dynamic)
    
    print("\n" + "=" * 60)
    print("分析完成！")
    print("=" * 60)
    print(f"\n分析报告已保存到: {results_dir}/integrated_analysis_report.json")
    print("\n要启动Web可视化系统，请运行:")
    print("  cd web_dashboard")
    print("  python app.py")
    print("\n然后在浏览器中访问: http://localhost:5000")

if __name__ == "__main__":
    main()