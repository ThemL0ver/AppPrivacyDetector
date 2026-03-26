import os
import sys
import argparse
from config import config
from logger import logger
from integrated_analysis import IntegratedAnalyzer

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='APP隐私权限检测与风险预警系统')
    parser.add_argument('--skip-dynamic', action='store_true', help='跳过动态分析')
    parser.add_argument('--only-integrated', action='store_true', help='只保存综合分析报告，删除其他结果文件')
    args = parser.parse_args()
    
    print("=" * 60)
    print("APP隐私权限检测与风险预警系统")
    print("=" * 60)
    
    samples_dir = config.samples_dir
    results_dir = config.results_dir
    
    if not os.path.exists(samples_dir):
        error_msg = f"错误: 样本目录不存在: {samples_dir}"
        print(error_msg)
        logger.error(error_msg)
        print("请将APK文件放入samples目录")
        return
    
    print("\n开始系统初始化...")
    print(f"样本目录: {samples_dir}")
    print(f"结果目录: {results_dir}")
    logger.info(f"系统初始化完成，样本目录: {samples_dir}, 结果目录: {results_dir}")
    
    analyzer = IntegratedAnalyzer(samples_dir, results_dir)
    
    print("\n开始执行完整分析流程...")
    logger.info("开始执行完整分析流程")
    
    try:
        report = analyzer.run_full_analysis(skip_dynamic=args.skip_dynamic, only_integrated=args.only_integrated)
        logger.info(f"分析完成，共分析 {report['total_analyzed']} 个APK")
    except Exception as e:
        error_msg = f"分析过程中发生错误: {str(e)}"
        print(error_msg)
        logger.error(error_msg)
        import traceback
        traceback.print_exc()
        return
    
    print("\n" + "=" * 60)
    print("分析完成！")
    print("=" * 60)
    print(f"\n分析报告已保存到: {results_dir}/integrated_analysis_report.json")
    print("\n要启动Web可视化系统，请运行:")
    print("  cd web_dashboard")
    print("  python app.py")
    print("\n然后在浏览器中访问: http://localhost:5000")
    logger.info("分析报告已生成，系统运行完成")

if __name__ == "__main__":
    main()