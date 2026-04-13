import argparse
import multiprocessing
import os

from integrated_analysis import IntegratedAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser(description="APP 隐私权限检测与风险预警系统")
    parser.add_argument("--skip-dynamic", action="store_true", help="仅执行静态分析并复用空动态结果")
    parser.add_argument(
        "--only-integrated",
        action="store_true",
        help="分析完成后仅保留 integrated_analysis_report.json",
    )
    parser.add_argument(
        "--dynamic-timeout-per-apk",
        type=int,
        default=300,
        help="动态分析单个 APK 的超时时间（秒），超时会自动终止并继续下一个样本",
    )
    args = parser.parse_args()

    samples_dir = "samples"
    results_dir = "results"

    print("=" * 60)
    print("APP 隐私权限检测与风险预警系统")
    print("=" * 60)

    if not os.path.exists(samples_dir):
        print(f"错误: 样本目录不存在 -> {samples_dir}")
        print("请先将 APK 样本放入 samples 目录。")
        return

    print(f"样本目录: {samples_dir}")
    print(f"结果目录: {results_dir}")
    if args.skip_dynamic:
        print("执行模式: 仅静态分析")
    else:
        print("执行模式: 静态分析 + 动态分析")
        print(f"动态单样本超时: {max(120, int(args.dynamic_timeout_per_apk))} 秒")

    analyzer = IntegratedAnalyzer(
        samples_dir,
        results_dir,
        dynamic_timeout_per_apk=args.dynamic_timeout_per_apk,
    )
    analyzer.run_full_analysis(skip_dynamic=args.skip_dynamic)

    if args.only_integrated:
        print("正在清理非综合报告文件...")
        for file_name in os.listdir(results_dir):
            if file_name == "integrated_analysis_report.json":
                continue
            file_path = os.path.join(results_dir, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
        print("清理完成。")

    print("=" * 60)
    print("分析完成")
    print("=" * 60)
    print(f"综合报告已保存到: {os.path.join(results_dir, 'integrated_analysis_report.json')}")
    print("如需查看前端看板，请运行:")
    print("  cd web_dashboard")
    print("  python app.py")
    print("然后访问: http://localhost:5000")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
