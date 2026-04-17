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
    parser.add_argument(
        "--manual-probe-seconds",
        type=int,
        default=0,
        help="低覆盖时人工操作窗口时长（秒），0 表示关闭人工补采",
    )
    parser.add_argument(
        "--low-coverage-api-threshold",
        type=int,
        default=4,
        help="Frida 首轮命中 API 调用低于该阈值时触发人工补采",
    )
    parser.add_argument(
        "--manual-probe-apks",
        type=str,
        default="",
        help="人工补采目标 APK 文件名列表（逗号分隔，如 Mooc.apk,BaiDu.apk）；为空表示对全部样本生效",
    )
    parser.add_argument(
        "--clear-app-data-after-analysis",
        action="store_true",
        help="批量动态分析时，每个 APK 分析结束后执行 pm clear，确保下次分析从初始状态开始",
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
        print(
            f"人工补采: {'开启' if int(args.manual_probe_seconds) > 0 else '关闭'} "
            f"(窗口={max(0, int(args.manual_probe_seconds))}秒, 触发阈值={max(1, int(args.low_coverage_api_threshold))})"
        )
        print(
            "批量环境清理: 开启 "
            f"(应用数据清理={'开启' if args.clear_app_data_after_analysis else '关闭'})"
        )

    manual_probe_apks = [
        item.strip()
        for item in str(args.manual_probe_apks or "").split(",")
        if item.strip()
    ]
    if manual_probe_apks:
        print("人工补采目标 APK: " + ", ".join(manual_probe_apks))

    analyzer = IntegratedAnalyzer(
        samples_dir,
        results_dir,
        dynamic_timeout_per_apk=args.dynamic_timeout_per_apk,
        manual_probe_seconds=args.manual_probe_seconds,
        low_coverage_api_threshold=args.low_coverage_api_threshold,
        manual_probe_apk_allowlist=manual_probe_apks,
        clear_app_data_after_analysis=args.clear_app_data_after_analysis,
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
