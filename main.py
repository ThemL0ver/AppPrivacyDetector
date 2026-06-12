"""APP 隐私权限检测与风险预警系统 —— 入口模块

=== 模块功能 ===
该脚本是整个系统的 CLI（命令行）入口，负责：
  1. 解析用户通过命令行传入的运行参数；
  2. 检查 APK 样本目录是否存在；
  3. 构造 IntegratedAnalyzer（综合分析器）实例；
  4. 触发完整的分析流程（静态分析 / 动态分析 / 综合分析）；
  5. 根据参数决定是否清理中间产物、仅保留综合报告；
  6. 输出最终结果路径及前端看板启动指引。

=== 命令行用法 ===
    python main.py                                    # 默认：静态 + 动态分析，全部样本
    python main.py --skip-dynamic                     # 仅静态分析，跳过动态
    python main.py --only-integrated                  # 分析完成后仅保留综合报告
    python main.py --include-apks BaiDu.apk,DeWu.apk  # 仅分析指定 APK
    python main.py --dynamic-timeout-per-apk 360      # 单个 APK 动态分析超时设为 360 秒
    python main.py --manual-probe-seconds 30          # 低覆盖时进入 30 秒人工操作窗口
    python main.py --clear-app-data-after-analysis    # 每个 APK 分析后清理应用数据

=== 依赖关系 ===
本模块依赖 integrated_analysis 模块中的 IntegratedAnalyzer 类来执行核心分析逻辑。
"""

# =========================== 标准库导入 ===========================
import argparse          # 命令行参数解析
import multiprocessing   # 多进程支持（Windows 下 freeze_support）
import os                # 文件系统和路径操作
import shutil            # 文件复制操作

# =========================== 项目内部导入 ===========================
from integrated_analysis import IntegratedAnalyzer


# =========================== 命令行入口函数 ===========================

def main() -> None:
    """系统主入口函数 —— 解析命令行参数并启动完整的隐私分析流程。

    该函数是整个系统的顶层调度器，执行步骤如下：
      1. 创建 ArgumentParser 并注册所有支持的 CLI 参数；
      2. 检查 samples 目录是否存在，若不存在则提前终止；
      3. 将命令行参数汇总打印给用户确认；
      4. 解析人工补采目标 APK 列表和仅分析 APK 列表；
      5. 构造 IntegratedAnalyzer 实例并触发 run_full_analysis()；
      6. 如果指定了 --only-integrated，清理中间报告文件；
      7. 打印完成提示及前端看板访问指引。

    参数：
        无 —— 所有必要信息通过命令行参数 (sys.argv) 传入。

    返回值：
        None —— 函数通过 print 输出状态信息，不返回任何值。
    """
    # ---------- 命令行参数定义 ----------
    # 创建 ArgumentParser 对象，description 会显示在 --help 输出中
    parser = argparse.ArgumentParser(description="APP 隐私权限检测与风险预警系统")

    # --skip-dynamic：仅执行静态分析，跳过动态分析（适用于没有模拟器环境时快速预览）
    parser.add_argument(
        "--skip-dynamic",
        action="store_true",
        help="仅执行静态分析并复用空动态结果",
    )

    # --only-integrated：分析完成后删除 csv、txt 等中间产物，仅保留综合 JSON 报告
    parser.add_argument(
        "--only-integrated",
        action="store_true",
        help="分析完成后仅保留 integrated_analysis_report.json",
    )

    # --dynamic-timeout-per-apk：动态分析单个 APK 的最大时长（秒），防止卡死
    parser.add_argument(
        "--dynamic-timeout-per-apk",
        type=int,
        default=300,
        help="动态分析单个 APK 的超时时间（秒），超时会自动终止并继续下一个样本",
    )

    # --manual-probe-seconds：Frida 覆盖不足时的人工补采窗口时长（秒）
    parser.add_argument(
        "--manual-probe-seconds",
        type=int,
        default=0,
        help="低覆盖时人工操作窗口时长（秒），0 表示关闭人工补采",
    )

    # --low-coverage-api-threshold：触发人工补采的 API 命中数阈值
    parser.add_argument(
        "--low-coverage-api-threshold",
        type=int,
        default=4,
        help="Frida 首轮命中 API 调用低于该阈值时触发人工补采",
    )

    # --manual-probe-apks：人工补采的目标 APK 白名单（逗号分隔）
    parser.add_argument(
        "--manual-probe-apks",
        type=str,
        default="",
        help="人工补采目标 APK 文件名列表（逗号分隔，如 Mooc.apk,BaiDu.apk）；为空表示对全部样本生效",
    )

    # --clear-app-data-after-analysis：每个 APK 分析后执行 pm clear，保证下次分析从干净状态开始
    parser.add_argument(
        "--clear-app-data-after-analysis",
        action="store_true",
        help="批量动态分析时，每个 APK 分析结束后执行 pm clear，确保下次分析从初始状态开始",
    )

    # --include-apks：指定仅分析某些 APK（逗号分隔），用于快速复测
    parser.add_argument(
        "--include-apks",
        type=str,
        default="",
        help="仅分析指定 APK 文件名列表（逗号分隔）；为空表示分析 samples 下全部 APK",
    )

    # 解析命令行参数，返回 Namespace 对象
    args = parser.parse_args()

    # ---------- 目录路径常量 ----------
    samples_dir = "samples"   # APK 样本存放目录
    results_dir = "results"   # 分析结果输出目录

    # ---------- 打印系统启动信息 ----------
    print("=" * 60)
    print("APP 隐私权限检测与风险预警系统")
    print("=" * 60)

    # ---------- 检查样本目录是否存在 ----------
    if not os.path.exists(samples_dir):
        print(f"错误: 样本目录不存在 -> {samples_dir}")
        print("请先将 APK 样本放入 samples 目录。")
        return  # 提前退出，不执行后续分析

    # ---------- 输出当前运行配置 ----------
    print(f"样本目录: {samples_dir}")
    print(f"结果目录: {results_dir}")

    if args.skip_dynamic:
        print("执行模式: 仅静态分析")
    else:
        print("执行模式: 静态分析 + 动态分析")
        # 动态超时取配置值与 120 秒中的较大者，防止设置过短导致分析不完整
        print(f"动态单样本超时: {max(120, int(args.dynamic_timeout_per_apk))} 秒")
        # 打印人工补采状态：窗口时长和触发阈值
        print(
            f"人工补采: {'开启' if int(args.manual_probe_seconds) > 0 else '关闭'} "
            f"(窗口={max(0, int(args.manual_probe_seconds))}秒, "
            f"触发阈值={max(1, int(args.low_coverage_api_threshold))})"
        )
        # 打印批量环境配置信息
        print(
            "批量环境清理: 开启 "
            f"(应用数据清理={'开启' if args.clear_app_data_after_analysis else '关闭'})"
        )

    # ---------- 解析人工补采目标 APK 列表 ----------
    # 将逗号分隔字符串拆分为列表，去除空白和空字符串
    manual_probe_apks = [
        item.strip()
        for item in str(args.manual_probe_apks or "").split(",")
        if item.strip()
    ]
    if manual_probe_apks:
        print("人工补采目标 APK: " + ", ".join(manual_probe_apks))

    # ---------- 解析仅分析 APK 列表 ----------
    # 将逗号分隔字符串拆分为列表，去除空白和空字符串
    include_apks = [
        item.strip()
        for item in str(args.include_apks or "").split(",")
        if item.strip()
    ]
    if include_apks:
        print("仅分析 APK: " + ", ".join(include_apks))

    # ---------- 构造综合分析器并启动分析 ----------
    # IntegratedAnalyzer 初始化时传入所有配置参数，内部会根据参数调度静态/动态分析
    analyzer = IntegratedAnalyzer(
        samples_dir,
        results_dir,
        dynamic_timeout_per_apk=args.dynamic_timeout_per_apk,
        manual_probe_seconds=args.manual_probe_seconds,
        low_coverage_api_threshold=args.low_coverage_api_threshold,
        manual_probe_apk_allowlist=manual_probe_apks,
        clear_app_data_after_analysis=args.clear_app_data_after_analysis,
        include_apks=include_apks,
    )
    # 启动完整分析流程：根据 skip_dynamic 决定是否执行动态分析
    analyzer.run_full_analysis(skip_dynamic=args.skip_dynamic)

    # ---------- 仅保留综合报告（可选） ----------
    # 如果用户指定了 --only-integrated，删除 results 目录下除综合报告外的所有文件
    if args.only_integrated:
        print("正在清理非综合报告文件...")
        for file_name in os.listdir(results_dir):
            # 跳过综合报告文件，不删除
            if file_name == "integrated_analysis_report.json":
                continue
            file_path = os.path.join(results_dir, file_name)
            # 仅删除文件，保留子目录
            if os.path.isfile(file_path):
                os.remove(file_path)
        print("清理完成。")

    

    # ---------- 打印完成信息 ----------
    print("=" * 60)
    print("分析完成")
    print("=" * 60)
    # 输出综合报告的文件路径
    print(f"综合报告已保存到: {os.path.join(results_dir, 'integrated_analysis_report.json')}")
    # 引导用户启动前端看板
    print("如需查看前端看板，请运行:")
    print("  cd web_dashboard")
    print("  python app.py")
    print("然后访问: http://localhost:5000")


# =========================== 程序入口 ===========================

if __name__ == "__main__":
    # Windows 系统下 multiprocessing 需要调用 freeze_support()，
    # 防止在使用 PyInstaller 打包或 spawn 模式启动子进程时出现递归调用问题
    multiprocessing.freeze_support()
    # 启动主函数
    main()
