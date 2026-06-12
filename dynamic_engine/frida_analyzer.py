# -*- coding: utf-8 -*-
"""
Frida 动态分析模块。

本模块基于 Frida 框架实现对 Android 应用的运行时敏感 API 调用监控。
包含两个核心类：
  - FridaDynamicAnalyzer：底层 Frida 会话管理器，负责设备连接、进程附加/启动、脚本注入、结果采集。
  - EnhancedDynamicAnalyzer：上层调度器，提供 attach/spawn 自动切换、探针并发执行及失败重试策略。

典型调用流程：
  1. 创建 EnhancedDynamicAnalyzer 实例，设置目标包名
  2. 调用 perform_frida_analysis() 启动监控
  3. 通过 get_frida_summary() 获取分析摘要

适用场景：应用隐私合规检测、API 调用行为分析。
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from dynamic_engine.hook_manager import HookManager


class FridaDynamicAnalyzer:
    """Frida 动态分析器（底层会话管理）。

    功能概述：
      负责单次 Frida 会话的完整生命周期管理，包括：
      1. 连接 Frida 设备（USB/Wi-Fi）
      2. 以 attach 或 spawn 模式附加到目标 APP 进程
      3. 注入 TypeScript Hook 脚本（sensitive_api_hook.ts）
      4. 运行指定时长并采集 API 调用日志
      5. 将结果序列化为 JSON 文件并返回结构化摘要

    状态管理：
      - hook_results 字典贯穿整个会话生命周期，作为数据汇聚中心
      - 每次新的分析前需调用 reset_runtime_state() 清空残留状态

    典型用途：
      作为 EnhancedDynamicAnalyzer 的底层引擎，不直接对外暴露。
    """

    def __init__(self, apk_path: str, package_name: str, output_dir: str = "results"):
        """初始化 Frida 动态分析器。

        参数：
            apk_path (str): 待分析的 APK 文件路径，用于命名输出文件。
            package_name (str): 目标 APP 的 Android 包名（如 com.example.app）。
            output_dir (str): 分析结果输出目录，默认为 "results"。
        """
        self.apk_path = apk_path
        self.package_name = package_name
        self.output_dir = output_dir
        # 创建 Hook 管理器，负责底层 Frida 设备操作与脚本交互
        self.hook_manager = HookManager(package_name)
        # 优先附加的进程 PID 列表（多进程 APP 场景下使用）
        self.preferred_pids: List[int] = []
        # 初始化空白的 Hook 结果字典，作为本次分析的初始数据容器
        self.hook_results: Dict[str, Any] = self._build_empty_hook_results()

    def _build_empty_hook_results(self) -> Dict[str, Any]:
        """构造空白的 Hook 结果字典。

        该字典作为每次 Frida 分析的初始状态，包含以下字段：
          - hooked_apis:    已成功 Hook 的 API 列表
          - call_logs:      敏感 API 调用日志（时间、参数、堆栈）
          - duration:       实际监控时长（秒）
          - errors:         会话期间发生的错误信息
          - signal_counts:  按 API 信号名称统计的调用次数
          - category_counts:按 API 类别（如网络、文件、传感器）统计的次数
          - aggregated_calls:按调用签名聚合后的调用记录
          - status_messages:脚本运行期间的状态消息

        返回：
            Dict[str, Any]: 包含上述所有字段的空初始字典。
        """
        return {
            "hooked_apis": [],
            "call_logs": [],
            "duration": 0.0,
            "errors": [],
            "signal_counts": {},
            "category_counts": {},
            "aggregated_calls": [],
            "status_messages": [],
        }

    def reset_runtime_state(self) -> None:
        """重置运行时状态，为新一轮分析做准备。

        操作步骤：
          1. 尝试停止当前 HookManager 会话（忽略可能的异常）
          2. 重新创建 HookManager 实例
          3. 重新应用优先 PID 设置
          4. 清空 hook_results 字典

        该方法在每次 perform_frida_analysis 调用前被执行，
        确保上一轮会话的残留数据不会污染新一轮分析结果。
        """
        try:
            # 安全停止上一次会话，即使已经停止也不抛出异常
            self.hook_manager.stop()
        except Exception:
            pass
        # 重新创建 HookManager，绑定相同的目标包名
        self.hook_manager = HookManager(self.package_name)
        # 恢复之前设置的优先 PID 列表
        self.hook_manager.set_preferred_pids(self.preferred_pids)
        # 重置结果容器
        self.hook_results = self._build_empty_hook_results()

    def set_preferred_pids(self, pids: List[int]) -> None:
        """设置优先附加的进程 PID 列表。

        背景说明：
          某些 Android 应用会启动多个进程（如 WebView 进程、推送服务进程）。
          Frida 默认可能附加到非主进程，导致 Hook 不到业务逻辑中的 API 调用。
          通过此方法可指定优先尝试的 PID，确保 Hook 正确的目标进程。

        参数：
            pids (List[int]): 目标 APP 的进程号列表，按优先级从前到后排列。
                           无效值（非正整数、重复值）会被自动过滤。

        副作用：
          同步更新内部的 HookManager 实例。
        """
        ordered: List[int] = []
        seen = set()
        for pid in pids or []:
            try:
                # 统一转换为整数类型
                normalized = int(pid)
            except (TypeError, ValueError):
                continue
            # 过滤无效 PID 和重复 PID
            if normalized <= 0 or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        self.preferred_pids = ordered
        # 将过滤后的 PID 列表同步到 HookManager
        self.hook_manager.set_preferred_pids(self.preferred_pids)

    def start_hook(self, spawn: bool = False) -> bool:
        """启动 Frida Hook 会话。

        本方法是整个动态分析的入口，按顺序完成以下关键步骤：
          1. 连接到 Frida 设备（通过 adb 连接的 Android 设备）
          2. 以 attach 或 spawn 模式附加到目标进程
          3. 加载 TypeScript Hook 脚本（sensitive_api_hook.ts）
          4. 等待脚本就绪信号

        参数：
            spawn (bool): 进程启动模式。
              - False（默认）：attach 模式，附加到已运行的目标 APP 进程。
              - True：spawn 模式，由 Frida 重新拉起目标 APP 并从启动时刻开始监控。

        返回：
            bool:
              - True：Hook 会话成功启动，脚本已就绪。
              - False：连接失败、脚本加载失败或等待就绪超时。
              失败时错误信息会写入 hook_results["errors"]。
        """
        print("=" * 60)
        print("start Frida runtime monitor")
        print("=" * 60)

        # 步骤1：连接到 Frida 设备
        if not self.hook_manager.connect_device():
            self.hook_results["errors"].append("unable to connect Frida device")
            return False

        # 步骤2：以 attach/spawn 模式启动会话
        success, pid = self.hook_manager.start(spawn=spawn)
        if not success:
            self.hook_results["errors"].append("unable to create Frida session")
            return False

        # 步骤3：注入 Hook 脚本（TypeScript 编写，编译为 JavaScript 执行）
        # 脚本路径相对于当前文件所在目录的 frida_agent 子目录
        script_path = os.path.join(os.path.dirname(__file__), "frida_agent", "sensitive_api_hook.ts")
        if not self.hook_manager.load_script(script_path, pid):
            self.hook_results["errors"].append("unable to load hook script")
            return False

        # 步骤4：等待脚本完成 Hook 注册并发送就绪信号
        # spawn 模式需要额外等待 APP 冷启动，因此超时时间更长
        if not self.hook_manager.wait_for_script_ready(timeout=10 if spawn else 8):
            # 脚本未能在超时时间内就绪，采集当前的半成品数据作为诊断依据
            self.hook_results["errors"] = self.hook_results.get("errors", []) + self.hook_manager.get_errors()
            self.hook_results["status_messages"] = self.hook_manager.get_status_messages()
            self.hook_results["hooked_apis"] = self.hook_manager.get_hooked_apis()
            self.hook_results["call_logs"] = self.hook_manager.get_call_logs()
            self.hook_results["signal_counts"] = self.hook_manager.get_signal_counts()
            self.hook_results["category_counts"] = self.hook_manager.get_category_counts()
            self.hook_results["aggregated_calls"] = self.hook_manager.get_aggregated_calls()
            # 采集 detached 事件，帮助诊断会话提前断开的原因
            detached_events = self.hook_manager.get_detached_events()
            if detached_events:
                self.hook_results["detached_events"] = detached_events
            # 确保至少有一条错误信息
            if not self.hook_results["errors"]:
                self.hook_results["errors"].append("hook script did not reach ready state")
            return False

        return True

    def monitor(self, duration: int = 60) -> Dict[str, Any]:
        """进入监控循环，等待指定时长后停止 Hook 并采集结果。

        监控流程：
          1. 记录开始时间
          2. 睡眠 duration 秒（期间 Frida 脚本在后台持续记录 API 调用）
          3. 停止 HookManager 会话
          4. 从 HookManager 汇聚所有采集数据到 hook_results
          5. 将结果保存为 JSON 文件
          6. 返回完整的结果字典

        参数：
            duration (int): 监控窗口时长，单位秒，默认 60。

        返回：
            Dict[str, Any]: 完整的 Hook 结果字典，包含调用日志、信号统计等。
        """
        start_time = time.time()
        print(f"[Frida] monitoring for {duration}s")

        try:
            # 监控窗口：在此期间 Frida 脚本持续拦截和记录敏感 API 调用
            time.sleep(duration)
        except KeyboardInterrupt:
            # 允许用户通过 Ctrl+C 提前终止监控
            print("[Frida] interrupted by user")
        finally:
            # 无论正常结束还是中断，都要执行停止和结果采集
            self.hook_manager.stop()
            # 从 HookManager 采集所有监控数据
            self.hook_results["hooked_apis"] = self.hook_manager.get_hooked_apis()
            self.hook_results["call_logs"] = self.hook_manager.get_call_logs()
            self.hook_results["duration"] = round(time.time() - start_time, 3)
            self.hook_results["errors"] = self.hook_results.get("errors", []) + self.hook_manager.get_errors()
            self.hook_results["signal_counts"] = self.hook_manager.get_signal_counts()
            self.hook_results["category_counts"] = self.hook_manager.get_category_counts()
            self.hook_results["aggregated_calls"] = self.hook_manager.get_aggregated_calls()
            self.hook_results["status_messages"] = self.hook_manager.get_status_messages()
            # 采集 detached 事件（会话异常断开的诊断信息）
            detached_events = self.hook_manager.get_detached_events()
            if detached_events:
                self.hook_results["detached_events"] = detached_events

        # 将结果持久化为 JSON 文件
        self._save_hook_results()
        print("=" * 60)
        print("Frida monitor finished")
        print("=" * 60)
        return self.hook_results

    def _save_hook_results(self) -> None:
        """将 Hook 结果持久化保存为 JSON 文件。

        文件命名规则：{APK文件名}_frida_hook.json
        保存位置：self.output_dir 指定的目录
        编码格式：UTF-8（ensure_ascii=False 保留中文可读性）
        格式化：缩进 2 空格，便于人工查阅。

        用途：
          为后续报告生成提供结构化数据源，也用于调试分析过程。
        """
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        # 构造输出文件路径：{输出目录}/{APK文件名}_frida_hook.json
        output_file = os.path.join(self.output_dir, f"{os.path.basename(self.apk_path)}_frida_hook.json")
        with open(output_file, "w", encoding="utf-8") as output_handle:
            json.dump(self.hook_results, output_handle, ensure_ascii=False, indent=2)
        print(f"[Frida] hook results saved to: {output_file}")

    def get_summary(self) -> Dict[str, Any]:
        """将原始 Hook 结果压缩为上层可用的摘要字典。

        摘要包含以下信息：
          - 统计指标：Hook 的 API 数量、总调用次数、信号种类、类别数
          - 诊断标志：Java Bridge 是否就绪、Hook 是否就绪
          - 异常标志：进程是否已终止、会话是否已 detach
          - 截断数据：aggregated_calls 前 30 条、status_messages 前 30 条等

        设计目的：
          避免将完整的 call_logs（可能包含数千条记录）传递给上层，
          只提取关键统计量和标志位，提高数据传输效率。

        返回：
            Dict[str, Any]: 分析结果摘要字典。
        """
        aggregated_calls = self.hook_results.get("aggregated_calls", [])
        status_messages = self.hook_results.get("status_messages", [])
        error_messages = self.hook_results.get("errors", [])
        detached_events = self.hook_results.get("detached_events", [])

        # 将状态消息和异常信息合并为小写字符串，用于关键字匹配
        status_blob = "\n".join(str(item) for item in status_messages).lower()
        issue_blob = "\n".join(str(item) for item in (list(error_messages) + list(detached_events))).lower()

        return {
            # === 数量统计 ===
            "total_hooked_apis": len(self.hook_results.get("hooked_apis", [])),
            "total_api_calls": len(self.hook_results.get("call_logs", [])),
            "total_hooked_signals": len(self.hook_results.get("signal_counts", {})),
            "total_categories": len(self.hook_results.get("category_counts", {})),
            "duration": self.hook_results.get("duration", 0.0),
            "errors": len(self.hook_results.get("errors", [])),

            # === 原始数据引用（供上层进一步分析） ===
            "hooked_apis": self.hook_results.get("hooked_apis", []),
            "signal_counts": self.hook_results.get("signal_counts", {}),
            "category_counts": self.hook_results.get("category_counts", {}),

            # === 截断数据（避免传输过大） ===
            "aggregated_calls": aggregated_calls[:30],
            "status_messages": status_messages[:30],
            "error_messages": error_messages[:30],
            "detached_events": detached_events[:10],

            # === 诊断标志位（通过关键字匹配判断会话状态） ===
            "java_bridge_ready": "java bridge ready" in status_blob,
            "java_hook_ready": "sensitive api hooks ready" in status_blob,
            "process_terminated": "process-terminated" in issue_blob,
            "session_detached": "session detached:" in issue_blob,
        }


class EnhancedDynamicAnalyzer:
    """Frida 分析的上层调度器（增强版）。

    功能概述：
      在 FridaDynamicAnalyzer 之上提供更健壮的分析接口，包括：
      1. attach/spawn 模式自动切换：当一种模式不稳定时自动尝试另一种
      2. 探针并发执行：监控期间可并行运行 UI 交互脚本触发敏感 API
      3. 智能重试判断：根据 Java Bridge 状态、进程终止信号决定是否重试
      4. 失败安全兜底：即使多次重试失败也返回最后的半成品结果

    设计理念：
      Frida 在实际使用中可能因设备环境、APP 加固等原因不稳定。
      本类通过多层容错机制最大化分析成功率，适合自动化批量检测场景。

    典型用法：
      >>> analyzer = EnhancedDynamicAnalyzer(apk_path, output_dir)
      >>> analyzer.set_package_name("com.target.app")
      >>> result = analyzer.perform_frida_analysis(duration=30, spawn_first=False)
      >>> summary = analyzer.get_frida_summary()
    """

    def __init__(self, apk_path: str, output_dir: str = "results"):
        """初始化增强动态分析器。

        参数：
            apk_path (str): 待分析的 APK 文件路径。
            output_dir (str): 结果输出目录，默认为 "results"。
        """
        self.apk_path = apk_path
        self.output_dir = output_dir
        # 目标包名，初始化时为 None，需要调用 set_package_name 设置
        self.package_name: Optional[str] = None
        # 底层的 Frida 分析器实例，延迟创建
        self.frida_analyzer: Optional[FridaDynamicAnalyzer] = None

    def set_package_name(self, package_name: str) -> None:
        """设置目标应用的包名，并创建对应的底层分析器。

        参数：
            package_name (str): Android 包名，如 "com.example.app"。

        副作用：
          内部创建 FridaDynamicAnalyzer 实例，使用相同的 apk_path 和 output_dir。
        """
        self.package_name = package_name
        if package_name:
            # 只有当包名非空时才创建分析器，避免无效实例
            self.frida_analyzer = FridaDynamicAnalyzer(
                self.apk_path,
                package_name,
                output_dir=self.output_dir,
            )

    def set_preferred_pids(self, pids: List[int]) -> None:
        """将优先 PID 信息同步传递给底层的 FridaDynamicAnalyzer。

        参数：
            pids (List[int]): 目标 APP 的进程 PID 列表，按优先级排序。

        适用场景：
          当上层模块通过 adb shell ps 等方式获取到目标 APP 的 PID 后，
          通过此方法告知底层分析器优先附加到这些进程。
        """
        if self.frida_analyzer:
            self.frida_analyzer.set_preferred_pids(pids)

    def _run_probe_callback(self, probe_callback: Callable[[], None]) -> None:
        """在独立线程中执行探针回调函数。

        探针回调的典型用途：
          - 在 Frida 监控期间通过 adb 模拟用户操作（点击、滑动）
          - 触发特定的 APP 功能，诱导敏感 API 被调用
          - 并发执行可提升效率，避免监控窗口白白等待

        参数：
            probe_callback (Callable[[], None]): 无参数无返回值的回调函数。

        异常处理：
          回调执行失败不会中断主监控流程，错误信息会被记录到 hook_results["errors"]。
        """
        try:
            print("[Frida] run probe callback")
            probe_callback()
            print("[Frida] probe callback done")
        except Exception as error:
            # 探针回调失败属于非致命错误，记录后继续
            if self.frida_analyzer:
                self.frida_analyzer.hook_results.setdefault("errors", []).append(
                    f"probe callback failed: {error}"
                )
            print(f"[Frida] probe callback failed: {error}")

    def _should_retry_with_spawn(self, result: Dict[str, Any]) -> bool:
        """判断当前 Frida 分析结果是否需要切换模式重试。

        判断依据（满足任一即返回 True）：
          1. 检测到 "Java bridge is not available" 错误
             → attach 时 APP 可能尚未完全初始化 Java 运行时
          2. 检测到 "Java runtime is not available" 错误
             → 同上，说明需要 spawn 模式从零开始加载
          3. 状态消息显示等待 Java Bridge/Runtime 但 Hook 未就绪
             → Java 层尚未准备好，spawn 可能更可靠
          4. 未检测到 Hook 就绪信号但发生了 session detached
             → 会话可能因 APP 进程重启等原因断开

        参数：
            result (Dict[str, Any]): 一轮 Frida 监控的完整结果。

        返回：
            bool: True 表示建议切换模式重试，False 表示结果可信无需重试。
        """
        errors = [str(item) for item in result.get("errors", [])]
        status_messages = [str(item) for item in result.get("status_messages", [])]
        detached_events = [str(item) for item in result.get("detached_events", [])]
        status_blob = "\n".join(status_messages).lower()
        java_hook_ready = "sensitive api hooks ready" in status_blob

        # 条件1：Java 桥不可用 —— 典型 attach 模式下的问题
        if any("Java bridge is not available." in item or "Java runtime is not available." in item for item in errors):
            return True

        # 条件2：仍在等待 Java 运行时但 Hook 未就绪
        if any("waiting for Java bridge" in item or "waiting for Java runtime" in item for item in status_messages):
            return not any("sensitive api hooks ready" in item for item in status_messages)

        # 条件3：未检测到 Hook 就绪且发生了会话分离
        if not java_hook_ready and any("session detached:" in item.lower() for item in detached_events + errors):
            return True

        return False

    def _monitor_with_optional_probe(
        self,
        duration: int,
        probe_callback: Optional[Callable[[], None]] = None,
    ) -> Dict[str, Any]:
        """执行监控并可选地并发运行探针回调。

        并发模型：
          - 主线程：调用 frida_analyzer.monitor()，阻塞等待监控窗口结束
          - 子线程：如果提供了 probe_callback，以守护线程方式并发执行
          - 子线程在 finally 中最多等待 5 秒，防止 monitor() 结束后长时间阻塞

        参数：
            duration (int): 监控时长（秒）。
            probe_callback (Optional[Callable]): 并发执行的探针回调，可为 None。

        返回：
            Dict[str, Any]: 监控结果字典。
        """
        probe_thread: Optional[threading.Thread] = None
        # 如果提供了探针回调，在守护线程中启动
        if probe_callback is not None:
            probe_thread = threading.Thread(
                target=self._run_probe_callback,
                args=(probe_callback,),
                daemon=True,  # 守护线程：主线程退出时自动终止
            )
            probe_thread.start()

        try:
            # 主线程执行监控（阻塞）
            return self.frida_analyzer.monitor(duration)
        except Exception as error:
            # 监控过程中的异常统一捕获并返回
            return {"error": f"Frida analysis failed: {error}"}
        finally:
            # 等待探针线程结束（最多等5秒），确保回调执行完整或安全终止
            if probe_thread is not None and probe_thread.is_alive():
                probe_thread.join(timeout=5)

    def perform_frida_analysis(
        self,
        duration: int = 60,
        probe_callback: Optional[Callable[[], None]] = None,
        spawn_first: bool = False,
    ) -> Dict[str, Any]:
        """执行一次完整的 Frida 分析（核心入口方法）。

        分析流程：
          1. 确定模式尝试顺序：spawn_first=True 时先 spawn 后 attach，反之亦然
          2. 对每种模式：
             a. 重置运行时状态（清空上一轮数据）
             b. 调用 start_hook 启动 Hook 会话
             c. 调用 _monitor_with_optional_probe 进入监控
             d. 调用 _should_retry_with_spawn 判断是否需要切换模式重试
          3. 若所有模式都失败，返回最后一轮的半成品结果

        参数：
            duration (int): 单轮监控窗口长度（秒），默认 60。
            probe_callback (Optional[Callable]): 监控期间并行执行的交互触发函数。
            spawn_first (bool): 是否优先使用 spawn 模式。
              - True：先 spawn 后 attach（适合需要监控启动阶段 API 调用的场景）
              - False：先 attach 后 spawn（默认，attach 通常更快更稳定）

        返回：
            Dict[str, Any]: 最终的分析结果字典。

        设计要点：
          - 每种模式最多尝试一次，即最多两轮
          - 若某轮结果不满足重试条件，直接返回不继续尝试
          - 重试时会打印模式切换信息，便于调试
        """
        if not self.frida_analyzer:
            return {"error": "package name is not set"}

        # 初始兜底结果
        last_result: Dict[str, Any] = {"error": "unable to start Frida hook"}

        # 确定模式尝试顺序
        attempt_order = [True, False] if spawn_first else [False, True]

        for attempt_index, spawn in enumerate(attempt_order):
            # 每轮开始前清空上一轮的残留状态
            self.frida_analyzer.reset_runtime_state()

            # 启动 Hook 会话
            if not self.frida_analyzer.start_hook(spawn=spawn):
                # 启动失败，记录结果并尝试下一模式
                last_result = dict(self.frida_analyzer.hook_results)
                if not last_result.get("errors"):
                    last_result["errors"] = ["unable to start Frida hook"]
                continue

            # 进入监控阶段
            result = self._monitor_with_optional_probe(duration, probe_callback)
            last_result = result

            # 判断是否需要切换模式重试
            should_retry = self._should_retry_with_spawn(result)
            is_last_attempt = attempt_index >= len(attempt_order) - 1

            if should_retry and not is_last_attempt:
                # 需要重试且还有剩余模式可用
                retry_mode = "spawn" if not spawn else "attach"
                print(f"[Frida] session ended before stable capture, retrying with {retry_mode} mode")
                continue

            # 不需要重试，或已经是最后一次尝试
            if not should_retry:
                return result

            # 需要重试但已是最后一次，返回当前结果
            return result

        # 所有模式尝试均失败，返回最后一轮的半成品结果
        return last_result

    def get_frida_summary(self) -> Dict[str, Any]:
        """获取最近一次 Frida 分析的摘要数据。

        返回：
            Dict[str, Any]: 包含统计指标和诊断标志的摘要字典。
            若尚未执行分析，返回空字典。
        """
        if not self.frida_analyzer:
            return {}
        return self.frida_analyzer.get_summary()
