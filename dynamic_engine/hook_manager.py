# -*- coding: utf-8 -*-
# ===========================================================================
# 模块: hook_manager.py
# 描述: Frida Hook 管理器 —— 动态隐私取证引擎的核心执行模块。
#       负责 Frida 设备连接、进程附加/启动、Agent 脚本注入编译、
#       消息回调处理、API 调用记录以及运行结果聚合的全流程自动化。
#       为上层分析模块屏蔽 Frida 底层细节，提供统一的 Hook 生命周期接口。
# ===========================================================================

from __future__ import annotations

import os
import shutil
import threading
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import frida


class HookManager:
    """Frida Hook 管理器 —— 动态隐私取证引擎的底层执行模块。

    核心职责:
    1. Frida 设备自动发现与连接 (支持 remote / local / USB 多种策略)
    2. 目标 APP 进程的附加 (attach) 或启动 (spawn)
    3. TypeScript Agent 脚本编译为可注入的 JavaScript bundle (带缓存)
    4. Agent 注入后的双向消息通信与回调处理
    5. 敏感 API 调用事件的记录、分类、聚合
    6. 运行状态管理 (就绪等待 / 错误收集 / 会话断开处理)

    使用示例:
        manager = HookManager("com.example.app")
        if manager.connect_device():
            success, pid = manager.start(spawn=False)
            if success and manager.load_script("agent/index.ts", pid):
                if manager.wait_for_script_ready(timeout=10):
                    # 等待一定时间收集数据...
                    calls = manager.get_aggregated_calls()
                    manager.stop()
    """

    # ---- 类级共享资源 ----
    # 线程锁: 保护 Agent bundle 编译缓存，防止多线程并发编译同一脚本
    _agent_lock = threading.Lock()
    # bundle 缓存字典: {脚本绝对路径 -> {"mtime": 文件修改时间, "bundle": 编译产物}}
    # 类级共享以避免重复编译，提高批量分析 APP 时的效率
    _bundle_cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, package_name: str):
        """初始化 HookManager 实例。

        参数:
            package_name: 目标 Android APP 的包名，如 "com.tencent.mm"。
                         用于进程枚举匹配和 attach 指定。
        """
        self.package_name = package_name       # 目标 APP 包名
        self.device = None                      # frida.core.Device 实例
        self.session = None                     # frida.core.Session 实例
        self.script = None                      # frida.core.Script 实例 (已注入的 Agent)
        self.is_running = False                 # 当前会话是否处于运行状态
        self.preferred_pids: List[int] = []     # 优先附加的进程号列表

        # ---- 运行过程中逐步填充的数据字段 (由 _on_message 回调驱动) ----
        self.hooked_apis: List[str] = []        # 已触发 Hook 的 API 名称列表 (去重)
        self.call_logs: List[Dict[str, Any]] = []  # 敏感 API 调用的完整原始日志
        self.signal_counts: Dict[str, int] = {}    # 每种 signal_key 的累计命中次数
        self.category_counts: Dict[str, int] = {}  # 每种 category (如 location/network) 的累计命中次数
        self.status_messages: List[str] = []       # Agent 回传的状态/日志消息
        self.errors: List[str] = []                # 运行中收集的错误信息
        self.detached_events: List[str] = []       # Frida 会话断开事件的详细记录

    def set_preferred_pids(self, pids: List[int]) -> None:
        """设置优先附加的进程 PID 列表。

        在启动 Hook 之前调用，告知管理器优先尝试附加这些 PID。
        输入列表会被去重、过滤无效值 (<=0 或非整数)，保留原有顺序。

        参数:
            pids: 整数 PID 列表，可能包含 None 或非整数值 (会被自动过滤)。
        """
        ordered: List[int] = []
        seen = set()  # 用于去重的已见 PID 集合
        for pid in pids or []:
            try:
                normalized = int(pid)  # 统一转为整数类型
            except (TypeError, ValueError):
                continue  # 跳过无法转整数的值
            if normalized <= 0 or normalized in seen:
                continue  # 跳过无效 PID 或重复 PID
            seen.add(normalized)
            ordered.append(normalized)
        self.preferred_pids = ordered

    # ========================================================================
    # Agent 编译与缓存子系统
    # 说明: TypeScript Agent 源码不能直接注入目标进程，需要通过 frida.Compiler
    #       编译为 JavaScript bundle。以下方法实现了完整的编译流水线:
    #       缓存检查 → 项目临时复制 → 依赖安装 → 编译 → 缓存存储。
    # ========================================================================

    @classmethod
    def _get_bundle_mtime(cls, script_path: str) -> float:
        """获取 Agent 源文件及其依赖的最新修改时间，用于判断编译缓存是否仍然有效。

        通过追踪 Agent 入口脚本和 package.json 两个文件的 mtime，
        取最大值作为缓存的版本号。任一文件发生变化，缓存即失效。

        参数:
            script_path: Agent TypeScript 入口文件的路径。
        返回:
            float: 追踪文件中最大的修改时间戳；若文件均不存在则返回 0.0。
        """
        project_root = os.path.dirname(script_path)  # Agent 项目根目录
        tracked_paths = [                             # 需要追踪修改时间的文件列表
            script_path,                              # Agent 入口脚本
            os.path.join(project_root, "package.json"),  # 项目依赖描述文件
        ]
        # 收集所有存在文件的 mtime，不存在的文件跳过
        mtimes = [os.path.getmtime(path) for path in tracked_paths if os.path.exists(path)]
        return max(mtimes) if mtimes else 0.0  # 返回最新的修改时间

    @classmethod
    def _ensure_agent_dependencies(cls, project_root: str) -> None:
        """确保 Frida Agent 编译所需的 node_modules 依赖已经安装到位。

        Frida Agent 编译依赖于 frida-java-bridge 等 npm 包。
        此方法通过 frida 内置的 PackageManager 自动安装，
        类似于在项目目录下执行 npm install。

        参数:
            project_root: 包含 package.json 的 Agent 项目根目录。
        """
        dependency_root = os.path.join(project_root, "node_modules", "frida-java-bridge")
        if os.path.isdir(dependency_root):
            return  # 依赖目录已存在，无需重复安装

        print("[HookManager] installing Frida agent dependencies")
        package_manager = frida.PackageManager()  # Frida 内置的包管理器
        package_manager.install(project_root=project_root)  # 自动安装 package.json 中的依赖

    @classmethod
    def _stage_agent_project(cls, script_path: str) -> Tuple[str, str]:
        """将 Agent 源文件与 node_modules 复制到系统临时目录，建立独立的编译工作区。

        这样做的目的是:
        1. 避免编译产物污染原始项目路径。
        2. 为批量分析多个 APP 时提供隔离的编译环境。
        3. 只复制发生变化的文件，减少不必要的 I/O。

        参数:
            script_path: Agent TypeScript 入口文件的路径。
        返回:
            (临时目录路径, 入口文件名) 的元组。
        """
        source_project_root = os.path.dirname(script_path)
        # 在系统临时目录下创建固定的 staging 目录
        stage_root = os.path.join(tempfile.gettempdir(), "appprivacydetector_frida_agent")
        os.makedirs(stage_root, exist_ok=True)

        # 需要复制到临时目录的文件映射: (临时目录中的文件名, 源文件路径)
        files_to_stage = [
            ("package.json", os.path.join(source_project_root, "package.json")),
            (os.path.basename(script_path), script_path),
        ]
        for staged_name, source_path in files_to_stage:
            staged_path = os.path.join(stage_root, staged_name)
            if not os.path.exists(source_path):
                raise FileNotFoundError(source_path)  # 源文件必须存在
            # 仅在目标不存在 或 源文件比目标更新时才复制 (增量更新策略)
            if (not os.path.exists(staged_path)) or (
                os.path.getmtime(source_path) > os.path.getmtime(staged_path)
            ):
                shutil.copyfile(source_path, staged_path)

        # 如果有已安装的 frida-java-bridge 依赖，也一并复制到临时目录
        source_dependency_root = os.path.join(source_project_root, "node_modules", "frida-java-bridge")
        staged_dependency_root = os.path.join(stage_root, "node_modules", "frida-java-bridge")
        if os.path.exists(os.path.join(source_dependency_root, "package.json")):
            shutil.copytree(source_dependency_root, staged_dependency_root, dirs_exist_ok=True)

        return stage_root, os.path.basename(script_path)

    @classmethod
    def _build_agent_bundle(cls, script_path: str) -> str:
        """编译 TypeScript Agent 源码为可注入目标进程的 JavaScript bundle。

        这是 Agent 注入流程的核心步骤，采用双重检查锁定 (Double-Checked Locking)
        模式保护缓存写入，确保同一脚本在多线程环境下只编译一次。

        编译流程:
        1. 检查类级缓存 _bundle_cache，若命中且源文件未变化则直接返回。
        2. 获取线程锁后再次检查缓存 (避免 TOCTOU 竞态条件)。
        3. 调用 _stage_agent_project 建立编译工作区。
        4. 调用 _ensure_agent_dependencies 安装依赖。
        5. 使用 frida.Compiler.build() 将 TS 源码编译为 JS bundle。
        6. 将编译结果存入缓存，供后续复用。

        参数:
            script_path: Agent TypeScript 入口文件的路径。
        返回:
            str: 编译完成的 JavaScript bundle 字符串，可直接用于 session.create_script()。
        """
        script_path = os.path.abspath(script_path)  # 转为绝对路径，作为缓存键
        source_mtime = cls._get_bundle_mtime(script_path)  # 获取当前源码的修改时间

        # ---- 第一次缓存检查 (无锁快速路径) ----
        cached = cls._bundle_cache.get(script_path)
        if cached and cached.get("mtime") == source_mtime:
            return str(cached["bundle"])  # 缓存命中，直接返回已编译的 bundle

        # ---- 获取线程锁，进入临界区 ----
        with cls._agent_lock:
            # ---- 第二次缓存检查 (加锁后再次确认，防止重复编译) ----
            cached = cls._bundle_cache.get(script_path)
            if cached and cached.get("mtime") == source_mtime:
                return str(cached["bundle"])  # 其他线程已编译完成，直接使用

            # ---- 执行编译流水线 ----
            project_root, entrypoint = cls._stage_agent_project(script_path)  # 建立编译工作区
            cls._ensure_agent_dependencies(project_root)  # 确保 npm 依赖安装
            print(f"[HookManager] compiling Frida agent: {entrypoint}")
            compiler = frida.Compiler()  # Frida 内置的 TypeScript 编译器
            bundle = compiler.build(entrypoint, project_root=project_root, type_check="none")  # 编译
            cls._bundle_cache[script_path] = {"mtime": source_mtime, "bundle": bundle}  # 存入缓存
            return bundle

    # ========================================================================
    # 设备连接与进程管理子系统
    # ========================================================================

    def connect_device(self) -> bool:
        """连接 Frida 设备 —— 动态 Hook 的第一步。

        采用多策略降级机制依次尝试连接，适配模拟器、真机和本地调试等
        不同运行环境。策略按优先级从高到低排列:

        策略1 - remote: 主动连接本地 127.0.0.1:27042 端口 (模拟器常用)
        策略2 - enumerate_remote: 从已发现设备列表中查找 remote 类型设备
        策略3 - enumerate_local: 从已发现设备列表中查找 local 类型设备
        策略4 - usb:     通过 USB 连接真机 (timeout=15s)
        策略5 - enumerate: 查找任意类型的已发现设备
        策略6 - local:   连接本机 Frida server (兜底方案)

        返回:
            bool: 连接成功返回 True，所有策略均失败返回 False。
        """
        # 连接策略列表: 每个元素为 (策略名称, 返回 Device 对象的可调用对象)
        strategies = [
            (
                "remote",
                # 策略1: 直接添加远程设备，端口 27042 是 frida-server 的默认监听端口
                lambda: frida.get_device_manager().add_remote_device("127.0.0.1:27042"),
            ),
            (
                "enumerate_remote",
                # 策略2: 遍历已枚举设备，返回第一个 remote 类型设备
                lambda: next(
                    (
                        device
                        for device in frida.get_device_manager().enumerate_devices()
                        if device.type == "remote"
                    ),
                    None,
                ),
            ),
            (
                "enumerate_local",
                # 策略3: 遍历已枚举设备，返回第一个 local 类型设备
                lambda: next(
                    (
                        device
                        for device in frida.get_device_manager().enumerate_devices()
                        if device.type == "local"
                    ),
                    None,
                ),
            ),
            # 策略4: 通过 USB 连接物理设备，超时 15 秒
            ("usb", lambda: frida.get_usb_device(timeout=15)),
            (
                "enumerate",
                # 策略5: 遍历所有已枚举设备，返回任意类型的第一个设备
                lambda: next(
                    (
                        device
                        for device in frida.get_device_manager().enumerate_devices()
                        if device.type in {"remote", "local", "usb"}
                    ),
                    None,
                ),
            ),
            # 策略6: 连接本地 frida-server (最终兜底)
            ("local", lambda: frida.get_local_device()),
        ]

        # 依次尝试每种连接策略
        for strategy_name, resolver in strategies:
            try:
                device = resolver()
                if device is not None:
                    self.device = device  # 保存设备引用
                    print(f"[HookManager] connected device via {strategy_name}: {device.name}")
                    return True
            except Exception as error:
                # 当前策略失败不中断流程，继续尝试下一种策略
                print(f"[HookManager] device strategy {strategy_name} failed: {error}")

        print("[HookManager] unable to connect to Frida device")
        return False

    def _find_running_pids(self) -> List[int]:
        """枚举当前设备上目标 APP 的正在运行的全部进程号，去重后返回。

        Frida 的 device.enumerate_processes() 返回设备上所有正在运行的进程。
        本方法通过进程的 identifier (包名) 或 name 字段匹配目标 APP，
        支持精确匹配和子串匹配，以覆盖多进程 APP 场景 (如 WebView、推送服务等)。

        返回:
            List[int]: 匹配到的进程 PID 列表 (已去重)。
        """
        if not self.device:
            return []

        matched: List[int] = []
        try:
            for process in self.device.enumerate_processes():
                # 安全获取进程标识符和名称
                identifier = str(getattr(process, "identifier", "") or "")
                name = str(getattr(process, "name", "") or "")
                # 精确匹配: 进程包名或名称与目标 APP 包名完全相同
                if self.package_name == identifier or self.package_name == name:
                    matched.append(int(process.pid))
                # 子串匹配: 用于发现目标 APP 的守护进程、推送服务等子进程
                elif self.package_name in identifier or self.package_name in name:
                    matched.append(int(process.pid))
        except Exception as error:
            print(f"[HookManager] enumerate processes failed: {error}")

        # 去重: 保持首次出现的顺序
        deduplicated: List[int] = []
        seen = set()
        for pid in matched:
            if pid not in seen:
                seen.add(pid)
                deduplicated.append(pid)
        return deduplicated

    def _preferred_attach_attempts(self) -> List[Tuple[str, Any]]:
        """根据 preferred_pids 生成优先附加策略列表。

        将用户预设的 PID 列表包装为 lambda 形式的附加策略，
        供 start() 方法在尝试其他策略之前优先执行。

        返回:
            List[Tuple[str, callable]]: 策略列表，每个元素为 (策略名, lambda)。
        """
        attempts: List[Tuple[str, Any]] = []
        for pid in self.preferred_pids:
            # 使用 lambda 闭包绑定 pid，避免延迟求值问题
            attempts.append((f"preferred_pid:{pid}", lambda pid=pid: self.device.attach(pid)))
        return attempts

    def start(self, spawn: bool = False) -> Tuple[bool, Optional[int]]:
        """启动 Frida 会话 —— 将 APP 进程纳入 Hook 管理。

        这是 connect_device 之后的第二步核心操作。根据 spawn 参数决定采用:
        - attach 模式 (spawn=False): 附加到已在运行的 APP 进程
        - spawn 模式 (spawn=True): 由 Frida 重新启动 APP，在启动瞬间注入

        两种模式都采用多级降级策略链:
        attach 模式: preferred_pids → 包名 attach → 运行中 PID attach → spawn 兜底
        spawn 模式: spawn 启动 → preferred_pids → 包名 attach 兜底 → PID attach

        参数:
            spawn: True=由 Frida 重新启动 APP；False=附加到已运行的 APP。
        返回:
            (成功标志, 进程号): 成功附加返回 (True, pid 或 None)。
                              spawn 模式下 pid 有值；attach 模式下 pid 可能为 None。
        """
        # Step 1: 确保设备已连接
        if not self.device and not self.connect_device():
            return False, None

        # Step 2: 构建策略链 —— 按优先级排列的附加尝试列表
        attach_attempts: List[Tuple[str, Any]] = []
        if not spawn:
            # ---- attach 模式策略链 ----
            # 优先尝试用户指定的 PID
            attach_attempts.extend(self._preferred_attach_attempts())
            # 尝试按包名 attach (Frida 自动选择主进程)
            attach_attempts.append(("package", lambda: self.device.attach(self.package_name)))
            # 遍历设备上所有匹配的运行中进程 (排除已尝试过的 preferred PID)
            for pid in self._find_running_pids():
                if pid in self.preferred_pids:
                    continue
                attach_attempts.append((f"pid:{pid}", lambda pid=pid: self.device.attach(pid)))
            # 最后兜底: 改用 spawn 模式启动 APP
            attach_attempts.append(("spawn_fallback", lambda: ("spawn", self.device.spawn([self.package_name]))))
        else:
            # ---- spawn 模式策略链 ----
            # 优先由 Frida 启动 APP (可获得最早的注入时机)
            attach_attempts.append(("spawn", lambda: ("spawn", self.device.spawn([self.package_name]))))
            # 如果 spawn 失败，退而求其次尝试 preferred PID
            attach_attempts.extend(self._preferred_attach_attempts())
            # 再尝试按包名 attach
            attach_attempts.append(("package_fallback", lambda: self.device.attach(self.package_name)))
            # 最后遍历运行中进程尝试 attach
            for pid in self._find_running_pids():
                if pid in self.preferred_pids:
                    continue
                attach_attempts.append((f"pid:{pid}", lambda pid=pid: self.device.attach(pid)))

        # Step 3: 依次尝试每种策略，第一个成功的即采用
        for attempt_name, attempt in attach_attempts:
            try:
                result = attempt()
                # --- spawn 模式的结果处理 ---
                # spawn 返回的是 ("spawn", pid) 元组，表示进程已启动但处于暂停状态
                if isinstance(result, tuple) and result[0] == "spawn":
                    pid = int(result[1])
                    self.session = self.device.attach(pid)  # Frida 附加到刚启动的进程
                    self.session.on("detached", self._on_detached)  # 注册会话断开回调
                    self.is_running = True
                    print(f"[HookManager] attached by {attempt_name}, pid={pid}")
                    return True, pid

                # --- attach 模式的结果处理 ---
                # 直接返回 Session 对象，表示已成功附加到正在运行的进程
                self.session = result
                self.session.on("detached", self._on_detached)  # 注册会话断开回调
                self.is_running = True
                print(f"[HookManager] attached by {attempt_name}")
                return True, None
            except Exception as error:
                # 当前策略失败，继续尝试下一个
                print(f"[HookManager] attach strategy {attempt_name} failed: {error}")

        print("[HookManager] all attach strategies failed")
        return False, None

    def load_script(self, js_path: str, pid: Optional[int] = None) -> bool:
        """编译并注入 Agent Hook 脚本到目标进程 —— 动态 Hook 的第三步。

        这是连接设备、启动会话之后的最后一步关键操作。流程如下:
        1. 调用 _build_agent_bundle 将 TypeScript Agent 编译为 JavaScript bundle
        2. 通过 session.create_script() 将 JS 代码注入目标进程
        3. 注册 on("message") 回调，建立双向通信管道
        4. 调用 script.load() 激活 Hook 代码
        5. 若为 spawn 模式 (pid 不为 None)，调用 device.resume(pid) 恢复进程执行

        参数:
            js_path: Agent TypeScript 入口源码文件路径。
            pid:    spawn 模式下的进程号，用于注入后恢复进程。
                   attach 模式下为 None，无需恢复。
        返回:
            bool: 脚本注入成功返回 True。
        """
        if not self.session:
            print("[HookManager] session not established")
            return False

        try:
            # Step 1: 编译 TypeScript Agent 源码为 JavaScript bundle
            bundle = self._build_agent_bundle(js_path)
            # Step 2: 创建 Frida Script 对象，将 JS bundle 注入目标进程
            self.script = self.session.create_script(bundle, name=os.path.basename(js_path))
            # Step 3: 注册消息回调 —— Agent 通过 send() 发送的消息由 _on_message 处理
            self.script.on("message", self._on_message)
            # Step 4: 加载脚本，激活所有 Hook 逻辑
            self.script.load()

            # Step 5: spawn 模式下恢复进程执行
            # spawn 启动时进程处于暂停状态，需要在注入脚本后恢复才能正常运行
            if pid is not None:
                self.device.resume(pid)
                print(f"[HookManager] resumed spawned process: {pid}")

            print(f"[HookManager] hook script loaded: {js_path}")
            return True
        except Exception as error:
            print(f"[HookManager] load script failed: {error}")
            return False

    def _on_detached(self, reason: Any, crash: Any) -> None:
        """Frida 会话断开回调 —— 当目标进程崩溃或被强制终止时触发。

        此回调由 Frida 在会话意外断开时调用，不可由用户主动触发。
        接收两个参数: reason (断开原因) 和 crash (崩溃详情)。
        收集的信息存入 detached_events 和 errors 列表，供上层诊断。

        参数:
            reason: Frida 提供的断开原因描述。
            crash:  崩溃详情 (如 Native crash 堆栈)，若无则为空。
        """
        detached_reason = str(reason or "unknown")
        crash_text = str(crash or "").strip()
        message = f"session detached: reason={detached_reason}"
        if crash_text:
            message += f", crash={crash_text}"
        self.detached_events.append(message)  # 记录断开事件
        self.errors.append(message)           # 同时作为错误收集
        print(f"[HookManager] {message}")

    def _record_api_call(self, payload: Dict[str, Any]) -> None:
        """记录 Agent 回传的敏感 API 调用事件 —— 核心数据采集入口。

        此方法是所有动态取证数据的统一入口。Agent 端通过 send() 回传
        每次敏感 API 调用事件，本方法负责:
        1. 解析 payload 中的 api、signal_key、category 等关键字段
        2. 构建标准化的日志条目 (entry)
        3. 保留 payload 中的未知扩展字段 (前向兼容)
        4. 更新 hooked_apis、signal_counts、category_counts 三个统计维度

        参数:
            payload: Agent 通过 send() 回传的事件字典，包含以下核心字段:
                - api:        被调用的 API 名称 (如 "android.location.LocationManager.getLastKnownLocation")
                - signal_key: 信号键 (用于跨 API 聚合同一隐私行为，如 "获取位置信息")
                - category:   隐私类别 (如 "location", "network", "identifier", "anti_analysis")
                - timestamp:  调用发生的时间戳
                - description: 人类可读的描述信息
                - args:       API 调用参数列表
                - return_value: API 返回值
                - uri:        相关的 URI (如 ContentResolver 查询的 URI)
                - stack:      Java 调用栈字符串
        """
        # 提取并清洗核心字段
        api_name = str(payload.get("api") or "").strip()
        # signal_key 优先取 payload 中的值，没有则降级为 api_name
        signal_key = str(payload.get("signal_key") or api_name or "unknown").strip()
        # category 默认值为 "other"
        category = str(payload.get("category") or "other").strip()

        # 构建标准化的日志条目 —— 包含所有已知字段的默认值处理
        entry: Dict[str, Any] = {
            "timestamp": payload.get("timestamp") or time.time(),
            "api": api_name,
            "signal_key": signal_key,
            "category": category,
            "description": str(payload.get("description") or signal_key),
            "args": payload.get("args") or [],
            "return_value": payload.get("return_value"),
            "uri": payload.get("uri", ""),
            "stack": payload.get("stack", ""),
        }
        # 前向兼容: 将 payload 中未知的扩展字段也保留到 entry 中
        for key, value in payload.items():
            if key in {
                "type",
                "timestamp",
                "api",
                "signal_key",
                "category",
                "description",
                "args",
                "return_value",
                "uri",
                "stack",
            }:
                continue  # 跳过已处理的已知字段
            entry[key] = value

        # 追加到日志列表
        self.call_logs.append(entry)

        # 维护 hooked_apis 去重列表
        if api_name and api_name not in self.hooked_apis:
            self.hooked_apis.append(api_name)

        # 递增信号键和类别的命中计数
        self.signal_counts[signal_key] = self.signal_counts.get(signal_key, 0) + 1
        self.category_counts[category] = self.category_counts.get(category, 0) + 1

    # ========================================================================
    # 消息处理与事件记录子系统
    # ========================================================================

    def _record_native_guard_status(self, status: str) -> None:
        """处理 Agent 回传的 Frida Native Guard 状态消息。

        Native Guard 是 Frida 内置的 Native 层反调试/反检测守护模块。
        Agent 启动完成后会回传安装了哪些守护组件，本方法将这些信息
        以标准 api_call 格式记录到 call_logs 中 (归类为 anti_analysis)。

        支持的守护类型:
        1. native anti-debug:      通过 /proc/self/status 的 TracerPid 检测调试器
        2. native root path guard:  隐藏常见的 root 特征路径
        3. native system property guard: 修改系统属性以隐藏调试痕迹

        参数:
            status: Agent 回传的守护状态字符串 (如 "native anti-debug installed")。
        """
        status_lower = status.lower()
        # 守护类型映射: (匹配标记, API 名称, 描述)
        guard_map = [
            ("native anti-debug installed", "Frida.nativeGuard.tracerPid", "native anti-debug guard installed"),
            ("native root path guard installed", "Frida.nativeGuard.rootPath", "native root path guard installed"),
            ("native system property guard installed", "Frida.nativeGuard.systemProperty", "native system property guard installed"),
        ]
        for marker, api_name, description in guard_map:
            if marker not in status_lower:
                continue  # 不匹配当前守护类型，检查下一个
            # 匹配成功: 构造标准 api_call 事件并记录
            self._record_api_call(
                {
                    "timestamp": time.time(),
                    "api": api_name,
                    "signal_key": "antiAnalysisProbe",  # 统一归属反分析探针类别
                    "category": "anti_analysis",
                    "description": description,
                    "args": [status],
                    "return_value": "installed",
                    "stack": "",
                    "source": "frida_native_guard",  # 标记来源为 Native Guard
                }
            )
            break  # 一次只匹配一种守护类型 (status 消息是单独的)

    def _record_appscan_style_event(self, payload: Dict[str, Any]) -> None:
        """处理 AppScan 风格的 method_result / request_result 事件。

        某些 Agent 实现采用与标准 api_call 不同的数据格式 (如 AppScan 项目)。
        本方法作为兼容性适配器，将非标准格式的 payload 转换为标准 api_call 格式，
        确保不同的 Agent 实现都能正确集成到统一的数据收集中。

        参数:
            payload: AppScan 风格的事件字典，使用 action/messages/arg/stacks 等字段。
        """
        # 提取 AppScan 特有字段映射
        action = str(payload.get("action") or "runtime_probe").strip()  # 作为 category
        message = str(payload.get("messages") or action).strip()         # 作为 description 和 api
        args_text = str(payload.get("arg") or "").strip()                # 参数文本
        stack_text = str(payload.get("stacks") or "").strip()            # 调用栈文本
        # 清理消息中的换行符，作为 API 名称使用
        api_name = message.replace("\r", " ").replace("\n", " ").strip()

        # 转发到标准记录方法
        self._record_api_call(
            {
                "timestamp": payload.get("time") or time.time(),
                "api": api_name,
                "signal_key": api_name,
                "category": action,
                "description": message,
                "args": [args_text] if args_text else [],
                "return_value": "",
                "stack": stack_text,
            }
        )

    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        """Frida 消息回调 —— 所有 Agent 回传数据的统一入口。

        这是整个动态取证引擎最核心的回调方法。Frida 的 script.on("message")
        机制使得 Agent 脚本可以通过 send() 向宿主机回传数据。本方法根据
        消息类型和 payload 结构，将消息分发到对应的处理方法:

        消息类型 "send" (Agent 主动发送):
        ├── payload.type == "api_call" 或含 "api" 字段 → _record_api_call()
        ├── payload.type == "method_result"/"request_result" → _record_appscan_style_event()
        ├── payload.type == "status" → 记录状态 + 检查 native guard
        ├── payload.type == "error"   → 记录错误
        └── payload 为非字典类型     → 作为状态消息记录

        消息类型 "error" (Frida 脚本运行时错误):
        └── 提取 stack/description，记录到 errors 列表

        参数:
            message: Frida 回传的消息字典，包含 type 和 payload 字段。
            data:   二进制数据负载 (通常为 None，仅在 Agent 使用 send(data) 时有值)。
        """
        message_type = message.get("type")
        if message_type == "send":
            # ---- Agent 主动发送的消息 ----
            payload = message.get("payload")
            if isinstance(payload, dict):
                payload_type = str(payload.get("type") or "").strip()
                # 情况1: 标准 API 调用事件 或 含有 api 字段的事件
                if payload_type == "api_call" or payload.get("api"):
                    self._record_api_call(payload)
                # 情况2: AppScan 风格的 method_result / request_result 事件
                elif payload_type in {"method_result", "request_result"}:
                    self._record_appscan_style_event(payload)
                # 情况3: Agent 状态报告 (如 "sensitive api hooks ready")
                elif payload_type == "status":
                    status = str(payload.get("message") or "").strip()
                    if status:
                        self.status_messages.append(status)
                        self._record_native_guard_status(status)  # 检查是否是 native guard 状态
                # 情况4: Agent 内部错误报告
                elif payload_type == "error":
                    error_message = str(payload.get("message") or "").strip()
                    if error_message:
                        self.errors.append(error_message)
            elif payload:
                # payload 存在但不是字典 (如纯字符串)，作为状态消息处理
                self.status_messages.append(str(payload))
        elif message_type == "error":
            # ---- Frida 脚本运行时错误 (可导致 Hook 失效) ----
            stack = str(message.get("stack") or message.get("description") or "").strip()
            if stack:
                self.errors.append(stack)
                print(f"[HookManager] script error: {stack}")

    # ========================================================================
    # 数据获取与状态查询接口 (供上层分析/UI模块调用)
    # ========================================================================

    def get_hooked_apis(self) -> List[str]:
        """返回所有已被触发 Hook 的 API 名称列表 (去重)。

        与 call_logs 的区别: 这里返回的是聚合去重后的 API 名称集合，
        用于快速了解 APP 触发了哪些隐私 API。顺序为首次触发顺序。
        """
        return list(self.hooked_apis)

    def get_call_logs(self) -> List[Dict[str, Any]]:
        """返回敏感 API 调用的完整原始日志列表。

        每条日志都是 _record_api_call() 构建的完整字典，
        包含 timestamp、api、signal_key、category、args、stack 等字段。
        返回值是 copy，避免外部修改影响内部状态。
        """
        return list(self.call_logs)

    def get_signal_counts(self) -> Dict[str, int]:
        """返回每种 signal_key 的累计调用次数。

        signal_key 将不同但同类的 API 归为一个信号 (如多个获取位置的方法
        都归为"获取位置信息")，此方法返回各信号的命中频率。
        返回值是 copy，避免外部修改影响内部状态。
        """
        return dict(self.signal_counts)

    def get_category_counts(self) -> Dict[str, int]:
        """返回每种 privacy category 的累计调用次数。

        category 是比 signal_key 更粗粒度的分类维度，
        如 "location"、"network"、"identifier" 等。
        返回值是 copy，避免外部修改影响内部状态。
        """
        return dict(self.category_counts)

    def get_status_messages(self) -> List[str]:
        """返回 Agent 回传的全部状态/日志消息。

        主要用于调试和确认 Agent 启动状态，
        如 "sensitive api hooks ready" 表示 Hook 初始化完成。
        返回值是 copy，避免外部修改影响内部状态。
        """
        return list(self.status_messages)

    def get_errors(self) -> List[str]:
        """返回运行过程中收集的全部错误信息列表。

        错误来源包括: Agent 脚本运行时错误、会话断开事件、
        Agent 报告的内部错误等。此方法用于故障诊断和结果可靠性评估。
        返回值是 copy，避免外部修改影响内部状态。
        """
        return list(self.errors)

    def get_detached_events(self) -> List[str]:
        """返回全部 Frida 会话断开事件的详细记录。

        每次 session detached 触发时记录的信息包含断开原因和崩溃详情。
        可用于判断 APP 是否在 Hook 期间异常退出或被反调试机制终止。
        返回值是 copy，避免外部修改影响内部状态。
        """
        return list(self.detached_events)

    def wait_for_script_ready(self, timeout: int = 8) -> bool:
        """阻塞等待 Agent 脚本初始化完成。

        Agent 脚本注入后需要一定时间完成 Java 桥接和 Hook 注册。
        本方法通过轮询 status_messages 和 errors 来判断 Agent 是否就绪:

        就绪条件: 收到 "sensitive api hooks ready" 状态消息
        失败条件:
        - "hook bootstrap failed" 或 "java.perform failed" 错误
        - "java runtime is not available" 错误 (目标进程无 Java 运行环境)
        - 检测到 session detached 事件 (进程可能崩溃或被终止)

        参数:
            timeout: 最大等待时间，单位秒 (默认 8 秒，最小值 1 秒)。
        返回:
            bool: Agent 就绪返回 True；超时或失败返回 False。
                  超时时若至少检测到 "java bridge ready" 也算部分就绪。
        """
        started_at = time.time()
        while time.time() - started_at < max(1, int(timeout)):
            # 将所有状态消息和错误消息拼接为小写文本，方便快速搜索关键字
            status_blob = "\n".join(self.status_messages).lower()
            error_blob = "\n".join(self.errors).lower()
            # 就绪信号: Agent 报告所有 Hook 已注册完成
            if "sensitive api hooks ready" in status_blob:
                return True
            # 快速失败: Hook 引导过程出错
            if "hook bootstrap failed" in error_blob or "java.perform failed" in error_blob:
                return False
            # 快速失败: 目标进程无 Java 运行时 (可能是纯 Native 进程)
            if "java runtime is not available" in error_blob:
                return False
            # 快速失败: 会话已断开
            if any("session detached:" in item.lower() for item in self.detached_events):
                return False
            time.sleep(0.2)  # 轮询间隔 200ms

        # 超时兜底: 即使未收到完整就绪信号，Java 桥就绪也视为可用
        return "java bridge ready" in "\n".join(self.status_messages).lower()

    def get_aggregated_calls(self) -> List[Dict[str, Any]]:
        """将原始 call_logs 按 signal_key 聚合并排序，生成结构化分析结果。

        聚合逻辑:
        1. 按 signal_key 分组，将同类的 API 调用合并。
        2. 统计每组的调用次数 (count)。
        3. 收集每组中涉及的具体 API 名称 (sample_apis)。
        4. 按调用次数降序排列 (次数相同按 signal_key 字母序)。

        这是上层分析模块的主要数据来源，聚合后的数据适合直接用于
        生成隐私报告或可视化图表。

        返回:
            List[Dict]: 聚合结果列表，每个元素包含:
                - signal_key:  信号键
                - category:    隐私类别
                - description: 人类可读描述
                - count:       调用次数
                - sample_apis: 涉及的具体 API 名称列表
        """
        grouped: Dict[str, Dict[str, Any]] = {}
        for log in self.call_logs:
            # 确定分组的 signal_key
            signal_key = str(log.get("signal_key") or log.get("api") or "unknown")
            # 该 signal_key 首次出现时初始化分组条目
            if signal_key not in grouped:
                grouped[signal_key] = {
                    "signal_key": signal_key,
                    "category": log.get("category", "other"),
                    "description": log.get("description", signal_key),
                    "count": 0,
                    "sample_apis": [],
                }

            grouped_entry = grouped[signal_key]
            grouped_entry["count"] += 1  # 累加调用计数
            # 收集去重后的 API 名称作为样本
            api_name = str(log.get("api") or "")
            if api_name and api_name not in grouped_entry["sample_apis"]:
                grouped_entry["sample_apis"].append(api_name)

        # 按调用次数降序排列，次数相同按 signal_key 升序
        return sorted(grouped.values(), key=lambda item: (-item["count"], item["signal_key"]))

    def stop(self) -> None:
        """停止 Hook —— 优雅地卸载脚本并断开 Frida 会话。

        执行顺序:
        1. 卸载已注入的 Agent 脚本 (script.unload())
        2. 断开 Frida 会话 (session.detach())
        3. 将 is_running 标志置为 False

        每一步都在 try-finally 中执行，确保即使某步失败也不会影响后续清理。
        """
        # Step 1: 卸载 Agent 脚本
        if self.script:
            try:
                self.script.unload()  # 通知 Frida 移除注入的脚本
            except Exception as error:
                print(f"[HookManager] unload script failed: {error}")
            finally:
                self.script = None  # 无论成败都清除引用

        # Step 2: 断开 Frida 会话
        if self.session:
            try:
                self.session.detach()  # 断开与目标进程的连接
            except Exception as error:
                print(f"[HookManager] detach session failed: {error}")
            finally:
                self.session = None  # 无论成败都清除引用

        self.is_running = False

    def is_connected(self) -> bool:
        """检查当前是否已成功连接到 Frida 设备。

        返回:
            bool: device 实例存在则返回 True。
        """
        return self.device is not None
