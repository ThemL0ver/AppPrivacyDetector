# -*- coding: utf-8 -*-
"""
模块：Flask Web 仪表板（App Privacy Detector Dashboard）

功能概述：
    本模块是 Android 应用隐私检测系统的 Web 可视化后端。它读取
    integrated_analysis_report.json（综合分析报告），并通过 RESTful API
    将静态分析、动态分析、权限风险等数据提供给前端页面（index.html），
    支撑"公众健康卡片"与"公安研判看板"两大可视化场景。

技术栈：Flask（Python Web 微框架）+ JSON 文件数据源

接口列表：
    GET  /                              首页（渲染模板）
    GET  /api/reload                    强制重新加载数据
    GET  /api/summary                   总体风险概览
    GET  /api/apps                      所有应用摘要列表
    GET  /api/app/<package_name>        单个应用详情
    GET  /api/permissions               权限频次统计
    GET  /api/permission-risks          权限风险分档
    GET  /api/app/<package_name>/dynamic 动态分析详情

作者：AppPrivacyDetector Team
"""

from flask import Flask, jsonify, render_template
import json
import math
import os


# ============================================================================
# 第一部分：路径配置 —— 自动定位模板目录与分析结果目录
# ============================================================================

# 获取当前脚本所在目录的绝对路径，作为后续路径解析的基准
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# 优先尝试 web_dashboard/templates 子目录作为模板文件夹
TEMPLATE_DIR = os.path.join(CURRENT_DIR, "templates")
# 若 templates 目录不存在，但当前目录下直接有 index.html，
# 则将当前目录本身作为模板目录（兼容扁平目录部署方式）
if not os.path.exists(TEMPLATE_DIR) and os.path.exists(os.path.join(CURRENT_DIR, "index.html")):
    TEMPLATE_DIR = CURRENT_DIR

# 创建 Flask 应用实例，指定模板文件夹路径
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# 全局内存缓存：避免每次 API 请求都重新读取磁盘上的 JSON 报告
_cached_report = None


def get_results_dir():
    """获取综合分析报告所在的结果目录。

    按优先级依次尝试以下三个路径，返回第一个确实存在的目录：
        1. web_dashboard/results/
        2. 项目根目录下的 results/
        3. 当前工作目录下的 results/

    若以上路径均不存在，则默认返回项目根目录的 results/（供后续错误提示使用）。

    返回：
        str: 结果目录的绝对路径。
    """
    # 按优先级列出所有可能的结果目录路径
    possible_paths = [
        os.path.join(CURRENT_DIR, "results"),           # web_dashboard/results/
        os.path.join(CURRENT_DIR, "..", "results"),     # 项目根目录/results/
        os.path.join(os.getcwd(), "results"),            # 当前工作目录/results/
    ]
    # 遍历候选路径，找到第一个真实存在的目录即返回
    for path in possible_paths:
        if os.path.exists(path) and os.path.isdir(path):
            return os.path.abspath(path)
    # 兜底：返回项目根目录下的 results 路径
    return os.path.abspath(os.path.join(CURRENT_DIR, "..", "results"))


# 全局变量：在模块加载时确定结果目录，后续所有函数共用
RESULTS_DIR = get_results_dir()


# ============================================================================
# 第二部分：工具函数 —— 数据处理与格式化
# ============================================================================

def _round_score(value):
    """将评分值四舍五入取整，避免前端展示出现冗长的浮点尾数。

    参数：
        value: 待取整的数值（可以是整数、浮点数或可转换为浮点数的字符串）。

    返回：
        int: 四舍五入后的整数评分；转换失败时返回 0。
    """
    try:
        # math.floor(value + 0.5) 等价于四舍五入（兼容 Python 各版本）
        return int(math.floor(float(value) + 0.5))
    except (TypeError, ValueError):
        # 处理 None、非数字字符串等异常输入
        return 0


def _normalize_risk_assessment(risk_assessment):
    """对单条风险评估记录中的三项评分（静态分、动态分、总分）做规范化取整。

    该函数会原地修改传入的字典，对 static_score、dynamic_score、total_score
    三个字段统一进行四舍五入处理。

    参数：
        risk_assessment (dict): 单条风险评估字典，包含各评分字段。
    """
    # 防御性检查：确保输入是字典类型
    if not isinstance(risk_assessment, dict):
        return
    # 对三个评分字段逐一取整
    for score_key in ("static_score", "dynamic_score", "total_score"):
        if score_key in risk_assessment:
            risk_assessment[score_key] = _round_score(risk_assessment.get(score_key))


def _normalize_report_scores(report):
    """对完整分析报告中的平均分与每条应用结果都执行分数规范化。

    处理内容：
        1. average_scores 中的三项平均分取整
        2. results 列表中每条记录的 risk_assessment 分取整

    参数：
        report (dict): 完整的综合分析报告字典。

    返回：
        dict: 规范化后的报告字典（在原对象上原地修改）。
    """
    # 防御性检查
    if not isinstance(report, dict):
        return report

    # 处理全局平均分：对报告级别的平均静态/动态/总分取整
    average_scores = report.get("average_scores")
    if isinstance(average_scores, dict):
        for score_key in ("static_score", "dynamic_score", "total_score"):
            if score_key in average_scores:
                average_scores[score_key] = _round_score(average_scores.get(score_key))

    # 处理每条应用结果：对其中的风险评估评分取整
    results = report.get("results")
    if isinstance(results, list):
        for result in results:
            if isinstance(result, dict):
                _normalize_risk_assessment(result.get("risk_assessment"))

    return report


def _count_collection(value):
    """统计容器类型的元素数量，用于计算敏感 API 调用数、权限数等。

    参数：
        value: 待统计的值，支持 dict、list 类型。

    返回：
        int: dict 的键数或 list 的元素数；其他类型统一返回 0。
    """
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 0


def _get_display_apk_name(result):
    """从分析结果中提取用于前端展示的 APK 文件名。

    优先级：display_apk_file > apk_file > artifact_apk_file > "unknown"

    参数：
        result (dict): 单条分析结果字典。

    返回：
        str: 用于展示的 APK 文件名。
    """
    if not isinstance(result, dict):
        return "unknown"
    # 按优先级依次尝试三个可能的字段名
    return (
        result.get("display_apk_file")
        or result.get("apk_file")
        or result.get("artifact_apk_file")
        or "unknown"
    )


def _get_frida_summary(dynamic_analysis):
    """从动态分析结果中提取 Frida Hook 框架的运行摘要信息。

    Frida 摘要中包含 Hook 到的 API 调用总数、唯一 API 数量等关键指标。

    参数：
        dynamic_analysis (dict): 动态分析结果字典。

    返回：
        dict: Frida 摘要字典；若数据缺失则返回空字典 {}。
    """
    # 层层防御性检查，确保嵌套结构存在
    if not isinstance(dynamic_analysis, dict):
        return {}
    frida_analysis = dynamic_analysis.get("frida_analysis")
    if not isinstance(frida_analysis, dict):
        return {}
    summary = frida_analysis.get("summary")
    return summary if isinstance(summary, dict) else {}


def _get_sensitive_api_call_count(dynamic_analysis):
    """从动态分析结果中获取敏感 API 调用数量（取较大值），用于前端展示。

    逻辑优先级：
        1. 直接统计 sensitive_api_calls 和 frida_sensitive_api_calls 的长度，取较大者
        2. 若以上均为空，则从 Frida 摘要中读取 unique_apis 或 total_api_calls

    参数：
        dynamic_analysis (dict): 动态分析结果字典。

    返回：
        int: 敏感 API 调用数量。
    """
    if not isinstance(dynamic_analysis, dict):
        return 0

    # 第一优先级：直接统计两个来源的敏感 API 调用数，取最大值
    direct_count = _count_collection(dynamic_analysis.get("sensitive_api_calls"))
    frida_count = _count_collection(dynamic_analysis.get("frida_sensitive_api_calls"))
    if direct_count or frida_count:
        return max(direct_count, frida_count)

    # 第二优先级：从 Frida 摘要中间接获取
    frida_summary = _get_frida_summary(dynamic_analysis)
    return _round_score(frida_summary.get("unique_apis") or frida_summary.get("total_api_calls") or 0)


def _get_permission_risk_bucket(permission_detail):
    """将权限风险等级字符串映射为统一的四档分类（L/M/H/VH），用于按档位聚合展示。

    支持的风险等级表示方式：
        - 英文标识：low / medium / high / very_high
        - 中文描述：低 / 中 / 高 / 极高 及其变体格式

    参数：
        permission_detail (dict): 单条权限详情字典，需包含 main_risk_level 或 risk_level 字段。

    返回：
        str | None: "low", "medium", "high", "very_high" 之一；无法识别时返回 None。
    """
    if not isinstance(permission_detail, dict):
        return None

    # 提取原始风险等级字符串，统一转为小写并去除首尾空白
    raw_level = str(
        permission_detail.get("main_risk_level")
        or permission_detail.get("risk_level")
        or ""
    ).strip().lower()

    # 无法识别时返回 None
    if not raw_level:
        return None

    # 极高风险：英文 very_high 或中文"极高"、纯"高"（在中文语境下可能表示最高风险）
    if raw_level == "very_high" or "极高" in raw_level or raw_level == "高" or raw_level.startswith("高（"):
        return "very_high"

    # 高风险：英文 high 或中文"中高"
    if raw_level == "high" or "中高" in raw_level:
        return "high"

    # 中风险：英文 medium 或中文"中"
    if raw_level == "medium" or raw_level == "中" or raw_level.startswith("中（"):
        return "medium"

    # 低风险：英文 low 或中文"低"
    if raw_level == "low" or raw_level == "低" or raw_level.startswith("低（"):
        return "low"

    # 兜底：未知等级返回 None，前端将不统计
    return None


# ============================================================================
# 第三部分：数据加载 —— JSON 报告读取与缓存
# ============================================================================

def load_analysis_results(force_reload=False):
    """加载并缓存综合分析报告（integrated_analysis_report.json）。

    首次调用时从磁盘读取 JSON 文件并存入全局缓存 _cached_report；
    后续调用直接返回缓存内容，避免重复 I/O 操作。

    参数：
        force_reload (bool): 是否强制重新读取。设为 True 时忽略缓存，重新解析文件。

    返回：
        dict | None: 规范化后的报告字典；若文件不存在或解析失败则返回 None。
    """
    global _cached_report
    # 若已有缓存且未被要求强制刷新，直接返回缓存
    if _cached_report is not None and not force_reload:
        return _cached_report

    # 拼接报告文件完整路径
    report_file = os.path.join(RESULTS_DIR, "integrated_analysis_report.json")
    if os.path.exists(report_file):
        try:
            # 以 UTF-8 编码读取 JSON，加载后立即对分数做规范化处理
            with open(report_file, "r", encoding="utf-8") as file:
                _cached_report = _normalize_report_scores(json.load(file))
                return _cached_report
        except Exception as error:
            # 打印错误信息供调试，但不中断程序运行
            print(f"[-] Failed to load report: {error}")
    else:
        print(f"[-] Report not found: {report_file}")
    return None


# ============================================================================
# 第四部分：Flask 路由 —— RESTful API 接口
# ============================================================================

# --- 4.1 首页路由 ---

@app.route("/")
def index():
    """渲染前端仪表板首页。

    返回：
        渲染后的 index.html 页面（使用 Jinja2 模板引擎）。
    """
    return render_template("index.html")


# --- 4.2 数据重载接口 ---

@app.route("/api/reload")
def reload_data():
    """强制重新加载 JSON 报告，清除内存缓存。

    适用于手动更新报告文件后无需重启 Flask 服务即可刷新数据。

    返回：
        JSON 响应：{"status": "success", "message": "Data reloaded"}
    """
    # 调用 load_analysis_results 并强制绕过缓存
    load_analysis_results(force_reload=True)
    return jsonify({"status": "success", "message": "Data reloaded"})


# --- 4.3 总体概览接口 ---

@app.route("/api/summary")
def get_summary():
    """返回分析总体概览：样本总量与高/中/低三个风险等级的 App 数量。

    前端通过该接口渲染首页顶部的统计卡片（总分析数、高风险数、中风险数、低风险数）。

    返回：
        JSON 响应，包含以下字段：
            - total_analyzed (int): 分析的样本总数
            - high_risk (int): 高风险应用数量
            - medium_risk (int): 中风险应用数量
            - low_risk (int): 低风险应用数量
        若数据不可用则返回 {"error": "No data available"}。
    """
    report = load_analysis_results()
    if report:
        # 从报告中提取各项统计指标
        return jsonify(
            {
                "total_analyzed": report.get("total_analyzed", 0),
                "high_risk": len(report.get("high_risk_apps", [])),
                "medium_risk": len(report.get("medium_risk_apps", [])),
                "low_risk": len(report.get("low_risk_apps", [])),
            }
        )
    return jsonify({"error": "No data available"})


# --- 4.4 应用列表接口 ---

@app.route("/api/apps")
def get_apps():
    """返回所有应用的精简摘要数据，供前端渲染应用列表卡片。

    该接口会将完整报告中的每条结果压缩为卡片视图所需的字段，包括：
        - 应用展示名称、包名
        - 风险等级与评分（静态分、动态分、总分）
        - 权限统计（总权限数、危险权限数、高风险权限数）
        - 敏感 API 调用次数
        - Frida 框架运行状态

    返回：
        JSON 数组，每个元素为一个应用的摘要字典；无数据时返回空数组 []。
    """
    report = load_analysis_results()
    if report and "results" in report:
        apps = []
        # 遍历每条分析结果，提取前端需要的字段
        for result in report["results"]:
            # 安全获取嵌套结构，避免 KeyError
            static_analysis = result.get("static_analysis") or {}
            dynamic_analysis = result.get("dynamic_analysis") or {}
            risk_assessment = result.get("risk_assessment") or {}

            # 权限分析子结构
            perm_analysis = static_analysis.get("permission_analysis", {})
            high_risk_permissions = perm_analysis.get("high_risk_permissions", [])

            # Frida 动态 Hook 摘要
            frida_summary = _get_frida_summary(dynamic_analysis)

            # 组装单条应用摘要数据
            apps.append(
                {
                    "apk_file": _get_display_apk_name(result),
                    "artifact_apk_file": result.get("artifact_apk_file") or result.get("apk_file"),
                    # 应用名称优先级：result.app_name > static_analysis.app_name > apk_file
                    "app_name": result.get("app_name")
                    or static_analysis.get("app_name")
                    or result.get("apk_file", "unknown"),
                    "package_name": result.get("package_name", "unknown"),
                    # 风险等级与标签
                    "risk_level": risk_assessment.get("risk_level", "low"),
                    "risk_label": risk_assessment.get("risk_label"),
                    # 三项评分（均已取整）
                    "risk_score": _round_score(risk_assessment.get("total_score", 0)),
                    "static_risk_score": _round_score(risk_assessment.get("static_score", 0)),
                    "dynamic_risk_score": _round_score(risk_assessment.get("dynamic_score", 0)),
                    # 权限统计
                    "permissions_count": static_analysis.get("total_permissions", 0),
                    "dangerous_permissions": len(perm_analysis.get("dangerous_permissions", [])),
                    "high_risk_permissions": len(high_risk_permissions),
                    # 敏感 API 调用统计
                    "sensitive_api_calls": _get_sensitive_api_call_count(dynamic_analysis),
                    "frida_api_calls": _round_score(frida_summary.get("total_api_calls", 0)),
                    # Frida 运行状态（如 attached/detached/error）
                    "frida_state": (dynamic_analysis.get("frida_analysis") or {}).get("state"),
                    # 检测到的风险发现项列表
                    "detected_findings": risk_assessment.get("detected_findings", []),
                }
            )
        return jsonify(apps)
    # 无数据时返回空数组，前端可据此展示"暂无数据"
    return jsonify([])


# --- 4.5 单个应用详情接口 ---

@app.route("/api/app/<package_name>")
def get_app_detail(package_name):
    """按 Android 包名返回单个应用的完整分析详情。

    前端点击应用卡片后通过该接口获取该应用的全部静态分析、动态分析和
    风险评估详情，用于渲染详情面板。

    参数：
        package_name (str): URL 路径参数，Android 应用的唯一包名（如 com.example.app）。

    返回：
        JSON 对象，包含该应用的完整分析结果；若未匹配到则返回
        {"error": "App not found"}。
    """
    report = load_analysis_results()
    if report and "results" in report:
        # 遍历结果列表，按包名精确匹配
        for result in report["results"]:
            if result.get("package_name") == package_name:
                # 对匹配到的结果再次做评分规范化（确保展示数据整洁）
                _normalize_risk_assessment(result.get("risk_assessment"))
                # 若缺失动态分析字段，补充一个空结构以避免前端渲染错误
                if "dynamic_analysis" not in result:
                    result["dynamic_analysis"] = {"monitoring_result": {"api_calls": []}}
                return jsonify(result)
    # 404 语义：未找到对应包名的应用
    return jsonify({"error": "App not found"})


# --- 4.6 权限频次统计接口 ---

@app.route("/api/permissions")
def get_permissions():
    """统计所有样本声明的全部权限，按出现频次降序排列。

    前端通过该接口渲染权限分布柱状图或词云，展示最常被申请的权限 Top 20。

    返回：
        JSON 数组，每个元素为 [权限名称, 出现次数] 的二元组，按次数降序，
        最多返回前 20 项。无数据时返回空数组 []。
    """
    report = load_analysis_results()
    if report and "results" in report:
        all_permissions = {}
        # 遍历所有应用，汇总权限出现频次
        for result in report["results"]:
            for permission in result.get("static_analysis", {}).get("permissions", []):
                # 累加计数：键为权限名，值为出现次数
                all_permissions[permission] = all_permissions.get(permission, 0) + 1

        # 按出现次数降序排序
        sorted_permissions = sorted(all_permissions.items(), key=lambda item: item[1], reverse=True)
        # 仅返回前 20 项，避免数据量过大影响前端渲染性能
        return jsonify(sorted_permissions[:20])
    return jsonify([])


# --- 4.7 权限风险分档接口 ---

@app.route("/api/permission-risks")
def get_permission_risks():
    """返回权限风险分档统计与全部权限详情。

    将每个权限按风险等级归入 low / medium / high / very_high 四档，
    统计各档位数量，同时返回去重后的权限详情列表。

    同一权限在不同应用中可能有不同风险等级，此处取最高等级作为该权限的归类。

    返回：
        JSON 对象，包含两个字段：
            - risk_stats (dict): 各风险档位的权限数量统计
            - permission_details (list): 去重后的权限详情列表
    """
    report = load_analysis_results()
    if report and "results" in report:
        # 风险档位计数器，初始化为 0
        risk_stats = {"low": 0, "medium": 0, "high": 0, "very_high": 0}
        permission_details = []   # 去重后的权限详情列表
        seen_perms = set()        # 用于去重的权限名称集合
        permission_levels = {}    # 记录每个权限的最高风险档位

        # 风险档位到严重程度的映射，数值越大越严重
        severity_rank = {"low": 1, "medium": 2, "high": 3, "very_high": 4}

        # 遍历所有应用，收集权限风险数据
        for result in report["results"]:
            perm_analysis = result.get("static_analysis", {}).get("permission_analysis", {})
            details = perm_analysis.get("permission_details", [])
            for perm in details:
                name = perm.get("name")
                if not name:
                    continue

                # 去重：同一权限名称只保留第一条详情记录
                if name not in seen_perms:
                    seen_perms.add(name)
                    permission_details.append(perm)

                # 获取该权限的风险档位
                bucket = _get_permission_risk_bucket(perm)
                if not bucket:
                    continue

                # 同一权限出现多次时，保留风险等级最高（最严重）的那一档
                current_bucket = permission_levels.get(name)
                if current_bucket is None or severity_rank[bucket] > severity_rank[current_bucket]:
                    permission_levels[name] = bucket

        # 根据最终的档位映射，统计各档位的权限数量
        for bucket in permission_levels.values():
            risk_stats[bucket] += 1

        return jsonify({"risk_stats": risk_stats, "permission_details": permission_details})
    return jsonify({"risk_stats": {}, "permission_details": []})


# --- 4.8 动态分析详情接口 ---

@app.route("/api/app/<package_name>/dynamic")
def get_app_dynamic(package_name):
    """按包名返回单个应用的动态分析详情，包括敏感 API 调用记录与 Frida Hook 日志。

    数据来源优先级：
        1. 报告中已有的 dynamic_analysis 字段（内存数据）
        2. 磁盘上的独立动态分析 JSON 文件（{文件名}_dynamic_analysis.json）

    参数：
        package_name (str): URL 路径参数，Android 应用包名。

    返回：
        JSON 对象，包含该应用的动态分析详情；若数据不可用则返回
        {"error": "Dynamic analysis data not found"}。
    """
    report = load_analysis_results()
    if report and "results" in report:
        for result in report["results"]:
            if result.get("package_name") == package_name:
                # 第一优先级：使用报告内嵌的动态分析数据
                if result.get("dynamic_analysis"):
                    return jsonify(result["dynamic_analysis"])

                # 第二优先级：尝试从磁盘读取独立的动态分析 JSON 文件
                apk_file = result.get("apk_file")
                if apk_file:
                    artifact_apk_file = result.get("artifact_apk_file") or apk_file
                    # 动态分析文件命名规则：{APK名称}_dynamic_analysis.json
                    dynamic_file = os.path.join(RESULTS_DIR, f"{artifact_apk_file}_dynamic_analysis.json")
                    if os.path.exists(dynamic_file):
                        try:
                            with open(dynamic_file, "r", encoding="utf-8") as file:
                                return jsonify(json.load(file))
                        except Exception:
                            # 文件读取失败时静默跳过，继续返回错误响应
                            pass
                # 找到包名后无需继续遍历
                break
    return jsonify({"error": "Dynamic analysis data not found"})


# ============================================================================
# 第五部分：程序入口 —— 启动 Flask 开发服务器
# ============================================================================

if __name__ == "__main__":
    # 打印启动横幅，便于在终端中确认服务状态和关键路径
    print("=" * 60)
    print("Starting dashboard...")
    print(f"Results dir: {RESULTS_DIR}")
    # 启动时预加载报告，检查数据可用性
    load_analysis_results()
    print("=" * 60)
    # 启动 Flask 开发服务器，监听 5000 端口，开启调试模式
    app.run(debug=True, port=5000)
