from flask import Flask, jsonify, render_template
import json
import math
import os


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(CURRENT_DIR, "templates")
if not os.path.exists(TEMPLATE_DIR) and os.path.exists(os.path.join(CURRENT_DIR, "index.html")):
    TEMPLATE_DIR = CURRENT_DIR

app = Flask(__name__, template_folder=TEMPLATE_DIR)
_cached_report = None


def get_results_dir():
    possible_paths = [
        os.path.join(CURRENT_DIR, "results"),
        os.path.join(CURRENT_DIR, "..", "results"),
        os.path.join(os.getcwd(), "results"),
    ]
    for path in possible_paths:
        if os.path.exists(path) and os.path.isdir(path):
            return os.path.abspath(path)
    return os.path.abspath(os.path.join(CURRENT_DIR, "..", "results"))


RESULTS_DIR = get_results_dir()


def _round_score(value):
    try:
        return int(math.floor(float(value) + 0.5))
    except (TypeError, ValueError):
        return 0


def _normalize_risk_assessment(risk_assessment):
    if not isinstance(risk_assessment, dict):
        return
    for score_key in ("static_score", "dynamic_score", "total_score"):
        if score_key in risk_assessment:
            risk_assessment[score_key] = _round_score(risk_assessment.get(score_key))


def _normalize_report_scores(report):
    if not isinstance(report, dict):
        return report

    average_scores = report.get("average_scores")
    if isinstance(average_scores, dict):
        for score_key in ("static_score", "dynamic_score", "total_score"):
            if score_key in average_scores:
                average_scores[score_key] = _round_score(average_scores.get(score_key))

    results = report.get("results")
    if isinstance(results, list):
        for result in results:
            if isinstance(result, dict):
                _normalize_risk_assessment(result.get("risk_assessment"))

    return report


def _get_permission_risk_bucket(permission_detail):
    if not isinstance(permission_detail, dict):
        return None

    raw_level = str(
        permission_detail.get("main_risk_level")
        or permission_detail.get("risk_level")
        or ""
    ).strip().lower()

    if not raw_level:
        return None
    if raw_level == "very_high" or "极高" in raw_level or raw_level == "高" or raw_level.startswith("高（"):
        return "very_high"
    if raw_level == "high" or "中高" in raw_level:
        return "high"
    if raw_level == "medium" or raw_level == "中" or raw_level.startswith("中（"):
        return "medium"
    if raw_level == "low" or raw_level == "低" or raw_level.startswith("低（"):
        return "low"
    return None


def load_analysis_results(force_reload=False):
    global _cached_report
    if _cached_report is not None and not force_reload:
        return _cached_report

    report_file = os.path.join(RESULTS_DIR, "integrated_analysis_report.json")
    if os.path.exists(report_file):
        try:
            with open(report_file, "r", encoding="utf-8") as file:
                _cached_report = _normalize_report_scores(json.load(file))
                return _cached_report
        except Exception as error:
            print(f"[-] Failed to load report: {error}")
    else:
        print(f"[-] Report not found: {report_file}")
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/reload")
def reload_data():
    load_analysis_results(force_reload=True)
    return jsonify({"status": "success", "message": "Data reloaded"})


@app.route("/api/summary")
def get_summary():
    report = load_analysis_results()
    if report:
        return jsonify(
            {
                "total_analyzed": report.get("total_analyzed", 0),
                "high_risk": len(report.get("high_risk_apps", [])),
                "medium_risk": len(report.get("medium_risk_apps", [])),
                "low_risk": len(report.get("low_risk_apps", [])),
            }
        )
    return jsonify({"error": "No data available"})


@app.route("/api/apps")
def get_apps():
    report = load_analysis_results()
    if report and "results" in report:
        apps = []
        for result in report["results"]:
            perm_analysis = result.get("static_analysis", {}).get("permission_analysis", {})
            high_risk_permissions = perm_analysis.get("high_risk_permissions", [])

            apps.append(
                {
                    "apk_file": result.get("apk_file", "unknown"),
                    "package_name": result.get("package_name", "unknown"),
                    "risk_level": result.get("risk_assessment", {}).get("risk_level", "low"),
                    "risk_score": _round_score(result.get("risk_assessment", {}).get("total_score", 0)),
                    "permissions_count": result.get("static_analysis", {}).get("total_permissions", 0),
                    "dangerous_permissions": len(perm_analysis.get("dangerous_permissions", [])),
                    "high_risk_permissions": len(high_risk_permissions),
                }
            )
        return jsonify(apps)
    return jsonify([])


@app.route("/api/app/<package_name>")
def get_app_detail(package_name):
    report = load_analysis_results()
    if report and "results" in report:
        for result in report["results"]:
            if result.get("package_name") == package_name:
                _normalize_risk_assessment(result.get("risk_assessment"))
                if "dynamic_analysis" not in result:
                    result["dynamic_analysis"] = {"monitoring_result": {"api_calls": []}}
                return jsonify(result)
    return jsonify({"error": "App not found"})


@app.route("/api/permissions")
def get_permissions():
    report = load_analysis_results()
    if report and "results" in report:
        all_permissions = {}
        for result in report["results"]:
            for permission in result.get("static_analysis", {}).get("permissions", []):
                all_permissions[permission] = all_permissions.get(permission, 0) + 1

        sorted_permissions = sorted(all_permissions.items(), key=lambda item: item[1], reverse=True)
        return jsonify(sorted_permissions[:20])
    return jsonify([])


@app.route("/api/permission-risks")
def get_permission_risks():
    report = load_analysis_results()
    if report and "results" in report:
        risk_stats = {"low": 0, "medium": 0, "high": 0, "very_high": 0}
        permission_details = []
        seen_perms = set()
        permission_levels = {}
        severity_rank = {"low": 1, "medium": 2, "high": 3, "very_high": 4}

        for result in report["results"]:
            perm_analysis = result.get("static_analysis", {}).get("permission_analysis", {})
            details = perm_analysis.get("permission_details", [])
            for perm in details:
                name = perm.get("name")
                if not name:
                    continue

                if name not in seen_perms:
                    seen_perms.add(name)
                    permission_details.append(perm)

                bucket = _get_permission_risk_bucket(perm)
                if not bucket:
                    continue

                current_bucket = permission_levels.get(name)
                if current_bucket is None or severity_rank[bucket] > severity_rank[current_bucket]:
                    permission_levels[name] = bucket

        for bucket in permission_levels.values():
            risk_stats[bucket] += 1

        return jsonify({"risk_stats": risk_stats, "permission_details": permission_details})
    return jsonify({"risk_stats": {}, "permission_details": []})


@app.route("/api/app/<package_name>/dynamic")
def get_app_dynamic(package_name):
    report = load_analysis_results()
    if report and "results" in report:
        for result in report["results"]:
            if result.get("package_name") == package_name:
                if result.get("dynamic_analysis"):
                    return jsonify(result["dynamic_analysis"])

                apk_file = result.get("apk_file")
                if apk_file:
                    dynamic_file = os.path.join(RESULTS_DIR, f"{apk_file}_dynamic_analysis.json")
                    if os.path.exists(dynamic_file):
                        try:
                            with open(dynamic_file, "r", encoding="utf-8") as file:
                                return jsonify(json.load(file))
                        except Exception:
                            pass
                break
    return jsonify({"error": "Dynamic analysis data not found"})


if __name__ == "__main__":
    print("=" * 60)
    print("Starting dashboard...")
    print(f"Results dir: {RESULTS_DIR}")
    load_analysis_results()
    print("=" * 60)
    app.run(debug=True, port=5000)
