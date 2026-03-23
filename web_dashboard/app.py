# Web可视化预警系统
from flask import Flask, render_template, jsonify
import json
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(CURRENT_DIR, 'templates')
if not os.path.exists(template_dir) and os.path.exists(os.path.join(CURRENT_DIR, 'index.html')):
    template_dir = CURRENT_DIR

app = Flask(__name__, template_folder=template_dir)

# 内存缓存，避免每次刷新页面都去读写硬盘
_cached_report = None

def get_results_dir():
    possible_paths = [
        os.path.join(CURRENT_DIR, 'results'),
        os.path.join(CURRENT_DIR, '..', 'results'),
        os.path.join(os.getcwd(), 'results')
    ]
    for path in possible_paths:
        if os.path.exists(path) and os.path.isdir(path):
            return os.path.abspath(path)
    return os.path.abspath(os.path.join(CURRENT_DIR, '..', 'results'))

RESULTS_DIR = get_results_dir()

def load_analysis_results(force_reload=False):
    """带缓存的JSON文件读取器，极大地提高响应速度"""
    global _cached_report
    
    # 如果已经缓存且不强制刷新，直接返回内存数据（微秒级响应）
    if _cached_report is not None and not force_reload:
        return _cached_report
        
    report_file = os.path.join(RESULTS_DIR, 'integrated_analysis_report.json')
    if os.path.exists(report_file):
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                _cached_report = json.load(f)
                return _cached_report
        except Exception as e:
            print(f"[-] 读取JSON文件出错: {e}")
    else:
        print(f"[-] 未找到分析报告: {report_file}")
    return None

@app.route('/')
def index():
    return render_template('index.html')

# 添加一个刷新缓存的接口，当你重新跑了分析后可以点击或请求这个接口
@app.route('/api/reload')
def reload_data():
    load_analysis_results(force_reload=True)
    return jsonify({"status": "success", "message": "数据已重新加载"})

@app.route('/api/summary')
def get_summary():
    report = load_analysis_results()
    if report:
        return jsonify({
            'total_analyzed': report.get('total_analyzed', 0),
            'high_risk': len(report.get('high_risk_apps', [])),
            'medium_risk': len(report.get('medium_risk_apps', [])),
            'low_risk': len(report.get('low_risk_apps', []))
        })
    return jsonify({'error': 'No data available'})

@app.route('/api/apps')
def get_apps():
    report = load_analysis_results()
    if report and 'results' in report:
        apps = []
        for result in report['results']:
            high_risk_count = 0
            if 'permission_analysis' in result.get('static_analysis', {}) and 'high_risk_permissions' in result['static_analysis']['permission_analysis']:
                high_risk_count = len(result['static_analysis']['permission_analysis']['high_risk_permissions'])
            
            apps.append({
                'apk_file': result.get('apk_file', '未知'),
                'package_name': result.get('package_name', '未知'),
                'risk_level': result.get('risk_assessment', {}).get('risk_level', 'low'),
                'risk_score': result.get('risk_assessment', {}).get('total_score', 0),
                'permissions_count': result.get('static_analysis', {}).get('total_permissions', 0),
                'dangerous_permissions': len(result.get('static_analysis', {}).get('permission_analysis', {}).get('dangerous_permissions', [])),
                'high_risk_permissions': high_risk_count
            })
        return jsonify(apps)
    return jsonify([])

@app.route('/api/app/<package_name>')
def get_app_detail(package_name):
    report = load_analysis_results()
    if report and 'results' in report:
        for result in report['results']:
            if result.get('package_name') == package_name:
                if 'dynamic_analysis' not in result:
                    result['dynamic_analysis'] = {
                        'monitoring_result': {'api_calls': []}
                    }
                return jsonify(result)
    return jsonify({'error': 'App not found'})

@app.route('/api/permissions')
def get_permissions():
    report = load_analysis_results()
    if report and 'results' in report:
        all_permissions = {}
        for result in report['results']:
            for perm in result.get('static_analysis', {}).get('permissions', []):
                if perm not in all_permissions:
                    all_permissions[perm] = 0
                all_permissions[perm] += 1
        
        sorted_perms = sorted(all_permissions.items(), key=lambda x: x[1], reverse=True)
        return jsonify(sorted_perms[:20])
    return jsonify([])

@app.route('/api/permission-risks')
def get_permission_risks():
    report = load_analysis_results()
    if report and 'results' in report:
        risk_stats = {'low': 0, 'medium': 0, 'high': 0, 'very_high': 0}
        permission_details = []
        seen_perms = set() 
        
        for result in report['results']:
            if 'permission_analysis' in result.get('static_analysis', {}):
                perm_analysis = result['static_analysis']['permission_analysis']
                if 'permission_details' in perm_analysis:
                    for perm in perm_analysis['permission_details']:
                        if perm['name'] not in seen_perms:
                            seen_perms.add(perm['name'])
                            permission_details.append(perm)
                        
                        main_risk = perm.get('main_risk_level', '')
                        if main_risk == '低':
                            risk_stats['low'] += 1
                        elif main_risk == '中':
                            risk_stats['medium'] += 1
                        elif main_risk == '中高':
                            risk_stats['high'] += 1
                        elif main_risk in ['高', '极高']:
                            risk_stats['very_high'] += 1
        
        return jsonify({
            'risk_stats': risk_stats,
            'permission_details': permission_details
        })
    return jsonify({'risk_stats': {}, 'permission_details': []})

@app.route('/api/app/<package_name>/dynamic')
def get_app_dynamic(package_name):
    report = load_analysis_results()
    if report and 'results' in report:
        for result in report['results']:
            if result.get('package_name') == package_name:
                if 'dynamic_analysis' in result and result['dynamic_analysis']:
                    return jsonify(result['dynamic_analysis'])
                
                apk_file = result.get('apk_file')
                if apk_file:
                    dynamic_file = os.path.join(RESULTS_DIR, f'{apk_file}_dynamic_analysis.json')
                    if os.path.exists(dynamic_file):
                        try:
                            with open(dynamic_file, 'r', encoding='utf-8') as f:
                                return jsonify(json.load(f))
                        except Exception:
                            pass
                break
    return jsonify({'error': 'Dynamic analysis data not found'})

if __name__ == '__main__':
    print("="*60)
    print(f"正在启动可视化面板...")
    print(f"结果读取路径设为: {RESULTS_DIR}")
    # 启动时预加载到内存
    load_analysis_results()
    print("="*60)
    app.run(debug=True, port=5000)
