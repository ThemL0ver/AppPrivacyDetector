#Web可视化预警系统
from flask import Flask, render_template, jsonify, request
import json
import os
from pathlib import Path

app = Flask(__name__)

RESULTS_DIR = "../results"

def load_analysis_results():
    report_file = os.path.join(RESULTS_DIR, 'integrated_analysis_report.json')
    if os.path.exists(report_file):
        with open(report_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/summary')
def get_summary():
    report = load_analysis_results()
    if report:
        return jsonify({
            'total_analyzed': report['total_analyzed'],
            'high_risk': len(report['high_risk_apps']),
            'medium_risk': len(report['medium_risk_apps']),
            'low_risk': len(report['low_risk_apps'])
        })
    return jsonify({'error': 'No data available'})

@app.route('/api/apps')
def get_apps():
    report = load_analysis_results()
    if report:
        apps = []
        for result in report['results']:
            high_risk_count = 0
            if 'high_risk_permissions' in result['static_analysis']['permission_analysis']:
                high_risk_count = len(result['static_analysis']['permission_analysis']['high_risk_permissions'])
            
            apps.append({
                'apk_file': result['apk_file'],
                'package_name': result['package_name'],
                'risk_level': result['risk_assessment']['risk_level'],
                'risk_score': result['risk_assessment']['total_score'],
                'permissions_count': result['static_analysis']['total_permissions'],
                'dangerous_permissions': len(result['static_analysis']['permission_analysis']['dangerous_permissions']),
                'high_risk_permissions': high_risk_count
            })
        return jsonify(apps)
    return jsonify([])

@app.route('/api/app/<package_name>')
def get_app_detail(package_name):
    report = load_analysis_results()
    if report:
        for result in report['results']:
            if result['package_name'] == package_name:
                # 确保返回的结果包含必要的字段
                if 'dynamic_analysis' not in result:
                    result['dynamic_analysis'] = {
                        'monitoring_result': {
                            'api_calls': []
                        }
                    }
                return jsonify(result)
    return jsonify({'error': 'App not found'})

@app.route('/api/permissions')
def get_permissions():
    report = load_analysis_results()
    if report:
        all_permissions = {}
        for result in report['results']:
            for perm in result['static_analysis']['permissions']:
                if perm not in all_permissions:
                    all_permissions[perm] = 0
                all_permissions[perm] += 1
        
        sorted_perms = sorted(all_permissions.items(), 
                            key=lambda x: x[1], reverse=True)
        
        return jsonify(sorted_perms[:20])
    return jsonify([])

@app.route('/api/permission-risks')
def get_permission_risks():
    report = load_analysis_results()
    if report:
        risk_stats = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'very_high': 0
        }
        
        permission_details = []
        
        for result in report['results']:
            if 'permission_analysis' in result['static_analysis']:
                perm_analysis = result['static_analysis']['permission_analysis']
                if 'permission_details' in perm_analysis:
                    for perm in perm_analysis['permission_details']:
                        permission_details.append(perm)
                        
                        # 统计风险等级
                        main_risk = perm['main_risk_level']
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
    if report:
        for result in report['results']:
            if result['package_name'] == package_name:
                # 构建动态分析文件名
                apk_file = result['apk_file']
                dynamic_file = os.path.join(RESULTS_DIR, f'{apk_file}_dynamic_analysis.json')
                
                if os.path.exists(dynamic_file):
                    with open(dynamic_file, 'r', encoding='utf-8') as f:
                        return jsonify(json.load(f))
                break
    return jsonify({'error': 'Dynamic analysis data not found'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)