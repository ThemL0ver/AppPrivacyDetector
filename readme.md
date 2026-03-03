# APP隐私权限检测与风险预警系统

## 项目概述
本项目是一个基于动静结合分析的APP隐私权限检测与风险预警系统，用于识别移动应用中的过度索权和隐私泄露风险。

## 系统架构
- 静态分析模块：APK反编译、权限声明提取
- 动态分析模块：运行时API调用监控
- 综合分析模块：动静结合风险评估
- Web可视化系统：风险预警与结果展示

## 使用说明

### 环境准备
1. 安装Python 3.7+
2. 安装依赖：`pip install -r requirements.txt`
3. 配置Android SDK和ADB工具
4. 启动Android模拟器

### 静态分析
```bash
cd static_analysis
python apk_analyzer.py
```

### 动态分析
```bash
cd dynamic_analysis
python dynamic_monitor.py
```

### 综合分析
```bash
python integrated_analysis.py
```

### 启动Web系统
```bash
cd web_dashboard
python app.py
```
访问 http://localhost:5000

## 目录结构