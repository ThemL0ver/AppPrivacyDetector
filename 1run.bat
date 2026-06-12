@echo off
:: 切换到脚本所在的目录（防止代码内部读取相对路径时出错）
cd /d D:\桌面\AppPrivacyDetector\web_dashboard

:: 打开新的命令行窗口并运行 python 脚本
start cmd /k "python app.py"