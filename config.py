# 配置管理模块
import os
from typing import Dict, Any

class Config:
    def __init__(self):
        self.samples_dir = "samples"
        self.results_dir = "results"
        self.adb_paths = [
            r"E:\Nox\bin\nox_adb.exe",
            r"C:\Program Files (x86)\Nox\bin\adb.exe",
            "adb"
        ]
        self.aapt_paths = [
            r"E:\Nox\bin\aapt.exe",
            r"E:\Nox\bin\nox_aapt.exe",
            "aapt"
        ]
        self.frida_server_path = "./data/local/tmp/frida-server-17.7.3-android-x86_64"
        self.simulator_port = "62025"
        self.monitoring_duration = 60
        self.max_retries = 3
        
    def get_config(self) -> Dict[str, Any]:
        """获取配置字典"""
        return {
            "samples_dir": self.samples_dir,
            "results_dir": self.results_dir,
            "adb_paths": self.adb_paths,
            "aapt_paths": self.aapt_paths,
            "frida_server_path": self.frida_server_path,
            "simulator_port": self.simulator_port,
            "monitoring_duration": self.monitoring_duration,
            "max_retries": self.max_retries
        }

# 创建全局配置实例
config = Config()