# 日志管理模块
import logging
from logging.handlers import RotatingFileHandler
import os

class Logger:
    def __init__(self, log_file="app_privacy_detector.log"):
        self.log_file = log_file
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """设置日志记录器"""
        # 创建日志的记录等级
        logging.basicConfig(level=logging.INFO)
        # 创建日志记录器，指明日志保存的路径，每个日志文件的最大值，保存的日志文件个数上限
        log_handle = RotatingFileHandler(
            self.log_file, 
            maxBytes=1024 * 1024 * 5, 
            backupCount=3
        )
        # 创建日志记录的格式
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(funcName)s'
        )
        # 为创建的日志记录器设置日志记录格式
        log_handle.setFormatter(formatter)
        # 为全局的日志工具对象添加日志记录器
        logging.getLogger().addHandler(log_handle)
        return logging.getLogger(__name__)
    
    def info(self, message):
        """记录信息日志"""
        self.logger.info(message)
    
    def warning(self, message):
        """记录警告日志"""
        self.logger.warning(message)
    
    def error(self, message):
        """记录错误日志"""
        self.logger.error(message)
    
    def critical(self, message):
        """记录严重错误日志"""
        self.logger.critical(message)

# 创建全局日志实例
logger = Logger()