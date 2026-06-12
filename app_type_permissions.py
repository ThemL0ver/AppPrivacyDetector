"""
基于 GB/T 41391-2022《信息安全技术 移动互联网应用程序（App）收集个人信息基本要求》标准的
应用类型定义、必要个人信息范围分类以及权限风险等级评估模块。

本模块提供以下核心功能：
1. 根据应用包名自动识别应用类型（如地图导航、即时通讯、网络支付等）
2. 定义各类型应用的必要个人信息（权限）范围
3. 判断给定权限属于"必要个人信息"还是"非必要个人信息"
4. 支持权限风险等级映射与风险评分权重体系

主要数据结构：
- APP_TYPES：应用类型 → 已知包名列表的映射
- NECESSARY_INFO：应用类型 → 必要权限列表及中文描述的映射
- PERMISSION_RISK_LEVELS：风险等级名称 → 风险权重的映射
- CONTEXTUAL_PERMISSION_DOMAINS：分业务场景的可解释敏感权限域
- SENSITIVE_API_WEIGHTS：敏感 API 类别 → 风险权重的映射
"""

from typing import Dict, List, Set

# ======================== 应用类型定义 ========================
# 根据 GB/T 41391-2022 附录A 划分的应用服务类型，每类下列出代表性的已知包名
APP_TYPES = {
    # 地图导航类
    'map': ['com.baidu.BaiduMap', 'com.autonavi.minimap', 'com.tencent.map'],
    
    # 网约车类
    'ride_hailing': ['com.sdu.didi.psnger', 'com.ubercab'],
    
    # 即时通讯类
    'instant_messaging': ['com.tencent.mm', 'com.tencent.mobileqq', 'com.alibaba.android.rimet', 'com.tencent.wework'],
    
    # 网络支付类
    'payment': ['com.eg.android.AlipayGphone', 'com.tencent.mm', 'com.unionpay', 'com.chinamworld.main', 'com.hexin.plat.android'],
    
    # 网络社区类
    'social': ['com.sina.weibo', 'com.tencent.mtt', 'com.zhihu.android'],
    
    # 网络购物类
    'shopping': ['com.jingdong.app.mall', 'com.taobao.taobao', 'com.tmall.wireless', 'com.achievo.vipshop'],
    
    # 餐饮外卖类
    'food_delivery': ['me.ele', 'com.sankuai.meituan.takeoutnew'],
    
    # 邮件类
    'email': ['com.android.email', 'com.google.android.gm'],
    
    # 网络借贷类
    'lending': [],
    
    # 房屋租售类
    'real_estate': [],
    
    # 汽车交易类
    'car_trading': [],
    
    # 教育服务类
    'education': ['com.chaoxing.mobile', 'com.xueersi.pad', 'com.netease.edu.ucmooc', 'com.baidu.homework'],
    
    # 旅游服务类
    'travel': ['com.Qunar'],
    
    # 医疗服务类
    'medical': ['com.wondersgroup.ybtproduct'],
    
    # 问诊挂号类
    'medical_consultation': [],
    
    # 健康管理类
    'health_management': [],
    
    # 网络直播类
    'live_streaming': [],
    
    # 在线影音类
    'video': ['com.qiyi.video'],
    
    # 音乐类
    'music': ['com.netease.cloudmusic', 'com.kugou.android', 'com.tencent.qqmusic'],
    
    # 短视频类
    'short_video': ['com.ss.android.ugc.aweme'],
    
    # 新闻资讯类
    'news': [],
    
    # 运动健身类
    'sports': [],
    
    # 浏览器类
    'browser': ['com.baidu.searchbox'],
    
    # 输入法类
    'input_method': [],
    
    # 安全管理类
    'security': [],
    
    # 电子图书类
    'ebook': [],
    
    # 拍摄美化类
    'camera': [],
    
    # 应用商店类
    'app_store': [],
    
    # 其他
    'other': []
}

# ======================== 必要个人信息定义 ========================
# 依据 GB/T 41391-2022 附录A，定义每种应用类型的必要个人信息（即必要权限）范围
# 每个条目包含：
#   - permissions：该类型应用为实现基本功能所必需声明的权限列表
#   - description：对该类型应用所需个人信息的中文描述
NECESSARY_INFO = {
    'map': {
        'permissions': [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.CAMERA'
        ],
        'description': '位置信息、网络状态、存储、基本设备信息、通知、WiFi状态、系统交互、蓝牙、前台服务、后台位置、相机'
    },
    
    'ride_hailing': {
        'permissions': [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.CALL_PHONE'
        ],
        'description': '位置信息、联系方式、相机、录音'
    },
    
    'instant_messaging': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、录音、联系人、存储'
    },
    
    'payment': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.USE_FINGERPRINT',
            'android.permission.USE_BIOMETRIC'
        ],
        'description': '网络状态、设备信息、相机、存储、基本设备信息、通知、WiFi状态、系统交互、蓝牙、前台服务、生物识别'
    },
    
    'social': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.FOREGROUND_SERVICE'
        ],
        'description': '网络状态、相机、录音、联系人、存储、基本设备信息、通知、WiFi状态、系统交互、蓝牙、前台服务'
    },
    
    'shopping': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT'
        ],
        'description': '网络状态、相机、存储、基本设备信息、通知、WiFi状态、系统交互、蓝牙'
    },
    
    'food_delivery': {
        'permissions': [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.FOREGROUND_SERVICE'
        ],
        'description': '位置信息、联系方式、相机、存储、基本设备信息、通知、WiFi状态、系统交互、蓝牙、前台服务'
    },
    
    'email': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_CONTACTS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、联系人、存储'
    },
    
    'lending': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_CONTACTS',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、设备信息、联系人、相机、存储'
    },
    
    'real_estate': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、存储'
    },
    
    'car_trading': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、存储'
    },
    
    'education': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.FOREGROUND_SERVICE'
        ],
        'description': '网络状态、相机、录音、存储、基本设备信息、通知、WiFi状态、系统交互、蓝牙、前台服务'
    },
    
    'travel': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、存储'
    },
    
    'medical': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、录音、存储'
    },
    
    'medical_consultation': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、录音、存储'
    },
    
    'health_management': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、录音、存储'
    },
    
    'live_streaming': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、相机、录音、存储'
    },
    
    'video': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_BASIC_PHONE_STATE',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.BLUETOOTH_ADMIN',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.DETECT_SCREEN_CAPTURE',
            'android.permission.DETECT_SCREEN_RECORDING',
            'android.permission.EXPAND_STATUS_BAR',
            'android.permission.CHANGE_NETWORK_STATE',
            'android.permission.CHANGE_WIFI_MULTICAST_STATE',
            'android.permission.HIGH_SAMPLING_RATE_SENSORS',
            'android.permission.REORDER_TASKS',
            'android.permission.SET_WALLPAPER',
            'android.permission.SET_WALLPAPER_HINTS',
            'android.permission.NFC',
            'android.permission.FLASHLIGHT',
            'android.permission.READ_MEDIA_VIDEO',
            'android.permission.READ_MEDIA_IMAGES',
            'android.permission.READ_MEDIA_AUDIO',
            'android.permission.READ_MEDIA_VISUAL_USER_SELECTED',
            'android.permission.CHANGE_CONFIGURATION',
            'android.permission.DISABLE_KEYGUARD',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.WRITE_CALENDAR',
            'android.permission.WRITE_SETTINGS',
            'android.permission.USE_FINGERPRINT',
            'android.permission.USE_BIOMETRIC',
            'com.android.launcher.permission.INSTALL_SHORTCUT',
            'com.android.launcher.permission.UNINSTALL_SHORTCUT',
            'com.qiyi.video.permission.MIPUSH_RECEIVE',
            'com.qiyi.video.permission.PROCESS_PUSH_MSG',
            'com.qiyi.video.permission.PUSH_PROVIDER',
            'com.qiyi.video.openadsdk.permission.TT_PANGOLIN',
            'com.qiyi.video.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION',
            'com.vivo.notification.permission.BADGE_ICON',
            'com.hihonor.push.permission.READ_PUSH_NOTIFICATION_INFO',
            'com.hihonor.calendar.permission.READ_CALENDAR_SUBSCRIPTIONS',
            'com.hihonor.calendar.permission.WRITE_CALENDAR_SUBSCRIPTIONS',
            'com.coloros.permission.WRITE_COLOROS_CALENDAR',
            'com.coloros.mcs.permission.RECIEVE_MCS_MESSAGE',
            'com.heytap.mcs.permission.RECIEVE_MCS_MESSAGE',
            'com.xiaomi.miplay.smartplay.CAST',
            'com.hihonor.handover.permission.BIND_HANDOVER_SERVICE',
            'org.fidoalliance.uaf.permissions.FIDO_CLIENT'
        ],
        'description': '网络状态、存储、相机、录音、粗略位置、基本设备信息、蓝牙、通知、前台服务、WiFi状态、音频设置、屏幕检测、系统交互、媒体访问、系统配置、推送服务、广告服务、日历服务、投屏服务、安装快捷方式、生物识别'
    },
    
    'music': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_MEDIA_AUDIO',
            'android.permission.READ_MEDIA_IMAGES',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE'
        ],
        'description': '网络状态、存储、录音、媒体访问、通知、前台服务、音频设置、系统交互'
    },
    
    'short_video': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_MEDIA_VIDEO',
            'android.permission.READ_MEDIA_IMAGES',
            'android.permission.READ_MEDIA_AUDIO',
            'android.permission.POST_NOTIFICATIONS',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_CONNECT',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE'
        ],
        'description': '网络状态、相机、录音、存储、媒体访问、通知、前台服务、音频设置、系统交互'
    },
    
    'news': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、存储'
    },
    
    'sports': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、位置信息、相机、录音、存储'
    },
    
    'browser': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、存储'
    },
    
    'input_method': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、存储'
    },
    
    'security': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_CONTACTS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、设备信息、联系人、存储'
    },
    
    'ebook': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、存储'
    },
    
    'camera': {
        'permissions': [
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.RECORD_AUDIO'
        ],
        'description': '相机、存储、录音'
    },
    
    'app_store': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、存储'
    },
    
    'other': {
        'permissions': [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ],
        'description': '网络状态、存储'
    }
}

# ======================== 权限风险等级映射 ========================
# 将中文风险等级映射为数值权重，用于后续风险评分计算
PERMISSION_RISK_LEVELS = {
    '极高': 5,
    '高': 3,
    '中高': 2,
    '中': 1,
    '低': 0.5
}

def get_app_type(package_name: str) -> str:
    """
    根据应用包名自动识别其所属的应用类型。

    识别策略分两层：
    1. 精确匹配：遍历 APP_TYPES 字典，检查包名是否包含已知包名
    2. 关键词匹配：若精确匹配失败，则基于包名中的关键词（如 wechat、taobao 等）
       进行模糊识别

    参数:
        package_name (str): Android 应用的完整包名，如 "com.tencent.mm"

    返回:
        str: 应用类型标识符，如 'instant_messaging'、'map'、'shopping' 等
              若无法识别则返回 'other'
    """
    package_name_lower = package_name.lower()
    
    # 第一层：遍历已知包名列表进行精确匹配
    for app_type, packages in APP_TYPES.items():
        for pkg in packages:
            if pkg.lower() in package_name_lower:
                return app_type
    
    # 第二层：基于包名特征关键词进行模糊匹配
    if 'wechat' in package_name_lower or 'wx' in package_name_lower:
        return 'instant_messaging'
    elif 'wework' in package_name_lower:
        return 'instant_messaging'
    elif 'qq' in package_name_lower:
        return 'instant_messaging'
    elif 'weibo' in package_name_lower:
        return 'social'
    elif 'hexin' in package_name_lower or 'chinamworld' in package_name_lower:
        return 'payment'
    elif 'taobao' in package_name_lower or 'tmall' in package_name_lower:
        return 'shopping'
    elif 'vipshop' in package_name_lower or 'achievo' in package_name_lower:
        return 'shopping'
    elif 'jingdong' in package_name_lower or 'jd' in package_name_lower:
        return 'shopping'
    elif 'meituan' in package_name_lower:
        return 'food_delivery'
    elif 'didi' in package_name_lower:
        return 'ride_hailing'
    elif 'alipay' in package_name_lower:
        return 'payment'
    elif 'wondersgroup' in package_name_lower or 'ybt' in package_name_lower:
        return 'medical'
    elif 'map' in package_name_lower or 'navi' in package_name_lower:
        return 'map'
    elif 'video' in package_name_lower or 'movie' in package_name_lower:
        return 'video'
    elif 'music' in package_name_lower or 'audio' in package_name_lower or 'sound' in package_name_lower:
        return 'music'
    elif 'news' in package_name_lower:
        return 'news'
    elif 'browser' in package_name_lower or 'search' in package_name_lower:
        return 'browser'
    elif 'education' in package_name_lower or 'study' in package_name_lower or 'learn' in package_name_lower or 'homework' in package_name_lower:
        return 'education'
    elif 'game' in package_name_lower:
        return 'other'
    
    return 'other'

def get_permission_category(app_type: str, permission: str) -> str:
    """
    判断某个权限对于指定应用类型来说属于哪个类别。

    根据 GB/T 41391-2022 的分类标准，将权限分为：
    - 'necessary'：必要个人信息对应的权限，是实现基本功能所必需的
    - 'non_necessary'：非必要个人信息对应的权限，超出基本功能所需

    参数:
        app_type (str): 应用类型标识符，如 'map'、'shopping' 等
        permission (str): Android 权限全名，如 'android.permission.CAMERA'

    返回:
        str: 权限类别，'necessary' 或 'non_necessary'
              若 app_type 不在 NECESSARY_INFO 中，默认返回 'non_necessary'
    """
    if app_type not in NECESSARY_INFO:
        return 'non_necessary'
    
    necessary_perms = NECESSARY_INFO[app_type]['permissions']
    
    if permission in necessary_perms:
        return 'necessary'
    else:
        return 'non_necessary'

def is_risky_permission(permission: str, risk_level: str) -> bool:
    """
    判断某个权限是否属于高风险权限。

    当权限的风险等级为 '高'、'极高' 或 '中高' 时，视为高风险权限。

    参数:
        permission (str): Android 权限全名
        risk_level (str): 权限的风险等级，如 '高'、'中'、'低' 等

    返回:
        bool: 是否为高风险权限
    """
    return risk_level in ['高', '极高', '中高']

# ======================== 权限类别权重 ========================
# 必要个人信息在风险评分中权重为 0（不参与风险累加）
# 非必要个人信息权重为 1，全额计入风险评分
PERMISSION_CATEGORY_WEIGHTS = {
    'necessary': 0,
    'non_necessary': 1
}

# ======================== 分业务场景敏感权限域 ========================
# 某些权限域在特定业务场景下是合理的（如视频应用需要相机和麦克风）
# 这些域不会被直接判定为违规，但会标记为"需要持续关注"的信号
# 目的是避免主流应用因同类功能权限的重复声明而被线性累加到极端高分
CONTEXTUAL_PERMISSION_DOMAINS = {
    'browser': {'location', 'camera', 'microphone', 'storage', 'notification', 'account'},
    'video': {'location', 'camera', 'microphone', 'storage', 'notification', 'biometric'},
    'music': {'location', 'microphone', 'storage', 'notification'},
    'short_video': {'location', 'camera', 'microphone', 'storage', 'notification', 'biometric'},
    'shopping': {'location', 'camera', 'microphone', 'storage', 'notification', 'biometric', 'account', 'phone'},
    'food_delivery': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'phone', 'contacts'},
    'education': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'phone'},
    'instant_messaging': {'location', 'camera', 'microphone', 'storage', 'notification', 'contacts', 'biometric', 'phone'},
    'payment': {'location', 'camera', 'storage', 'notification', 'biometric', 'account', 'phone'},
    'lending': {'location', 'camera', 'storage', 'notification', 'biometric', 'account', 'phone', 'contacts'},
    'map': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'calendar'},
    'ride_hailing': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'phone', 'contacts'},
    'travel': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'calendar', 'phone'},
    'medical': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'phone', 'biometric'},
    'medical_consultation': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'phone', 'biometric'},
    'health_management': {'location', 'camera', 'microphone', 'storage', 'notification', 'account', 'phone', 'biometric'}
}

# ======================== 敏感 API 类别权重 ========================
# 动态 Hook 捕获的各类敏感 API 调用的风险权重
# 权重越高表示该类别 API 被滥用时带来的隐私风险越大
SENSITIVE_API_WEIGHTS = {
    'location': 2.0,       # 位置信息 → 极高敏感度
    'contacts': 2.0,       # 联系人 → 极高敏感度
    'camera': 1.5,         # 相机 → 高敏感度
    'microphone': 1.5,     # 麦克风 → 高敏感度
    'storage': 1.0,        # 存储 → 中敏感度
    'phone': 2.0,          # 电话/设备标识 → 极高敏感度
    'sms': 2.0,            # 短信 → 极高敏感度
    'account': 1.5,        # 账户信息 → 高敏感度
    'network': 1.0         # 网络 → 中敏感度
}

# ======================== 风险评分阈值 ========================
# 根据最终风险评分将应用划分为三个风险等级
RISK_THRESHOLDS = {
    'high': 70,    # 高风险：评分 >= 70
    'medium': 38,  # 中风险：评分 >= 38 且 < 70
    'low': 0       # 低风险：评分 < 38
}
