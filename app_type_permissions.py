# 基于GBT+41391-2022标准的应用类型和必要个人信息分类
from typing import Dict, List, Set

# 应用类型定义
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

# 不同类型应用的必要个人信息范围（基于GBT+41391-2022附录A）
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

# 权限风险等级映射
PERMISSION_RISK_LEVELS = {
    '极高': 5,
    '高': 3,
    '中高': 2,
    '中': 1,
    '低': 0.5
}

def get_app_type(package_name: str) -> str:
    """
    根据包名判断应用类型
    """
    package_name_lower = package_name.lower()
    
    for app_type, packages in APP_TYPES.items():
        for pkg in packages:
            if pkg.lower() in package_name_lower:
                return app_type
    
    # 基于包名特征的补充识别
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
    判断权限类别：必要个人信息、非必要但有关联个人信息、无关个人信息
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
    判断是否为高风险权限
    """
    return risk_level in ['高', '极高', '中高']

# 权限类别权重
PERMISSION_CATEGORY_WEIGHTS = {
    'necessary': 0,  # 必要个人信息不计算风险
    'non_necessary': 1  # 非必要个人信息计算风险
}

# 分业务场景可解释的敏感权限域。
# 这些域不会被直接判定为合规，但会作为“业务相关、需持续关注”的信号，
# 用于避免主流应用因同类功能权限重复声明而被线性累加到极端高分。
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

# 敏感API类别权重
SENSITIVE_API_WEIGHTS = {
    'location': 2.0,
    'contacts': 2.0,
    'camera': 1.5,
    'microphone': 1.5,
    'storage': 1.0,
    'phone': 2.0,
    'sms': 2.0,
    'account': 1.5,
    'network': 1.0
}

# 风险等级阈值
RISK_THRESHOLDS = {
    'high': 55,
    'medium': 35,
    'low': 0
}
