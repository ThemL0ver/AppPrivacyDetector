# 基于GBT+41391-2022标准的应用类型和必要权限映射

# 应用类型分类
APP_TYPES = {
    "社交": [
        "com.tencent.mm",  # 微信
        "com.tencent.mobileqq",  # QQ
        "com.sina.weibo",  # 微博
        "com.zhihu.android",  # 知乎
        "com.douban.frodo"  # 豆瓣
    ],
    "地图导航": [
        "com.autonavi.minimap",  # 高德地图
        "com.baidu.BaiduMap",  # 百度地图
        "com.tencent.map"  # 腾讯地图
    ],
    "支付": [
        "com.eg.android.AlipayGphone",  # 支付宝
        "com.tencent.mm"  # 微信支付
    ],
    "购物": [
        "com.jingdong.app.mall",  # 京东
        "com.taobao.taobao",  # 淘宝
        "com.suning.mobile.ebuy"  # 苏宁
    ],
    "视频": [
        "com.qiyi.video",  # 爱奇艺
        "com.tencent.qqlive",  # 腾讯视频
        "com.sohu.sohuvideo"  # 搜狐视频
    ],
    "音乐": [
        "com.netease.cloudmusic",  # 网易云音乐
        "com.tencent.qqmusic",  # QQ音乐
        "com.kugou.android"  # 酷狗音乐
    ],
    "新闻": [
        "com.tencent.news",  # 腾讯新闻
        "com.sina.news",  # 新浪新闻
        "com.baidu.news"  # 百度新闻
    ],
    "工具": [
        "com.qihoo360.mobilesafe",  # 360安全卫士
        "com.cleanmaster.mguard",  # 猎豹清理大师
        "com.tencent.mobileqqclean"  # QQ清理
    ],
    "游戏": [
        "com.tencent.tmgp.pubgmhd",  # 和平精英
        "com.tencent.tmgp.sgame",  # 王者荣耀
        "com.miHoYo.hyperion"  # 原神
    ],
    "教育": [
        "com.chaoxing.mobile",  # 超星学习通
        "com.xueersi.pad",  # 学而思
        "com.happyelements.AndroidAnimal"  # 开心消消乐（教育类）
    ]
}

# 必要个人信息对应的权限映射
# 基于GBT+41391-2022附录A
NECESSARY_PERMISSIONS = {
    # 社交类应用必要权限
    "社交": {
        "android.permission.READ_CONTACTS": "必要个人信息",
        "android.permission.WRITE_CONTACTS": "必要个人信息",
        "android.permission.GET_ACCOUNTS": "必要个人信息",
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息"
    },
    # 地图导航类应用必要权限
    "地图导航": {
        "android.permission.ACCESS_FINE_LOCATION": "必要个人信息",
        "android.permission.ACCESS_COARSE_LOCATION": "必要个人信息",
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息"
    },
    # 支付类应用必要权限
    "支付": {
        "android.permission.READ_PHONE_STATE": "必要个人信息",
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息",
        "android.permission.USE_FINGERPRINT": "必要个人信息"
    },
    # 购物类应用必要权限
    "购物": {
        "android.permission.READ_PHONE_STATE": "必要个人信息",
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息",
        "android.permission.READ_EXTERNAL_STORAGE": "必要个人信息"
    },
    # 视频类应用必要权限
    "视频": {
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息",
        "android.permission.READ_EXTERNAL_STORAGE": "必要个人信息",
        "android.permission.WRITE_EXTERNAL_STORAGE": "必要个人信息"
    },
    # 音乐类应用必要权限
    "音乐": {
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息",
        "android.permission.READ_EXTERNAL_STORAGE": "必要个人信息",
        "android.permission.WRITE_EXTERNAL_STORAGE": "必要个人信息"
    },
    # 新闻类应用必要权限
    "新闻": {
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息"
    },
    # 工具类应用必要权限
    "工具": {
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息"
    },
    # 游戏类应用必要权限
    "游戏": {
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息",
        "android.permission.READ_PHONE_STATE": "必要个人信息"
    },
    # 教育类应用必要权限
    "教育": {
        "android.permission.INTERNET": "必要个人信息",
        "android.permission.ACCESS_NETWORK_STATE": "必要个人信息",
        "android.permission.CAMERA": "必要个人信息"  # 用于拍照上传作业
    }
}

# 非必要但有关联个人信息的权限
RELATED_PERMISSIONS = {
    "android.permission.CAMERA": "非必要但有关联个人信息",
    "android.permission.RECORD_AUDIO": "非必要但有关联个人信息",
    "android.permission.READ_SMS": "非必要但有关联个人信息",
    "android.permission.RECEIVE_SMS": "非必要但有关联个人信息",
    "android.permission.SEND_SMS": "非必要但有关联个人信息",
    "android.permission.READ_CALL_LOG": "非必要但有关联个人信息",
    "android.permission.WRITE_CALL_LOG": "非必要但有关联个人信息",
    "android.permission.CALL_PHONE": "非必要但有关联个人信息",
    "android.permission.PROCESS_OUTGOING_CALLS": "非必要但有关联个人信息"
}

# 无关个人信息的权限
IRRELEVANT_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES": "无关个人信息",
    "android.permission.SYSTEM_ALERT_WINDOW": "无关个人信息",
    "android.permission.VIBRATE": "无关个人信息",
    "android.permission.WAKE_LOCK": "无关个人信息",
    "android.permission.BLUETOOTH": "无关个人信息",
    "android.permission.NFC": "无关个人信息"
}

def get_app_type(package_name):
    """根据包名获取应用类型"""
    for app_type, packages in APP_TYPES.items():
        if package_name in packages:
            return app_type
    return "其他"

def get_permission_category(app_type, permission):
    """获取权限类别"""
    # 首先检查是否是必要个人信息
    if app_type in NECESSARY_PERMISSIONS:
        if permission in NECESSARY_PERMISSIONS[app_type]:
            return NECESSARY_PERMISSIONS[app_type][permission]
    
    # 检查是否是非必要但有关联个人信息
    if permission in RELATED_PERMISSIONS:
        return RELATED_PERMISSIONS[permission]
    
    # 检查是否是无关个人信息
    if permission in IRRELEVANT_PERMISSIONS:
        return IRRELEVANT_PERMISSIONS[permission]
    
    # 默认非必要但有关联个人信息
    return "非必要但有关联个人信息"