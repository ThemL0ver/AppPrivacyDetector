import pandas as pd

# 测试读取Excel文件
try:
    df = pd.read_excel('docs/apk系统权限与风险.xlsx')
    print("Excel文件读取成功")
    print("列名:", df.columns.tolist())
    print("前5行数据:")
    print(df.head())
except Exception as e:
    print(f"读取Excel文件失败: {e}")
