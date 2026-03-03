import pandas as pd

# 读取Excel文件
excel_path = 'docs/apk系统权限与风险.xlsx'

try:
    df = pd.read_excel(excel_path)
    print("Excel文件读取成功！")
    print(f"文件形状: {df.shape}")
    print("\n列名:")
    print(df.columns.tolist())
    print("\n前10行数据:")
    print(df.head(10))
    
    # 检查权限和风险等级列
    if '权限名' in df.columns and '风险等级' in df.columns:
        print("\n权限风险等级对应关系:")
        for _, row in df.iterrows():
            permission = row['权限名']
            risk_level = row['风险等级']
            if pd.notna(risk_level):
                print(f"{permission}: {risk_level}")
    else:
        print("\n未找到'权限名'或'风险等级'列")
        
except Exception as e:
    print(f"读取Excel文件失败: {e}")
