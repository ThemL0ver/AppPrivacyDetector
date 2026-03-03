import pandas as pd

# 详细测试读取Excel文件
try:
    df = pd.read_excel('docs/apk系统权限与风险.xlsx')
    print("Excel文件读取成功")
    print(f"共 {len(df)} 行数据")
    print(f"列名: {df.columns.tolist()}")
    
    # 查看所有权限名称
    print("\n所有权限名称:")
    for i, row in df.iterrows():
        permission = row['权限名']
        risk_level = row['风险等级']
        if pd.notna(permission):
            print(f"  {i+1}. {permission}: {risk_level}")
            
    # 检查特定权限是否存在
    test_permissions = [
        'android.permission.CAMERA',
        'android.permission.READ_PHONE_STATE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.INTERNET'
    ]
    
    print("\n检查特定权限:")
    for perm in test_permissions:
        matches = df[df['权限名'] == perm]
        if not matches.empty:
            risk_level = matches.iloc[0]['风险等级']
            print(f"  {perm}: {risk_level}")
        else:
            print(f"  {perm}: 未找到")
            
except Exception as e:
    print(f"读取Excel文件失败: {e}")
    import traceback
    traceback.print_exc()
