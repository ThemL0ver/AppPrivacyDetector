import androguard
print(f"Androguard version: {androguard.__version__}")
print(f"Androguard attributes: {dir(androguard)}")

# 尝试不同的导入方式
try:
    from androguard import apk
    print("Successfully imported androguard.apk")
except ImportError as e:
    print(f"Error importing androguard.apk: {e}")

try:
    from androguard.core import apk
    print("Successfully imported androguard.core.apk")
except ImportError as e:
    print(f"Error importing androguard.core.apk: {e}")

try:
    from androguard.core.bytecodes import apk
    print("Successfully imported androguard.core.bytecodes.apk")
except ImportError as e:
    print(f"Error importing androguard.core.bytecodes.apk: {e}")
