"""
权限知识库读取与展示模块。

该脚本用于加载并验证 CSV 格式的 Android 权限知识库文件，
展示知识库的条目数量、字段结构和前若干条权限规则，
以便开发者快速确认知识库数据是否正常加载。

依赖：
- static_analysis.permission_knowledge.PermissionKnowledgeBase：权限知识库数据类
"""

from pathlib import Path

from static_analysis.permission_knowledge import PermissionKnowledgeBase


def main() -> None:
    """
    主函数：从 CSV 文件加载权限知识库并打印摘要信息。

    功能流程：
    1. 定位 d:\桌面\AppPrivacyDetector\docs\apk系统权限与风险.csv 文件
    2. 通过 PermissionKnowledgeBase.from_csv() 解析 CSV，构建知识库对象
    3. 打印知识库总条目数、字段名称列表
    4. 遍历前 10 条权限规则，打印其核心字段（权限名、风险等级、中文名、保护级别）

    返回:
        None
    """
    docs_dir = Path(__file__).resolve().parent / "docs"
    knowledge = PermissionKnowledgeBase.from_csv(docs_dir / "apk系统权限与风险.csv")

    print(f"权限知识库条目数: {len(knowledge.rows)}")
    print("字段:")
    print("  " + ", ".join(knowledge.rows[0].keys()))
    print("\n前 10 条权限规则:")
    for index, entry in enumerate(knowledge.rows[:10], start=1):
        print(
            f"{index:02d}. {entry['权限名']} -> {entry['风险等级']} / "
            f"{entry['权限中文名']} / {entry['Android保护级别']}"
        )


if __name__ == "__main__":
    main()
