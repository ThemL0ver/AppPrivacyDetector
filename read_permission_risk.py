from pathlib import Path

from static_analysis.permission_knowledge import PermissionKnowledgeBase


def main() -> None:
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
