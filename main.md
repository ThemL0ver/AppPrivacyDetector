# `main.py` 参数操作手册

本文档说明当前项目中 `main.py` 的命令行参数含义与用法。

## 1. 基础用法

在项目根目录执行：

```powershell
.venv\Scripts\python.exe main.py [参数]
```

查看帮助：

```powershell
.venv\Scripts\python.exe main.py --help
```

## 2. 参数说明

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---:|---|
| `--skip-dynamic` | 开关 | 关闭 | 仅执行静态分析，跳过动态分析。 |
| `--only-integrated` | 开关 | 关闭 | 分析完成后只保留 `results/integrated_analysis_report.json`，清理其他结果文件。 |
| `--dynamic-timeout-per-apk` | 整数（秒） | `300` | 动态分析单个 APK 的超时时间。超时后会终止该样本并继续下一个样本。 |
| `--manual-probe-seconds` | 整数（秒） | `0` | 低覆盖时人工补采窗口时长。`0` 表示关闭人工补采。 |
| `--low-coverage-api-threshold` | 整数 | `4` | Frida 首轮命中 API 调用数低于该阈值时触发人工补采。 |
| `--manual-probe-apks` | 字符串（逗号分隔） | 空 | 指定仅对哪些 APK 启用人工补采，例如 `Mooc.apk,BaiDu.apk`。为空表示对全部样本可触发。 |

## 3. 参数细节

- `--skip-dynamic` 开启后，动态分析相关参数（如人工补采参数）不会生效。
- `--manual-probe-apks` 按 APK 文件名匹配，大小写不敏感，多个值用英文逗号 `,` 分隔。
- `--dynamic-timeout-per-apk` 在程序内部会限制最小值，建议不低于 `120` 秒。
- `--manual-probe-seconds` 建议设置为 `60~180` 秒，便于完成登录、授权和关键页面点击。

## 4. 常用命令示例

1. 全流程（静态 + 动态）：

```powershell
.venv\Scripts\python.exe main.py
```

2. 仅静态分析：

```powershell
.venv\Scripts\python.exe main.py --skip-dynamic
```

3. 全流程并限制动态单样本超时为 5 分钟：

```powershell
.venv\Scripts\python.exe main.py --dynamic-timeout-per-apk 300
```

4. 开启人工补采（所有样本都可能触发）：

```powershell
.venv\Scripts\python.exe main.py --manual-probe-seconds 120 --low-coverage-api-threshold 5
```

5. 仅对 `Mooc.apk` 和 `BaiDu.apk` 开启人工补采：

```powershell
.venv\Scripts\python.exe main.py --manual-probe-seconds 120 --low-coverage-api-threshold 5 --manual-probe-apks Mooc.apk,BaiDu.apk
```

6. 分析后只保留综合报告：

```powershell
.venv\Scripts\python.exe main.py --only-integrated
```

## 5. 推荐组合

针对“自动化命中不足”的场景，推荐：

```powershell
.venv\Scripts\python.exe main.py --only-integrated --dynamic-timeout-per-apk 300 --manual-probe-seconds 120 --low-coverage-api-threshold 5 --manual-probe-apks Mooc.apk
```

