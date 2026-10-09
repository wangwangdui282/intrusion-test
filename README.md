# Intrusion

本地运行的安全测试编排平台：把 nmap、sqlmap、dirsearch 等命令行工具，包成网页上的可视化任务 —— 选目标、选工具、点运行、看实时日志与结构化结果。

> ⚠️ **免责声明**
> 本项目仅供**已获得明确授权**的安全测试、教学与研究使用。请勿对未授权的目标进行任何扫描或测试，使用者需自行承担全部责任。

## 目录结构

```
intrusion-test/
├─ app/                 应用本体（FastAPI 后端 + 单页前端）
│  ├─ main.py           后端：API、任务编排、子进程调用
│  ├─ run.py            启动入口（uvicorn，监听 127.0.0.1:8080）
│  └─ frontend/         前端页面
├─ tools/               第三方工具（不随仓库提供，需自行准备）
├─ runtime/             便携 Python 运行时（不随仓库提供）
├─ data/                运行数据
├─ reports/             扫描报告输出
├─ 启动控制台.vbs        一键启动（Windows）
└─ 停止控制台.vbs        一键停止（Windows）
```

## 快速开始

1. 准备 Python 3.10 或以上
2. 安装依赖：`pip install -r requirements.txt`
3. 自行准备第三方工具（nmap / sqlmap / dirsearch 等）并放入 `tools/` 目录，具体路径以 `app/main.py` 中的配置为准
4. 启动：双击 `启动控制台.vbs`，或命令行执行 `python app/run.py`
5. 浏览器打开 http://127.0.0.1:8080

## 为什么不带 tools/ 与 runtime/

体积（合计 200MB 以上）和**许可证**两方面的原因：nmap、sqlmap、dirsearch 各有自己的开源许可，nmap 对商业集成还有额外限制。把它们重新打包分发会产生许可问题，因此由使用者自行获取。

## 许可证

待补充（建议 MIT 或 Apache-2.0）。