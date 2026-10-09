import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

app = FastAPI()

# ============ 路径 ============
BASE_DIR = Path(__file__).resolve().parent.parent   # intrusion-test/
APP_DIR = Path(__file__).resolve().parent           # intrusion-test/app/
TOOLS_DIR = BASE_DIR / "tools"                      # intrusion-test/tools/
DATA_DIR = BASE_DIR / "data"                        # 持久化数据目录
DATA_DIR.mkdir(exist_ok=True)

HISTORY_FILE = DATA_DIR / "history.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

# ============ 工具默认路径 ============
# 便携 Python（随项目打包，免安装）。存在就用它，保证换电脑也能跑。
BUNDLED_PYTHON = BASE_DIR / "runtime" / "python" / "python.exe"

DEFAULT_TOOL_PATHS = {
    "nmap": str(TOOLS_DIR / "nmap" / "nmap.exe"),
    "sqlmap": str(TOOLS_DIR / "sqlmap" / "sqlmap.py"),
    # dirsearch 用启动器跑（启动器会把 dirsearch 目录加进 sys.path）
    "dirsearch": str(BASE_DIR / "runtime" / "run_dirsearch.py"),
    # 用项目自带的便携 Python 跑 dirsearch；没有则回退到主程序自己的解释器
    "dirsearch_python": str(BUNDLED_PYTHON) if BUNDLED_PYTHON.exists() else sys.executable,
}

TOOL_META = {
    "nmap": {
        "display": "Nmap",
        "desc": "看服务器开了哪些门（端口/服务）",
        "placeholder": "比如 127.0.0.1",
    },
    "sqlmap": {
        "display": "SQLMap",
        "desc": "测网站会不会被人用「注入」攻击",
        "placeholder": "比如 http://xxx/news.php?id=1",
    },
    "dirsearch": {
        "display": "DirSearch",
        "desc": "找网站背后藏着哪些文件和入口",
        "placeholder": "比如 http://127.0.0.1/pikachu-master/",
    },
}

# 常见 AI 供应商快捷选择
PROVIDERS = [
    {"id": "agnes",    "name": "Agnes AI",    "base_url": "https://api.agnes-ai.cn/v1",                      "model": "agnes-3.0-flash", "icon": "A", "color": "#5da8ff"},
    {"id": "openai",   "name": "OpenAI",      "base_url": "https://api.openai.com/v1",                       "model": "gpt-4o-mini", "icon": "O", "color": "#10a37f"},
    {"id": "deepseek", "name": "DeepSeek",    "base_url": "https://api.deepseek.com",                        "model": "deepseek-chat", "icon": "D", "color": "#4d6bfe"},
    {"id": "kimi",     "name": "Kimi",        "base_url": "https://api.moonshot.cn/v1",                      "model": "moonshot-v1-8k", "icon": "K", "color": "#18a058"},
    {"id": "qwen",     "name": "通义千问",    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus", "icon": "Q", "color": "#615ced"},
    {"id": "glm",      "name": "智谱 GLM",    "base_url": "https://open.bigmodel.cn/api/paas/v4",            "model": "glm-4-flash", "icon": "G", "color": "#3859ff"},
    {"id": "silicon",  "name": "SiliconFlow", "base_url": "https://api.siliconflow.cn/v1",                   "model": "Qwen/Qwen2.5-7B-Instruct", "icon": "S", "color": "#7c3aed"},
    {"id": "ollama",   "name": "Ollama",      "base_url": "http://127.0.0.1:11434/v1",                       "model": "llama3.1", "icon": "O", "color": "#94a3b8"},
    {"id": "lmstudio", "name": "LM Studio",   "base_url": "http://127.0.0.1:1234/v1",                        "model": "local-model", "icon": "L", "color": "#e8b93e"},
]

# 轨迹四关定义（供 /api/ai/stage 判断下一阶段名称）
STAGES = [
    {"key": "nmap",      "name": "Nmap 侦察",    "tool": "nmap",      "next_name": "DirSearch 目录枚举"},
    {"key": "dirsearch", "name": "DirSearch 枚举", "tool": "dirsearch", "next_name": "SQLMap 注入测试"},
    {"key": "sqlmap",    "name": "SQLMap 利用",  "tool": "sqlmap",    "next_name": "后续行动（深入利用 / 验证 / 报告）"},
    {"key": "ai",        "name": "AI 分析",      "tool": None,        "next_name": ""},
]

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*(?:\x07|\x1b\\)")


def clean_ansi(text: str) -> str:
    """去掉终端 ANSI 转义序列。"""
    return ANSI_RE.sub("", text)


# ============ 持久化读写 ============
def load_json(path, default):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def save_json(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


SETTINGS = load_json(SETTINGS_FILE, {"ai": {}, "tools": {}})
SETTINGS.setdefault("ai", {})
SETTINGS.setdefault("tools", {})
# 历史记录不跨会话保留：每次启动服务都是全新会话（工具路径、AI 设置仍保留）
RECORDS = []
# 启动时清掉上次留下的历史文件，避免磁盘上残留旧记录
try:
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()
except Exception:
    pass
# 每次启动生成一个会话标识，前端据此判断是否需要清掉浏览器里存的轨迹记录
SESSION_TOKEN = uuid.uuid4().hex

settings_lock = threading.RLock()
records_lock = threading.RLock()


def save_settings():
    with settings_lock:
        save_json(SETTINGS_FILE, SETTINGS)


def save_records():
    with records_lock:
        save_json(HISTORY_FILE, RECORDS)


def get_tool_path(key: str) -> str:
    override = (SETTINGS.get("tools") or {}).get(key, "").strip()
    return override or DEFAULT_TOOL_PATHS.get(key, "")


# ============ 命令构建（参数面板真正生效） ============
def _split_extra(extra: str) -> list:
    """把「附加参数」字符串按空格拆成参数列表（支持引号包裹）。"""
    import shlex
    try:
        return shlex.split(extra)
    except Exception:
        return extra.split()


def build_command(tool: str, target: str, params: dict) -> list:
    p = params or {}
    if tool == "nmap":
        return _build_nmap(target, p)
    elif tool == "sqlmap":
        return _build_sqlmap(target, p)
    elif tool == "dirsearch":
        return _build_dirsearch(target, p)
    raise ValueError(f"未知工具: {tool}")


def _build_nmap(target: str, p: dict) -> list:
    cmd = [get_tool_path("nmap")]

    # 预设模板（命中预设时，端口/时序/sV/sC 由预设决定，独立选项跳过避免重复）
    scan_type = p.get("scan_type", "custom")
    presets = {
        "basic":   ["-sV", "-sC", "-T4"],
        "quick":   ["-T4", "-F"],
        "full":    ["-p-", "-sV", "-T4"],
        "service": ["-sV", "-sC", "-T4"],
        "os":      ["-O", "-sV", "--osscan-guess"],
        "vuln":    ["-sV", "--script=vuln"],
        "stealth": ["-sS", "-T2", "-f"],
        "udp":     ["-sU", "-sV"],
    }
    is_preset = scan_type in presets
    if is_preset:
        cmd += presets[scan_type]

    # 端口（仅自定义模式）
    if not is_preset:
        ports = (p.get("ports") or "").strip()
        if ports:
            cmd += ["-p", ports]

    # 扫描技术
    scan_tech = (p.get("scan_tech") or "").strip()
    if scan_tech:
        cmd.append(scan_tech)

    # 时序模板（仅自定义模式）
    if not is_preset:
        timing = (p.get("timing") or "").strip()
        if timing:
            cmd.append(timing)

    # NSE 脚本 + 脚本参数
    scripts = (p.get("scripts") or "").strip()
    if scripts:
        cmd += ["--script", scripts]
    script_args = (p.get("script_args") or "").strip()
    if script_args:
        cmd += ["--script-args", script_args]

    # 开关（预设模式下 sV/sC 已含，跳过避免重复）
    if p.get("sV") and not is_preset:
        cmd.append("-sV")
    if p.get("sC") and not is_preset:
        cmd.append("-sC")
    if p.get("os_detect"):
        cmd.append("-O")
    if p.get("no_ping"):
        cmd.append("-Pn")
    if p.get("skip_dns"):
        cmd.append("-n")
    if p.get("verbose"):
        cmd.append("-v")
    if p.get("aggressive"):
        cmd.append("-A")
    if p.get("fragment"):
        cmd.append("-f")

    # 排除主机
    exclude = (p.get("exclude") or "").strip()
    if exclude:
        cmd += ["--exclude", exclude]

    # 输出文件
    if p.get("output_normal"):
        cmd += ["-oN", "output/nmap.txt"]
    if p.get("output_xml"):
        cmd += ["-oX", "output/nmap.xml"]

    # 附加参数
    extra = (p.get("extra") or "").strip()
    if extra:
        cmd += _split_extra(extra)

    cmd.append(target)
    return cmd


def _build_sqlmap(target: str, p: dict) -> list:
    cmd = [sys.executable, get_tool_path("sqlmap")]
    mode = p.get("mode", "url")

    # 注入方式
    if mode == "url":
        cmd += ["-u", target]
    elif mode == "request":
        req_file = (p.get("request_file") or "").strip()
        if req_file:
            cmd += ["-r", req_file]
    elif mode == "batch_url":
        cmd += ["-m", target]
    elif mode == "post":
        cmd += ["-u", target, "--data", p.get("data", "")]
    elif mode == "crawl":
        cmd += ["-u", target, "--crawl", str(p.get("crawl_depth", 2))]

    # HTTP 方法（仅 url 模式）
    method = (p.get("method") or "").strip()
    if method and mode == "url":
        cmd += ["--method", method]

    # 请求头/身份
    cookie = (p.get("cookie") or "").strip()
    if cookie:
        cmd += ["--cookie", cookie]
    ua = (p.get("user_agent") or "").strip()
    if ua:
        cmd += ["--user-agent", ua]
    if p.get("random_agent"):
        cmd.append("--random-agent")
    proxy = (p.get("proxy") or "").strip()
    if proxy:
        cmd += ["--proxy", proxy]

    # 注入检测
    if p.get("batch", True):
        cmd.append("--batch")
    risk = (p.get("risk") or "").strip()
    if risk:
        cmd += ["--risk", risk]
    level = (p.get("level") or "").strip()
    if level:
        cmd += ["--level", level]
    technique = (p.get("technique") or "").strip()
    if technique:
        cmd += ["--technique", technique]
    tamper = (p.get("tamper") or "").strip()
    if tamper:
        cmd += ["--tamper", tamper]
    threads = (p.get("threads") or "").strip()
    if threads:
        cmd += ["--threads", threads]
    dbms = (p.get("dbms") or "").strip()
    if dbms:
        cmd += ["--dbms", dbms]

    # 枚举操作
    if p.get("dbs"):
        cmd.append("--dbs")
    if p.get("current_db"):
        cmd.append("--current-db")
    if p.get("current_user"):
        cmd.append("--current-user")
    if p.get("users"):
        cmd.append("--users")
    if p.get("passwords"):
        cmd.append("--passwords")
    if p.get("tables"):
        cmd.append("--tables")
    if p.get("columns"):
        cmd.append("--columns")
    if p.get("dump"):
        cmd.append("--dump")
    database = (p.get("database") or "").strip()
    if database:
        cmd += ["-D", database]
    table = (p.get("table") or "").strip()
    if table:
        cmd += ["-T", table]

    # 附加参数
    extra = (p.get("extra") or "").strip()
    if extra:
        cmd += _split_extra(extra)
    return cmd


def _build_dirsearch(target: str, p: dict) -> list:
    cmd = [get_tool_path("dirsearch_python"), get_tool_path("dirsearch"), "-u", target]

    # 字典
    wordlist = (p.get("wordlist") or "").strip()
    if wordlist:
        cmd += ["-w", wordlist]

    # 扩展名
    ext = (p.get("extensions") or "").strip()
    if ext:
        cmd += ["-e", ext]
    if p.get("force_extensions"):
        cmd.append("-f")

    # 请求相关
    method = (p.get("method") or "").strip()
    if method:
        cmd += ["-m", method]
    threads = (p.get("threads") or "").strip()
    if threads:
        cmd += ["-t", threads]
    delay = (p.get("delay") or "").strip()
    if delay:
        cmd += ["--delay", delay]
    cookie = (p.get("cookie") or "").strip()
    if cookie:
        cmd += ["--cookie", cookie]
    ua = (p.get("user_agent") or "").strip()
    if ua:
        cmd += ["--user-agent", ua]
    if p.get("random_agent"):
        cmd.append("--random-agent")
    proxy = (p.get("proxy") or "").strip()
    if proxy:
        cmd += ["--proxy", proxy]
    header = (p.get("header") or "").strip()
    if header:
        cmd += ["-H", header]

    # 匹配/过滤
    status_codes = (p.get("status_codes") or "").strip()
    if status_codes:
        cmd += ["-i", status_codes]
    exclude_status = (p.get("exclude_status") or "").strip()
    if exclude_status:
        cmd += ["-x", exclude_status]
    exclude_size = (p.get("exclude_size") or "").strip()
    if exclude_size:
        cmd += ["--exclude-sizes", exclude_size]

    # 递归
    # 递归逻辑：勾了"递归"才生效；深度>0 用 -R <n>；深度=0 或空则无限递归 -r，两者永不同时出现
    if p.get("recursive"):
        recursive_depth = (p.get("recursive_depth") or "").strip()
        if recursive_depth and recursive_depth.isdigit() and int(recursive_depth) > 0:
            cmd += ["-R", recursive_depth]
        else:
            cmd.append("-r")

    # 输出
    if p.get("output_file"):
        cmd += ["-o", "output/dirsearch.txt"]
    if p.get("follow_redirect"):
        cmd.append("-F")

    # 附加参数
    extra = (p.get("extra") or "").strip()
    if extra:
        cmd += _split_extra(extra)
    return cmd


def format_command(cmd: list) -> str:
    """把命令列表拼成给人看的字符串，带空格的参数用双引号包住。"""
    parts = []
    for a in cmd:
        if any(c in a for c in " \t"):
            parts.append('"' + a + '"')
        else:
            parts.append(a)
    return " ".join(parts)


def build_env() -> dict:
    env = os.environ.copy()
    if not env.get("APPDATA"):
        userprofile = env.get("USERPROFILE") or os.path.expanduser("~")
        env["APPDATA"] = os.path.join(userprofile, "AppData", "Roaming")
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


# ============ AI 调用（OpenAI 兼容格式） ============
def get_ai_configured() -> bool:
    """判断 AI 是否已配置（有密钥即可）。"""
    ai = SETTINGS.get("ai") or {}
    return bool((ai.get("api_key") or "").strip())


def call_ai(messages: list, temperature: float = 0.4):
    """调用 OpenAI 兼容接口，返回 (文本, 错误信息)。错误信息为空表示成功。"""
    ai = SETTINGS.get("ai") or {}
    base = (ai.get("base_url") or "").strip().rstrip("/")
    model = (ai.get("model") or "").strip()
    key = (ai.get("api_key") or "").strip()
    if not base:
        return None, "还没配置 AI（缺少服务地址）"
    if not model:
        return None, "还没配置 AI（缺少模型名）"
    if not key:
        return None, "还没配置 AI（缺少密钥）"
    if base.endswith("/chat/completions"):
        url = base
    else:
        url = base + "/chat/completions"
    payload = {"model": model, "messages": messages, "temperature": temperature}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:400]
        except Exception:
            detail = ""
        hint = ""
        if e.code == 401:
            hint = "（401：密钥无效或未提供，请检查 API Key）"
        elif e.code == 403:
            hint = "（403：令牌有效但无权访问该模型，请到服务商后台确认你的密钥是否开通了对应模型的权限，或模型 ID 是否填写正确）"
        elif e.code == 404:
            hint = "（404：服务地址或模型不存在，请检查 Base URL 和模型 ID）"
        elif e.code == 429:
            hint = "（429：请求过于频繁或额度用尽，请等待后重试或检查配额）"
        return None, f"AI 服务返回错误 {e.code} {hint}\n原始响应: {detail}"
    except Exception as e:
        return None, f"调用 AI 失败: {e}"
    try:
        return data["choices"][0]["message"]["content"], None
    except Exception:
        return None, "AI 返回格式无法解析"


def parse_stage_json(text: str) -> dict:
    """从 AI 文本里解析出结构化 JSON，失败则降级为纯文本 summary。"""
    text = (text or "").strip()
    # 去掉可能的 markdown 代码块包裹
    if text.startswith("```"):
        text = text.strip("`").strip()
        if text.lower().startswith("json"):
            text = text[4:].strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            d = json.loads(text[start:end + 1])
            return {
                "summary": str(d.get("summary", "")).strip(),
                "key_findings": [str(x) for x in (d.get("key_findings") or [])][:6],
                "next_guidance": str(d.get("next_guidance", "")).strip(),
                "suggested_targets": [str(x) for x in (d.get("suggested_targets") or [])][:5],
            }
        except Exception:
            pass
    return {"summary": text, "key_findings": [], "next_guidance": "", "suggested_targets": []}


# ============ 扫描会话 ============
class ScanSession:
    def __init__(self, record: dict):
        self.id = record["id"]
        self.record = record
        self.q = queue.Queue()
        self.proc = None
        self.thread = None

    def start(self, cmd: list):
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                cwd=str(BASE_DIR),
                env=build_env(),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as e:
            self.record["status"] = "error"
            self.record["end_time"] = time.time()
            self.record["lines"].append(f"[启动失败] {e}")
            save_records()
            self.q.put(None)
            return
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                line = clean_ansi(raw.decode("utf-8", errors="replace")).rstrip("\r\n")
                self.record["lines"].append(line)
                self.q.put(line)
        finally:
            try:
                self.proc.stdout.close()
            except Exception:
                pass
            self.record["exit_code"] = self.proc.wait()
            if self.record["status"] == "running":
                self.record["status"] = "finished" if self.record["exit_code"] == 0 else "error"
            self.record["end_time"] = time.time()
            save_records()
            self.q.put(None)

    def stop(self):
        if self.record["status"] != "running":
            return
        self.record["status"] = "stopped"
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.record["end_time"] = time.time()
        self.q.put(None)


sessions = {}
sessions_lock = threading.RLock()


def start_scan(tool: str, target: str, params: dict) -> dict:
    rec = {
        "id": uuid.uuid4().hex[:12],
        "tool": tool,
        "display": TOOL_META[tool]["display"],
        "target": target,
        "params": params or {},
        "command": "",
        "status": "running",
        "start_time": time.time(),
        "end_time": None,
        "exit_code": None,
        "lines": [],
        "analysis": None,
    }
    cmd = build_command(tool, target, params)
    rec["command"] = format_command(cmd)
    session = ScanSession(rec)
    with records_lock:
        RECORDS.append(rec)
        save_records()
    with sessions_lock:
        sessions[rec["id"]] = session
    session.start(cmd)
    return rec


def get_record(scan_id: str):
    with records_lock:
        for r in RECORDS:
            if r["id"] == scan_id:
                return r
    return None


# ============ 路由：页面与工具 ============
@app.get("/", response_class=FileResponse)
async def home():
    return FileResponse(APP_DIR / "frontend" / "index.html", media_type="text/html")


@app.get("/api/tools")
async def get_tools():
    result = {}
    for key, cfg in TOOL_META.items():
        path = get_tool_path(key)
        result[key] = {
            "display": cfg["display"],
            "desc": cfg["desc"],
            "placeholder": cfg["placeholder"],
            "available": os.path.isfile(path),
            "path": path,
        }
    return JSONResponse(result)


class RunRequest(BaseModel):
    tool: str
    target: str
    params: Optional[dict] = None


@app.post("/api/run")
async def run(req: RunRequest):
    tool = req.tool
    target = (req.target or "").strip()
    if tool not in TOOL_META:
        return JSONResponse({"error": f"未知工具: {tool}"}, status_code=400)
    if not target:
        return JSONResponse({"error": "目标不能为空"}, status_code=400)
    path = get_tool_path(tool)
    if not os.path.isfile(path):
        return JSONResponse({"error": f"工具未找到: {path}，可在「工具路径」里手动设置"}, status_code=400)
    rec = start_scan(tool, target, req.params)
    return JSONResponse({"scan_id": rec["id"], "command": rec["command"]})


@app.get("/api/scan/{scan_id}/stream")
async def stream(scan_id: str):
    with sessions_lock:
        session = sessions.get(scan_id)
    if session is None:
        return JSONResponse({"error": "找不到该扫描任务"}, status_code=404)

    def gen():
        while True:
            item = session.q.get()
            if item is None:
                payload = json.dumps(
                    {"type": "done", "status": session.record["status"], "exit_code": session.record["exit_code"]},
                    ensure_ascii=False,
                )
                yield f"data: {payload}\n\n"
                break
            payload = json.dumps({"type": "line", "text": item}, ensure_ascii=False)
            yield f"data: {payload}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class StopRequest(BaseModel):
    scan_id: str


@app.post("/api/stop")
async def stop(req: StopRequest):
    with sessions_lock:
        session = sessions.get(req.scan_id)
    if session is None:
        return JSONResponse({"ok": False, "error": "not found"})
    session.stop()
    return JSONResponse({"ok": True})


# ============ 路由：历史 ============
@app.get("/api/history")
async def history():
    with records_lock:
        items = sorted(RECORDS, key=lambda r: r["start_time"], reverse=True)
    return JSONResponse([{k: v for k, v in r.items() if k != "lines"} for r in items])


@app.get("/api/scan/{scan_id}")
async def scan_detail(scan_id: str):
    rec = get_record(scan_id)
    if rec is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(rec)


# ============ 路由：AI 解读 ============
class AnalyzeRequest(BaseModel):
    task_id: str


@app.post("/api/ai/analyze")
async def ai_analyze(req: AnalyzeRequest):
    """接收任务 id，取该任务输出（末尾 8000 字），调 AI 生成中文解读。"""
    rec = get_record(req.task_id)
    if rec is None:
        return JSONResponse({"error": "任务不存在"}, status_code=404)
    if not get_ai_configured():
        return JSONResponse({"error": "还没配置 AI，请先点右上角「AI 设置」填好服务地址、模型和密钥"}, status_code=400)
    if rec.get("analysis"):
        return JSONResponse({"analysis": rec["analysis"]})
    output = "\n".join(rec.get("lines", []))[-8000:]
    if not output.strip():
        output = "（该任务没有输出内容）"
    messages = [
        {"role": "system", "content": "你是专业的网络安全分析助手，负责用通俗易懂的中文解读扫描结果。"},
        {"role": "user", "content": f"以下是安全扫描工具 {rec['display']} 对目标 {rec['target']} 的扫描输出，请用中文给出解读，包含：1) 发现了什么；2) 关键发现与风险等级；3) 可能的影响；4) 修复/防御建议。\n\n扫描输出：\n{output}"},
    ]
    text, err = call_ai(messages, temperature=0.4)
    if err:
        return JSONResponse({"error": err}, status_code=502)
    rec["analysis"] = text
    save_records()
    return JSONResponse({"analysis": text})


# ============ 路由：AI 阶段记录 ============
class StageRequest(BaseModel):
    tool: str


# 每个工具阶段的专属引导提示：让 AI 从本阶段真实输出里提取线索，给出有针对性的下一步
STAGE_GUIDANCE = {
    "nmap": (
        "这是 Nmap 侦察阶段。请从端口/服务/版本输出中提取具体线索，判断下一步该怎么走，例如：\n"
        "- 发现 80/443 等 HTTP(S) 服务 → 建议用 DirSearch 枚举 Web 目录，寻找敏感文件或隐藏入口\n"
        "- 发现 3306(MySQL)/1433(MSSQL)/5432(PostgreSQL) 等数据库端口 → 建议留意带参数的 Web 接口，或用 SQLMap 测试\n"
        "- 发现 22(SSH)/3389(RDP)/21(FTP)/23(Telnet) 等管理端口 → 可提醒弱口令/口令爆破方向（需在授权范围内）\n"
        "- 发现 445(SMB)/139(NetBIOS) → 可提醒 SMB 相关检测\n"
        "- 发现版本较老或有已知漏洞的服务 → 建议查证对应 CVE，谨慎验证\n"
        "suggested_targets 请给出可以继续测试的具体目标（形如 IP、IP:端口 或 http://IP:端口/）。"
    ),
    "dirsearch": (
        "这是 DirSearch 目录枚举阶段。请从扫出的路径/状态码中提取线索，判断哪些值得继续深入，例如：\n"
        "- 发现 .env / config.php / backup.sql / .git / 日志文件等 → 敏感信息，建议优先查看内容\n"
        "- 发现 admin / login / upload 等入口 → 建议测试登录、弱口令或文件上传\n"
        "- 发现带参数的 URL（如 xxx.php?id=1、?page=、?cat= 等）→ 很可能是注入点，建议用 SQLMap 测试\n"
        "- 发现 403/401 等受限路径 → 可提醒尝试绕过（需在授权范围内）\n"
        "suggested_targets 请给出具体 URL（优先带参数的、或疑似敏感的路径）。"
    ),
    "sqlmap": (
        "这是 SQLMap 注入利用阶段。请从爆出的数据库/表/列/用户名/密码哈希中提取线索，判断下一步，例如：\n"
        "- 爆出用户名 + 明文/弱口令 → 建议用这些凭据尝试登录后台、邮箱或其他服务，做横向越权测试\n"
        "- 爆出密码哈希 → 建议离线破解后复用，警惕同一套口令的横向复用\n"
        "- 只拿到库名/表名但没 dump → 建议继续 dump 敏感表（users/admin/accounts 等）\n"
        "- 发现当前数据库用户权限较高（如 root/sa/dba）→ 可提醒提权或写文件方向（需授权）\n"
        "- 发现多个库/多个用户 → 建议整理账号资产，评估横向影响面\n"
        "suggested_targets 请给出下一步具体目标（如要 dump 的表名、要尝试登录的入口 URL、或要横向测试的目标）。"
    ),
}


@app.post("/api/ai/stage")
async def ai_stage(req: StageRequest):
    """接收工具名，取该工具最近一次有输出的任务，让 AI 按固定格式返回 JSON，解析后返回。"""
    tool = req.tool
    if tool not in TOOL_META:
        return JSONResponse({"error": "未知工具"}, status_code=400)
    if not get_ai_configured():
        return JSONResponse({"error": "还没配置 AI，请先点右上角「AI 设置」填好服务地址、模型和密钥"}, status_code=400)

    # 取该工具最近一次有输出的任务
    candidates = [r for r in RECORDS if r["tool"] == tool and r.get("lines")]
    if not candidates:
        return JSONResponse({"error": "该阶段还没有扫描输出，请先在控制台完成一次该工具的扫描"}, status_code=400)
    latest = max(candidates, key=lambda r: r["start_time"])
    output = "\n".join(latest.get("lines", []))[-6000:]

    stage_def = next((s for s in STAGES if s["tool"] == tool), None)
    stage_name = stage_def["name"] if stage_def else tool
    next_name = stage_def["next_name"] if stage_def else "下一阶段"

    # 该阶段专属的引导说明（没有则用通用说明）
    guidance = STAGE_GUIDANCE.get(tool, "请根据输出内容判断下一步该怎么走。")

    messages = [
        {"role": "system", "content": "你是一名资深渗透测试向导，协助对已获授权的目标进行测试。你要基于本阶段的真实输出内容，给出具体、可执行的下一步建议，而不是泛泛而谈。你只输出 JSON。"},
        {"role": "user", "content": (
            f"用户刚完成「{stage_name}」阶段的扫描。\n"
            f"本阶段原始输出：\n{output}\n\n"
            f"{guidance}\n\n"
            '请严格只输出一个 JSON 对象（禁止输出 JSON 以外的任何文字，禁止用 markdown 代码块），结构如下：\n'
            '{"summary":"用3-6句话总结本阶段实际扫到了什么","key_findings":["从输出里提炼的关键发现，尽量具体，最多6条"],"next_guidance":"基于这些发现，给出下一步的具体建议（' + next_name + '方向），要可操作，但只是建议、不强迫用户照做","suggested_targets":["下一步建议的具体目标，最多5个"]}'
        )},
    ]
    text, err = call_ai(messages, temperature=0.3)
    if err:
        return JSONResponse({"error": err}, status_code=502)
    return JSONResponse(parse_stage_json(text))


# ============ 路由：设置 ============
@app.get("/api/settings")
async def get_settings():
    tools = {k: get_tool_path(k) for k in DEFAULT_TOOL_PATHS}
    return JSONResponse({
        "ai": SETTINGS.get("ai") or {},
        "tools": tools,
        "providers": PROVIDERS,
        "session_token": SESSION_TOKEN,
    })


class AiSettingsRequest(BaseModel):
    base_url: str = ""
    model: str = ""
    api_key: str = ""
    favorites: Optional[list] = None


@app.put("/api/settings/ai")
async def put_ai_settings(req: AiSettingsRequest):
    SETTINGS["ai"] = {
        "base_url": req.base_url,
        "model": req.model,
        "api_key": req.api_key,
        "favorites": req.favorites or [],
    }
    save_settings()
    return JSONResponse({"ok": True})


class ToolsSettingsRequest(BaseModel):
    nmap: str = ""
    sqlmap: str = ""
    dirsearch: str = ""
    dirsearch_python: str = ""


@app.put("/api/settings/tools")
async def put_tools_settings(req: ToolsSettingsRequest):
    SETTINGS["tools"] = {
        "nmap": req.nmap.strip(),
        "sqlmap": req.sqlmap.strip(),
        "dirsearch": req.dirsearch.strip(),
        "dirsearch_python": req.dirsearch_python.strip(),
    }
    save_settings()
    return JSONResponse({"ok": True})

# ============ 路由：外观（主题 / 背景图）============
# 主题存 localStorage，背景图存 data/ 目录（可记忆）

BACKGROUND_FILE = DATA_DIR / "background.json"


class AppearanceRequest(BaseModel):
    theme: str = ""          # "dark" / "light" / ""
    background: str = ""     # data URL（base64），空字符串表示清除
    auto_color: bool = True  # 是否从背景图取主色调


@app.get("/api/appearance")
async def get_appearance():
    data = load_json(BACKGROUND_FILE, {"theme": "light", "background": ""})
    return JSONResponse({
        "theme": data.get("theme", "light"),
        "background": data.get("background", ""),
    })


@app.put("/api/appearance")
async def put_appearance(req: AppearanceRequest):
    # 限制背景图大小（base64 后约 8MB 数据对应 ~6MB 原图）
    bg = req.background or ""
    if len(bg) > 9 * 1024 * 1024:
        return JSONResponse({"error": "背景图太大，请选择 6MB 以内的图片"}, status_code=400)
    data = {
        "theme": req.theme.strip() or "light",
        "background": bg,
    }
    save_json(BACKGROUND_FILE, data)
    return JSONResponse({"ok": True})


@app.delete("/api/appearance/background")
async def delete_background():
    data = load_json(BACKGROUND_FILE, {"theme": "light", "background": ""})
    data["background"] = ""
    save_json(BACKGROUND_FILE, data)
    return JSONResponse({"ok": True})

# ============ CVE 查询（真实数据来自 NVD 公开 API）============

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def clean_version(v: str) -> str:
    """把 2.4.49p1 / 2.4.49-1 / 2.4.49 (Ubuntu) 之类归一成 2.4.49"""
    m = re.match(r"^(\d+(?:\.\d+){1,3})", (v or "").strip())
    return m.group(1) if m else ""


# 版本号里常见但无意义的“产品名”，要去掉
_PRODUCT_NOISE = re.compile(r"\b(httpd|server|service|protocol|release|version|unix|ubuntu|debian|windows|linux|generic)\b", re.I)


def normalize_product(name: str) -> str:
    """把产品名清洗成适合查 NVD 的关键词，例如 'Apache httpd' -> 'Apache'"""
    name = re.sub(r"\(.*?\)", " ", name or "")          # 去掉括号内容
    name = _PRODUCT_NOISE.sub(" ", name)
    name = re.sub(r"[^A-Za-z0-9_.+\- ]+", " ", name)
    tokens = [t for t in name.split() if t and not t.isdigit()]
    # 最多保留前两个词，太长反而搜不到
    return " ".join(tokens[:2]).strip()


def extract_products_from_output(tool: str, output: str) -> list:
    """从扫描输出里提取「产品 + 版本」候选，用于查 CVE。返回 [{product, version, evidence}]"""
    found = []
    seen = set()

    def add(product, version, evidence):
        product = normalize_product(product)
        version = clean_version(version)
        if not product or not version or len(product) < 2:
            return
        key = (product.lower(), version)
        if key in seen:
            return
        seen.add(key)
        found.append({"product": product, "version": version, "evidence": evidence.strip()[:120]})

    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        # Nmap 风格: 80/tcp open  http    Apache httpd 2.4.49 ((Unix))
        m = re.match(r"^\d+/\w+\s+open\s+\S+\s+(.+)$", line)
        if m:
            rest = m.group(1).strip()
            tokens = rest.split()
            if len(tokens) >= 2:
                # 从前往后找第一个版本号（那才是服务的真实版本）
                for i in range(1, len(tokens)):
                    if re.match(r"^v?\d+\.\d+", tokens[i]):
                        name = " ".join(tokens[:i])
                        add(name, tokens[i].lstrip("vV"), line)
                        break
            continue

        # 通用: "Server: Apache/2.4.49" / "nginx/1.18.0"
        m2 = re.search(r"([A-Za-z][A-Za-z0-9_.+\-]{1,30})/(v?\d+\.\d+(?:\.\d+)*)", line)
        if m2:
            add(m2.group(1), m2.group(2), line)
            continue
        m3 = re.search(r"^([A-Za-z][A-Za-z0-9_.+\-]{1,30})\s+[vV]?(\d+\.\d+(?:\.\d+)*)\b", line)
        if m3:
            add(m3.group(1), m3.group(2), line)

    return found[:6]


def query_nvd(keyword: str, timeout: int = 12) -> list:
    """查询 NVD。返回 [{id, desc, score, severity, url}]，失败返回 []"""
    try:
        from urllib.parse import quote
        url = NVD_API + "?keywordSearch=" + quote(keyword) + "&resultsPerPage=5"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Intrusion-Console/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return []

    out = []
    for item in (data.get("vulnerabilities") or []):
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        desc = ""
        for d in (cve.get("descriptions") or []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score, severity = None, ""
        metrics = cve.get("metrics") or {}
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(mkey) or []
            if arr:
                cd = (arr[0].get("cvssData") or {})
                score = cd.get("baseScore")
                severity = cd.get("baseSeverity") or (arr[0].get("baseSeverity") or "")
                break
        out.append({
            "id": cid,
            "desc": (desc or "")[:400],
            "score": score,
            "severity": (severity or "").upper(),
            "url": "https://nvd.nist.gov/vuln/detail/" + cid,
        })
    return out


_nvd_last_call = [0.0]


def query_nvd_throttled(keyword: str, timeout: int = 12) -> list:
    """带限流的 NVD 查询：NVD 无 API Key 时约 6 秒 1 次，太快会被拒。"""
    wait = 6.5 - (time.time() - _nvd_last_call[0])
    if wait > 0:
        time.sleep(min(wait, 7))
    _nvd_last_call[0] = time.time()
    return query_nvd(keyword, timeout=timeout)


class CveRequest(BaseModel):
    task_id: str


@app.post("/api/cve/scan")
async def cve_scan(req: CveRequest):
    """从任务输出里提取产品特征，去 NVD 查真实 CVE。"""
    rec = get_record(req.task_id)
    if rec is None:
        return JSONResponse({"error": "任务不存在"}, status_code=404)

    output = "\n".join(rec.get("lines", []))
    if not output.strip():
        return JSONResponse({"matched": [], "queried": [], "note": "该任务没有输出内容"})

    products = extract_products_from_output(rec.get("tool", ""), output)
    if not products:
        return JSONResponse({"matched": [], "queried": [], "note": "未能从输出中识别出可查询的产品/版本特征"})

    queried, matched = [], []
    seen_ids = set()
    for p in products:
        keyword = f"{p['product']} {p['version']}".strip()
        queried.append(keyword)
        for cve in query_nvd_throttled(keyword):
            if cve["id"] in seen_ids:
                continue
            # 提高把握：描述里必须真的提到这个版本号，否则可能只是泛泛相关
            ver = p["version"]
            if ver and ver not in (cve.get("desc") or ""):
                continue
            seen_ids.add(cve["id"])
            cve["matched_on"] = keyword
            cve["evidence"] = p.get("evidence", "")
            matched.append(cve)

    # 按 CVSS 分数从高到低排
    matched.sort(key=lambda x: (x.get("score") or 0), reverse=True)

    return JSONResponse({
        "matched": matched[:12],
        "queried": queried,
        "note": "" if matched else "未在 NVD 中匹配到相关 CVE",
    })
