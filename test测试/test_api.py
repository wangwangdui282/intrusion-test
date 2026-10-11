# -*- coding: utf-8 -*-
"""Intrusion v1.5 接口自动化测试（pytest）。

运行前提：
  1. 先启动服务（见仓库 启动控制台.vbs，或手动）：
       python app/run.py            # 监听 127.0.0.1:8080
  2. 本测试默认打 127.0.0.1:8080；可用环境变量覆盖：
       INTRUSION_HOST=127.0.0.1 INTRUSION_PORT=8080
  3. 渗透目标默认为本机 DVWA（Apache/PHP）：
       Nmap 扫 127.0.0.1，DirSearch 扫 http://127.0.0.1/DVWA/
       可用 INTRUSION_TARGET_IP / INTRUSION_TARGET_URL 覆盖。
  4. AI 正向用例（API-011/015）需要已配置 Agnes（或其他 OpenAI 兼容）Key。
     用环境变量注入测试用 Key（勿写死真实 Key）：
       AGNES_TEST_API_KEY=<你的测试key>
     未提供时，这两条正向用例自动 skip，不影响其余用例。

测试对象为 v1.5 的 16 个接口中的 15 个（GET / 为静态页，不纳入接口自动化）。
"""
import os
import json

import pytest

# ---------------------------------------------------------------------------
# 基础配置
# ---------------------------------------------------------------------------
HOST = os.environ.get("INTRUSION_HOST", "127.0.0.1")
PORT = os.environ.get("INTRUSION_PORT", "8080")
BASE = f"http://{HOST}:{PORT}"

# Agnes 预设（与 main.py PROVIDERS[0] 一致）；仅当环境变量提供测试 Key 时才真正调用
AGNES_BASE_URL = "https://api.agnes-ai.cn/v1"
AGNES_MODEL = "agnes-3.0-flash"
AGNES_TEST_API_KEY = os.environ.get("AGNES_TEST_API_KEY", "").strip()

# 一个稳定不可达的地址，用于触发 AI 调用失败（502），不碰真实服务
UNREACHABLE_BASE_URL = "http://127.0.0.1:9"   # 端口 9 通常无监听，快速失败

# 渗透目标：默认接本机 DVWA。可用环境变量覆盖。
TARGET_IP = os.environ.get("INTRUSION_TARGET_IP", "127.0.0.1")
TARGET_URL = os.environ.get("INTRUSION_TARGET_URL", "http://127.0.0.1/DVWA/")


def base_headers():
    return {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# 服务可用性
# ---------------------------------------------------------------------------
def _service_up():
    import urllib.request
    try:
        with urllib.request.urlopen(f"{BASE}/api/settings", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def test_000_service_up():
    assert _service_up(), (
        "服务未启动或不可达。请先启动 app/run.py（默认 127.0.0.1:8080）后再跑本测试。"
    )


# ---------------------------------------------------------------------------
# fixture：一条真实存在的扫描任务（供 API-005/007/011/025 等依赖 id 的用例）
# 通过 /api/run 起一个最快扫描（nmap quick），拿到 scan_id。
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def running_scan_id():
    import urllib.request
    body = json.dumps({
        "tool": "nmap",
        "target": TARGET_IP,
        "params": {"scan_type": "quick"},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/api/run", data=body, headers=base_headers(), method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data["scan_id"]


def _post(path, payload, expect=None, timeout=30):
    import urllib.request
    import urllib.error
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}{path}", data=body, headers=base_headers(), method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(text) if text.strip() else {})
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(text) if text.strip() else {}
        except Exception:
            return e.code, {"raw": text}


def _get(path, expect=None):
    import urllib.request
    import urllib.error
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(text) if text.strip() else text)
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(text) if text.strip() else {}
        except Exception:
            return e.code, {"raw": text}


def _put(path, payload):
    import urllib.request
    import urllib.error
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}{path}", data=body, headers=base_headers(), method="PUT"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(text) if text.strip() else {})
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(text) if text.strip() else {}
        except Exception:
            return e.code, {"raw": text}


def _delete(path):
    import urllib.request
    import urllib.error
    req = urllib.request.Request(f"{BASE}{path}", method="DELETE", headers=base_headers())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(text) if text.strip() else {}
        except Exception:
            return e.code, {"raw": text}


# ---------------------------------------------------------------------------
# API-001 ~ API-004  /api/run
# ---------------------------------------------------------------------------
def test_API_001_run_nmap_success():
    status, data = _post("/api/run", {
        "tool": "nmap", "target": TARGET_IP,
        "params": {"scan_type": "basic"},
    })
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert "scan_id" in data and "command" in data, f"响应缺少 scan_id/command：{data}"
    assert "nmap" in data["command"].lower()


def test_API_002_run_unknown_tool():
    status, data = _post("/api/run", {"tool": "evil", "target": TARGET_IP})
    assert status == 400, f"预期 400，实际 {status}：{data}"


def test_API_003_run_empty_target():
    status, data = _post("/api/run", {"tool": "nmap", "target": "", "params": {}})
    assert status == 400, f"预期 400，实际 {status}：{data}"


def test_API_004_run_tool_path_missing():
    # 前置：把 nmap 工具路径指向一个不存在的文件，使 os.path.isfile 为假
    status, _ = _put("/api/settings/tools", {
        "nmap": r"C:\does\not\exist\nmap.exe",
        "sqlmap": "", "dirsearch": "", "dirsearch_python": "",
    })
    assert status == 200, f"设置工具路径失败：{status}"
    try:
        status, data = _post("/api/run", {"tool": "nmap", "target": TARGET_IP})
        assert status == 400, f"预期 400（工具未找到），实际 {status}：{data}"
        assert "工具未找到" in json.dumps(data, ensure_ascii=False)
    finally:
        # 恢复：清掉覆盖，让后续用例可用默认路径
        _put("/api/settings/tools", {"nmap": "", "sqlmap": "", "dirsearch": "", "dirsearch_python": ""})


# ---------------------------------------------------------------------------
# API-005 / API-006  SSE 流
# ---------------------------------------------------------------------------
def test_API_005_stream_running_task(running_scan_id):
    import urllib.request
    sid = running_scan_id
    req = urllib.request.Request(f"{BASE}/api/scan/{sid}/stream")
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 200
        assert "text/event-stream" in (r.headers.get("Content-Type") or "")
        chunk = r.readline()
        assert chunk, "SSE 流立即为空"


def test_API_006_stream_not_found():
    status, data = _get(f"/api/scan/NotExist01/stream")
    assert status == 404, f"预期 404，实际 {status}：{data}"


# ---------------------------------------------------------------------------
# API-007 / API-008  stop
# ---------------------------------------------------------------------------
def test_API_007_stop_running_task(running_scan_id):
    sid = running_scan_id
    status, data = _post("/api/stop", {"scan_id": sid})
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert data.get("ok") in (True, False)  # running 时 ok=true；若已结束则 false（记录真实行为）


def test_API_008_stop_missing_task():
    # 当前实现对"停止不存在的 scan_id"返回 200 + ok:false（记录真实行为，非 404）。
    # 按"不改代码、按真实行为测"原则，本用例验证该行为；若后续改为 404 需同步更新此断言。
    status, data = _post("/api/stop", {"scan_id": "NotExist01"})
    assert status == 200, f"当前实现返回 200（ok:false），实际 {status}：{data}"
    assert data.get("ok") is False, f"停止不存在的任务应 ok:false，实际 {data}"


# ---------------------------------------------------------------------------
# API-009 / API-010  history / scan detail
# ---------------------------------------------------------------------------
def test_API_009_history_list():
    status, data = _get("/api/history")
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert isinstance(data, list), f"历史应为列表：{type(data)}"
    for item in data:
        assert "lines" not in item, "历史列表不应包含 lines"


def test_API_010_scan_detail_not_found():
    status, data = _get("/api/scan/NotExist01")
    assert status == 404, f"预期 404，实际 {status}：{data}"


# ---------------------------------------------------------------------------
# 配置 AI（为 API-011/013/015 做准备）
# ---------------------------------------------------------------------------
def _configure_ai(base_url, model, api_key):
    return _put("/api/settings/ai", {
        "base_url": base_url, "model": model, "api_key": api_key, "favorites": [],
    })


AI_ORIG = None  # 延迟到 _ensure_ai_orig() 里首次读取，避免 import 时就连服务


def _ensure_ai_orig():
    global AI_ORIG
    if AI_ORIG is None:
        status, data = _get("/api/settings")
        AI_ORIG = (data.get("ai") or {}) if isinstance(data, dict) else {}
    return AI_ORIG


def _restore_ai():
    orig = _ensure_ai_orig()
    _put("/api/settings/ai", {
        "base_url": orig.get("base_url", ""),
        "model": orig.get("model", ""),
        "api_key": orig.get("api_key", ""),
        "favorites": orig.get("favorites", []),
    })


# ---------------------------------------------------------------------------
# API-011 ~ API-014  ai/analyze
# ---------------------------------------------------------------------------
def test_API_011_ai_analyze_success(running_scan_id):
    if not AGNES_TEST_API_KEY:
        pytest.skip("未提供 AGNES_TEST_API_KEY，跳过 AI 正向用例")
    _configure_ai(AGNES_BASE_URL, AGNES_MODEL, AGNES_TEST_API_KEY)
    try:
        sid = running_scan_id
        # 真实 Agnes 生成几千字分析可能较慢，给 90s 超时避免误判
        status, data = _post("/api/ai/analyze", {"task_id": sid}, timeout=90)
        assert status == 200, f"预期 200，实际 {status}：{data}"
        assert data.get("analysis"), f"analysis 为空：{data}"
    finally:
        _restore_ai()


def test_API_012_ai_analyze_task_not_found():
    # 即便未配置 AI，任务不存在也先返回 404（代码先查 record 再查配置）
    status, data = _post("/api/ai/analyze", {"task_id": "NotExist01"})
    assert status == 404, f"预期 404，实际 {status}：{data}"


def test_API_013_ai_analyze_not_configured(running_scan_id):
    # 前置：清空 AI key（保存原值，测完恢复），构造"未配置 AI"状态
    _configure_ai(AGNES_BASE_URL, AGNES_MODEL, "")  # key 置空 => 未配置
    try:
        sid = running_scan_id
        status, data = _post("/api/ai/analyze", {"task_id": sid})
        assert status == 400, f"未配置 AI 应 400，实际 {status}：{data}"
        # 代码 L714-715 的提示文案是"还没配置 AI"；任务存在但 key 空即此路径
        assert ("还没配置 AI" in json.dumps(data, ensure_ascii=False)) or (
            "api_key" in json.dumps(data, ensure_ascii=False)
        ), f"应提示未配置 AI，实际 {data}"
    finally:
        _restore_ai()


def test_API_014_ai_analyze_service_failure():
    if not AGNES_TEST_API_KEY:
        pytest.skip("未提供 AGNES_TEST_API_KEY，跳过 AI 失败用例")
    # 用一条全新 task 避免命中 L716 analysis 缓存，确保走到 L725 call_ai 才触发 502
    # 起一条新 nmap quick 扫描作为目标（与 running_scan_id 隔离）
    _, rec = _post("/api/run", {"tool": "nmap", "target": TARGET_IP, "params": {"scan_type": "quick"}})
    fresh_sid = rec["scan_id"]
    _configure_ai(UNREACHABLE_BASE_URL, AGNES_MODEL, AGNES_TEST_API_KEY)
    try:
        status, data = _post("/api/ai/analyze", {"task_id": fresh_sid})
        assert status == 502, f"AI 调用失败应 502，实际 {status}：{data}"
        assert data.get("error"), f"应含 error 描述：{data}"
    finally:
        _restore_ai()


# ---------------------------------------------------------------------------
# API-015 ~ API-018  ai/stage
# ---------------------------------------------------------------------------
def test_API_015_ai_stage_success():
    if not AGNES_TEST_API_KEY:
        pytest.skip("未提供 AGNES_TEST_API_KEY，跳过 AI 阶段向导正向用例")
    _configure_ai(AGNES_BASE_URL, AGNES_MODEL, AGNES_TEST_API_KEY)
    try:
        status, data = _post("/api/ai/stage", {"tool": "nmap"})
        assert status == 200, f"预期 200，实际 {status}：{data}"
        assert "summary" in data, f"缺少 summary：{data}"
    finally:
        _restore_ai()


def test_API_016_ai_stage_unknown_tool():
    status, data = _post("/api/ai/stage", {"tool": "evil"})
    assert status == 400, f"预期 400，实际 {status}：{data}"


def test_API_017_ai_stage_not_configured():
    _configure_ai(AGNES_BASE_URL, AGNES_MODEL, "")  # 未配置
    try:
        status, data = _post("/api/ai/stage", {"tool": "nmap"})
        assert status == 400, f"未配置 AI 应 400，实际 {status}：{data}"
        assert "还没配置 AI" in json.dumps(data, ensure_ascii=False)
    finally:
        _restore_ai()


def test_API_018_ai_stage_no_output_for_tool():
    # L775 "还没配置 AI" 先于 L779 "没有扫描输出" 判断，
    # 所以必须先用任意 key 配好 AI，让 _ai_configured() 返回 True，
    # 才能走到 L779 "该阶段还没有扫描输出" 的 400。
    status, hist = _get("/api/history")
    has_dirsearch = any(h.get("tool") == "dirsearch" for h in hist if isinstance(hist, list))
    if has_dirsearch:
        pytest.skip("本会话已存在 dirsearch 输出，无法构造'无该工具输出'场景，跳过")
    _configure_ai(AGNES_BASE_URL, AGNES_MODEL, "sk-any-占位")  # 先配好 AI，绕过 L775
    try:
        status, data = _post("/api/ai/stage", {"tool": "dirsearch"})
        assert status == 400, f"预期 400（无扫描输出），实际 {status}：{data}"
        assert "还没有扫描输出" in json.dumps(data, ensure_ascii=False)
    finally:
        _restore_ai()


# ---------------------------------------------------------------------------
# API-019 ~ API-021  settings
# ---------------------------------------------------------------------------
def test_API_019_put_ai_settings():
    status, data = _put("/api/settings/ai", {
        "base_url": UNREACHABLE_BASE_URL,  # 占位不可达值，验证可写入
        "model": "test-model",
        "api_key": "sk-test-占位",
        "favorites": [],
    })
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert data.get("ok") is True
    _restore_ai()  # 恢复，避免影响后续


def test_API_020_get_settings():
    status, data = _get("/api/settings")
    assert status == 200, f"预期 200，实际 {status}：{data}"
    for key in ("ai", "tools", "providers", "session_token"):
        assert key in data, f"缺少字段 {key}"


def test_API_021_put_tool_settings():
    status, data = _put("/api/settings/tools", {
        "nmap": "", "sqlmap": "", "dirsearch": "", "dirsearch_python": "",
    })
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert data.get("ok") is True


# ---------------------------------------------------------------------------
# API-022 ~ API-024  appearance
# ---------------------------------------------------------------------------
def test_API_022_put_appearance_ok():
    status, data = _put("/api/appearance", {
        "theme": "dark", "background": "", "auto_color": True,
    })
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert data.get("ok") is True
    _delete("/api/appearance/background")  # 清掉，避免残留


def test_API_023_put_appearance_oversized_background():
    # 程序化生成 >9MB 的 base64 字符串，稳定触发 400（不依赖占位符）
    oversized = "A" * (9 * 1024 * 1024 + 10)
    status, data = _put("/api/appearance", {
        "theme": "dark", "background": oversized, "auto_color": True,
    })
    assert status == 400, f"预期 400（背景图太大），实际 {status}：{data}"
    assert "背景图太大" in json.dumps(data, ensure_ascii=False)


def test_API_024_delete_background():
    status, data = _delete("/api/appearance/background")
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert data.get("ok") is True


# ---------------------------------------------------------------------------
# API-025 ~ API-028  cve/scan
# ---------------------------------------------------------------------------
def test_API_025_cve_scan_success(running_scan_id):
    sid = running_scan_id
    status, data = _post("/api/cve/scan", {"task_id": sid})
    assert status == 200, f"预期 200，实际 {status}：{data}"
    # 无版本输出时也会 200（note 提示），命中时 matched 非空。二者都合法。
    assert "matched" in data and "note" in data, f"缺少 matched/note：{data}"


def test_API_026_cve_scan_no_output():
    # 构造一条"刚起就停"的任务：几乎无输出 => 触发 note="该任务没有输出内容"
    _, rec = _post("/api/run", {"tool": "nmap", "target": TARGET_IP, "params": {}})
    sid2 = rec["scan_id"]
    _post("/api/stop", {"scan_id": sid2})
    status, data = _post("/api/cve/scan", {"task_id": sid2})
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert "note" in data, f"应含 note：{data}"


def test_API_027_cve_scan_no_version_feature(running_scan_id):
    # 有输出但无"产品+版本"特征 => note="未能识别…"（依赖具体输出，尽力而为）
    status, data = _post("/api/cve/scan", {"task_id": running_scan_id})
    assert status == 200, f"预期 200，实际 {status}：{data}"
    assert "note" in data or "matched" in data


def test_API_028_cve_scan_task_not_found():
    status, data = _post("/api/cve/scan", {"task_id": "NotExist01"})
    assert status == 404, f"预期 404，实际 {status}：{data}"
