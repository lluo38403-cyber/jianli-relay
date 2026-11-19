#!/usr/bin/env python3
"""relay.py 本地验证脚本（Python 标准库 only，不连外网）。

起一个桩上游服务商（OpenAI 兼容，127.0.0.1:18099，收到请求返回固定文本）
+ relay（127.0.0.1:18098，临时配置），断言：

  1. chat 200 返回桩文本（含 temperature / max_tokens 透传、Bearer 头）
  2. 错 Token 401
  3. 无 Token 401
  4. 不允许的模型 400
  5. health 200 形状对
  6. 管理端 setup → login → config 读到掩码不漏原值 → 改 model 生效
     → 轮换 token 后旧 token 401、新 token 通
  7. stats 有计数
  8. 上游挂了 → 502
  9. ai_enabled=false 时 chat 503（health 仍 200）
  10. daily_limit 改成 2 后第 3 次 429
  11. 拉模型列表：桩返回未排序含重复的 id → 返回去重排序后的列表
  12. 未登录拉模型 → 401
  13. 草稿 Key 优先于已保存 Key（桩按 Key 返回不同列表）
  14. 上游 401 时拉模型 → 401
  15. 无 Key 时拉模型 → 400（换无 Key 配置重启 relay 再测）
  16. 管理页含服务商预置下拉框（四家地址 + 自定义）与允许模型白名单说明
     + pickModel 入口仍在
  17. 自动更新：无发布时 /api/version 与 /download/latest 都是 404
     → 未登录上传 401 → 无文件 400 → 版本格式不对 400
     → 上传 1.0.1 后 version/dowload 对得上（sha256 与内容一致）
     → 再传 1.0.2 覆盖旧版
  18. 管理页含发布新版表单：文件框 + 版本号 + 更新说明 + 上传按钮
     + 上传逻辑（/api/admin/release、正在上传、512MB 提示），且不含真实 Key/Token
     + 发布钥匙状态行（发布钥匙：已设置/未设置）
  19. 发布钥匙鉴权：未配置时带钥匙头仍 401 → 配好后正确钥匙上传成功
     → 错钥匙 401 → 无钥匙无会话 401 → 管理员会话仍能上传
     → 错钥匙+有效会话 200；管理页与 config 含 release_token_set 且不漏原值

全部通过退出 0，否则退出 1，并打印通过数。
"""

import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.path.join(HERE, "relay.py")

STUB_PORT = 18099
RELAY_PORT = 18098
APP_TOKEN = "test-app-token-abcdef"
API_KEY = "sk-test-secret-key"
ADMIN_PW = "admin123"

STUB_STATE = {"last": None}
HOLD = {"stub": None, "relay": None, "tmpdirs": []}
STATE = {"app_token": APP_TOKEN, "cookie": None}
RESULTS = []


# ---------------- 桩上游 ----------------

class StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}
        STUB_STATE["last"] = {
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": body,
        }
        resp = {
            "id": "chatcmpl-stub",
            "object": "chat.completion",
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": "桩回复：你好"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        }
        data = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # 桩模型列表：按 Authorization 里的 Key 返回不同列表（验草稿 Key 优先）
        if self.path == "/models":
            auth = self.headers.get("Authorization")
            if auth == "Bearer sk-bad-key":
                data = json.dumps(
                    {"error": {"message": "Incorrect API key"}}).encode("utf-8")
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if auth == "Bearer sk-draft-key":
                names = ["z-draft-model", "a-draft-model", "m-draft-model"]
            else:
                names = ["zebra-model", "apple-model", "mango-model", "apple-model"]
            data = json.dumps(
                {"object": "list",
                 "data": [{"id": n, "object": "model"} for n in names]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def start_stub():
    srv = ThreadingHTTPServer(("127.0.0.1", STUB_PORT), StubHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def stop_stub(srv):
    srv.shutdown()
    srv.server_close()


# ---------------- relay 子进程 ----------------

def write_config(path, **overrides):
    cfg = {
        "provider": "zhipu",
        "model": "test-model",
        "base_url": "http://127.0.0.1:%d" % STUB_PORT,
        "api_key": API_KEY,
        "ai_enabled": True,
        "app_token": APP_TOKEN,
        "allowed_models": ["test-model", "other-model"],
        "admin_password_hash": None,
        "port": RELAY_PORT,
        "daily_limit_per_ip": 200,
    }
    cfg.update(overrides)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)


class RelayProc:
    def __init__(self, config_path):
        self.config_path = config_path
        self.proc = None

    def start(self):
        env = dict(os.environ)
        env["RELAY_CONFIG"] = self.config_path
        self.proc = subprocess.Popen(
            [sys.executable, RELAY_PY], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                status, _, _, _ = http_get("/api/ai/health")
                if status == 200:
                    return
            except Exception:
                pass
            if self.proc.poll() is not None:
                out = self.proc.stdout.read() if self.proc.stdout else ""
                raise RuntimeError("relay 提前退出：%s" % out)
            time.sleep(0.2)
        raise RuntimeError("relay 15 秒内未就绪")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


# ---------------- HTTP 工具 ----------------

def http_req(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", RELAY_PORT, timeout=10)
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    cookie = resp.getheader("Set-Cookie")
    conn.close()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        parsed = None
    return resp.status, parsed, raw.decode("utf-8", "replace"), cookie


def http_get(path, headers=None):
    return http_req("GET", path, headers=headers)


def http_req_raw(method, path, data, headers=None):
    """发原始 bytes（multipart 上传 / 二进制下载用），返回
    (status, parsed_json_or_None, raw_bytes, content_type)。"""
    conn = http.client.HTTPConnection("127.0.0.1", RELAY_PORT, timeout=30)
    conn.request(method, path, body=data, headers=dict(headers or {}))
    resp = conn.getresponse()
    raw = resp.read()
    ctype = resp.getheader("Content-Type")
    conn.close()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        parsed = None
    return resp.status, parsed, raw, ctype


def multipart_body(fields, files):
    """拼 multipart/form-data：fields=[(name, value)]，
    files=[(name, filename, content_bytes)]。返回 (body, content_type)。"""
    boundary = "----relaytestboundary7d3f"
    parts = []
    for name, value in fields:
        parts.append((
            "--" + boundary + "\r\n"
            'Content-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
            % (name, value)).encode("utf-8"))
    for name, filename, content in files:
        parts.append((
            "--" + boundary + "\r\n"
            'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
            "Content-Type: application/zip\r\n\r\n"
            % (name, filename)).encode("utf-8") + content + b"\r\n")
    parts.append(("--" + boundary + "--\r\n").encode("utf-8"))
    return b"".join(parts), "multipart/form-data; boundary=" + boundary


def make_test_zip(marker):
    """确定性小 zip：两次调用 marker 不同则内容不同。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("a.txt", date_time=(2026, 1, 1, 0, 0, 0)),
                   "hello-" + marker)
        z.writestr(zipfile.ZipInfo("b/b.txt", date_time=(2026, 1, 1, 0, 0, 0)),
                   "world-" + marker)
    return buf.getvalue()


def chat(token=None, model=None, extra=None):
    headers = {}
    if token is not None:
        headers["X-App-Token"] = token
    body = {"messages": [{"role": "user", "content": "你好"}]}
    if model is not None:
        body["model"] = model
    if extra:
        body.update(extra)
    return http_req("POST", "/api/ai/chat", body=body, headers=headers)


def auth_headers():
    return {"Cookie": STATE["cookie"]} if STATE["cookie"] else {}


# ---------------- 测试用例 ----------------

def test_chat_200():
    STUB_STATE["last"] = None
    status, data, raw, _ = chat(token=STATE["app_token"],
                                extra={"temperature": 0.5, "max_tokens": 100})
    assert status == 200, "期望 200，得到 %s：%s" % (status, raw)
    assert data["choices"][0]["message"]["content"] == "桩回复：你好", "桩文本不对：%s" % raw
    last = STUB_STATE["last"]
    assert last is not None, "桩上游没收到请求"
    assert last["path"] == "/chat/completions", "上游路径不对：%s" % last["path"]
    assert last["auth"] == "Bearer " + API_KEY, "Authorization 头不对：%s" % last["auth"]
    assert last["body"]["model"] == "test-model", "模型不对：%s" % last["body"]
    assert last["body"]["temperature"] == 0.5, "temperature 未透传"
    assert last["body"]["max_tokens"] == 100, "max_tokens 未透传"


def test_wrong_token_401():
    status, data, raw, _ = chat(token="wrong-token")
    assert status == 401, "期望 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw


def test_no_token_401():
    status, data, raw, _ = chat(token=None)
    assert status == 401, "期望 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw


def test_bad_model_400():
    status, data, raw, _ = chat(token=STATE["app_token"], model="gpt-4")
    assert status == 400, "期望 400，得到 %s：%s" % (status, raw)
    assert data == {"error": "model_not_allowed"}, "错误体不对：%s" % raw


def test_health_shape():
    status, data, raw, _ = http_get("/api/ai/health")
    assert status == 200, "期望 200，得到 %s：%s" % (status, raw)
    assert data == {"ok": True, "provider": "zhipu",
                    "model": "test-model", "ai_enabled": True}, "形状不对：%s" % raw


def test_admin_flow():
    # setup：成功后直接登录（发 Cookie）
    status, data, raw, cookie = http_req(
        "POST", "/api/admin/setup", body={"password": ADMIN_PW})
    assert status == 200, "setup 期望 200，得到 %s：%s" % (status, raw)
    assert cookie and "relay_session=" in cookie, "setup 未发会话 Cookie"
    assert "HttpOnly" in cookie, "会话 Cookie 缺 HttpOnly"
    STATE["cookie"] = cookie.split(";")[0]
    # 已设密码后 setup 应 400
    status, _, raw, _ = http_req(
        "POST", "/api/admin/setup", body={"password": "other123"},
        headers=auth_headers())
    assert status == 400, "重复 setup 期望 400，得到 %s：%s" % (status, raw)
    # config：掩码，不漏原值
    status, data, raw, _ = http_req("GET", "/api/admin/config", headers=auth_headers())
    assert status == 200, "config 期望 200，得到 %s：%s" % (status, raw)
    assert API_KEY not in raw, "config 泄露了 api_key 原值"
    assert APP_TOKEN not in raw, "config 泄露了 app_token 原值"
    assert data["api_key_masked"] and data["api_key_masked"] != API_KEY
    assert data["app_token_masked"] and data["app_token_masked"] != APP_TOKEN
    # 未登录读 config → 401
    status, _, raw, _ = http_req("GET", "/api/admin/config")
    assert status == 401, "未登录 config 期望 401，得到 %s：%s" % (status, raw)
    # 错密码登录 → 401
    status, _, raw, _ = http_req(
        "POST", "/api/admin/login", body={"password": "wrongpw"})
    assert status == 401, "错密码登录期望 401，得到 %s：%s" % (status, raw)
    # 对密码登录 → 200 + Cookie
    status, _, raw, cookie2 = http_req(
        "POST", "/api/admin/login", body={"password": ADMIN_PW})
    assert status == 200, "登录期望 200，得到 %s：%s" % (status, raw)
    assert cookie2 and "relay_session=" in cookie2, "登录未发会话 Cookie"
    STATE["cookie"] = cookie2.split(";")[0]
    # 改 model 生效
    status, _, raw, _ = http_req(
        "POST", "/api/admin/config", body={"model": "other-model"},
        headers=auth_headers())
    assert status == 200, "改 model 期望 200，得到 %s：%s" % (status, raw)
    status, data, raw, _ = http_get("/api/ai/health")
    assert data["model"] == "other-model", "改 model 未生效：%s" % raw
    STUB_STATE["last"] = None
    status, _, raw, _ = chat(token=STATE["app_token"])
    assert status == 200, "改 model 后 chat 期望 200，得到 %s：%s" % (status, raw)
    assert STUB_STATE["last"]["body"]["model"] == "other-model", "上游收到的模型不对"
    # 轮换 token：旧 token 401，新 token 通
    status, data, raw, _ = http_req(
        "POST", "/api/admin/config", body={"rotate_app_token": True},
        headers=auth_headers())
    assert status == 200 and data.get("app_token"), "轮换应只返回一次新 token：%s" % raw
    new_token = data["app_token"]
    assert new_token != APP_TOKEN, "轮换后 token 没变"
    status, _, raw, _ = chat(token=APP_TOKEN)
    assert status == 401, "旧 token 期望 401，得到 %s：%s" % (status, raw)
    status, _, raw, _ = chat(token=new_token)
    assert status == 200, "新 token 期望 200，得到 %s：%s" % (status, raw)
    STATE["app_token"] = new_token


def test_stats():
    status, data, raw, _ = http_req("GET", "/api/admin/stats", headers=auth_headers())
    assert status == 200, "stats 期望 200，得到 %s：%s" % (status, raw)
    assert data["total_calls"] >= 3, "stats 计数不对：%s" % raw
    assert data["by_ip"].get("127.0.0.1", 0) >= 3, "stats 分 IP 不对：%s" % raw


def test_upstream_down_502():
    stop_stub(HOLD["stub"])
    try:
        status, data, raw, _ = chat(token=STATE["app_token"])
        assert status == 502, "上游挂了期望 502，得到 %s：%s" % (status, raw)
        assert data == {"error": "upstream_failed"}, "错误体不对：%s" % raw
        assert API_KEY not in raw, "502 里泄露了 Key"
    finally:
        HOLD["stub"] = start_stub()
        time.sleep(0.2)


def test_ai_disabled_503():
    status, _, raw, _ = http_req(
        "POST", "/api/admin/config", body={"ai_enabled": False},
        headers=auth_headers())
    assert status == 200, "关 AI 期望 200，得到 %s：%s" % (status, raw)
    status, data, raw, _ = chat(token=STATE["app_token"])
    assert status == 503, "AI 关了期望 503，得到 %s：%s" % (status, raw)
    assert data == {"error": "ai_disabled"}, "错误体不对：%s" % raw
    status, data, raw, _ = http_get("/api/ai/health")
    assert status == 200 and data["ai_enabled"] is False, "health 应仍 200 且 ai_enabled=false：%s" % raw
    status, _, raw, _ = http_req(
        "POST", "/api/admin/config", body={"ai_enabled": True},
        headers=auth_headers())
    assert status == 200, "恢复 AI 期望 200，得到 %s：%s" % (status, raw)


def test_daily_limit_429():
    # 换一份全新配置（daily_limit_per_ip=2，用量从 0 开始），重启 relay
    HOLD["relay"].stop()
    d2 = tempfile.mkdtemp(prefix="relay-test-limit-")
    HOLD["tmpdirs"].append(d2)
    cfg_path = os.path.join(d2, "config.json")
    write_config(cfg_path, daily_limit_per_ip=2)
    relay2 = RelayProc(cfg_path)
    relay2.start()
    HOLD["relay"] = relay2
    s1, _, r1, _ = chat(token=APP_TOKEN)
    assert s1 == 200, "第 1 次期望 200，得到 %s：%s" % (s1, r1)
    s2, _, r2, _ = chat(token=APP_TOKEN)
    assert s2 == 200, "第 2 次期望 200，得到 %s：%s" % (s2, r2)
    s3, data, r3, _ = chat(token=APP_TOKEN)
    assert s3 == 429, "第 3 次期望 429，得到 %s：%s" % (s3, r3)
    assert data == {"error": "rate_limited"}, "错误体不对：%s" % r3


def test_models_list():
    status, data, raw, _ = http_req(
        "POST", "/api/admin/models", body={}, headers=auth_headers())
    assert status == 200, "拉模型期望 200，得到 %s：%s" % (status, raw)
    assert data == {"models": ["apple-model", "mango-model", "zebra-model"]}, \
        "模型列表不对（应去重排序）：%s" % raw
    assert API_KEY not in raw, "拉模型泄露了 Key"


def test_models_unauth():
    status, data, raw, _ = http_req("POST", "/api/admin/models", body={})
    assert status == 401, "未登录拉模型期望 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw


def test_models_draft_priority():
    status, data, raw, _ = http_req(
        "POST", "/api/admin/models", body={"api_key": "sk-draft-key"},
        headers=auth_headers())
    assert status == 200, "草稿 Key 拉模型期望 200，得到 %s：%s" % (status, raw)
    assert data == {"models": ["a-draft-model", "m-draft-model", "z-draft-model"]}, \
        "草稿 Key 未优先（应返回草稿 Key 对应的列表）：%s" % raw


def test_models_upstream_401():
    status, data, raw, _ = http_req(
        "POST", "/api/admin/models", body={"api_key": "sk-bad-key"},
        headers=auth_headers())
    assert status == 401, "上游 401 期望 401，得到 %s：%s" % (status, raw)
    assert "sk-bad-key" not in raw, "401 里泄露了 Key"


def test_models_no_key():
    # 换一份无 Key 的配置重启 relay，重新 setup + 登录
    HOLD["relay"].stop()
    d3 = tempfile.mkdtemp(prefix="relay-test-nokey-")
    HOLD["tmpdirs"].append(d3)
    cfg_path = os.path.join(d3, "config.json")
    write_config(cfg_path, api_key="")
    relay3 = RelayProc(cfg_path)
    relay3.start()
    HOLD["relay"] = relay3
    status, _, raw, cookie = http_req(
        "POST", "/api/admin/setup", body={"password": ADMIN_PW})
    assert status == 200, "无 Key 配置下 setup 期望 200，得到 %s：%s" % (status, raw)
    STATE["cookie"] = cookie.split(";")[0]
    status, data, raw, _ = http_req(
        "POST", "/api/admin/models", body={}, headers=auth_headers())
    assert status == 400, "无 Key 拉模型期望 400，得到 %s：%s" % (status, raw)
    assert data == {"error": "no_api_key"}, "错误体不对：%s" % raw


def test_admin_page_presets():
    # 登录后打开管理页：应含服务商预置下拉框 + 白名单说明 + pickModel 入口
    status, _, raw, _ = http_req("GET", "/admin", headers=auth_headers())
    assert status == 200, "管理页期望 200，得到 %s" % status
    for needle in [
        'id="providerPreset"', 'applyPreset()', 'syncPreset()',
        'https://open.bigmodel.cn/api/paas/v4',
        'https://api.deepseek.com/v1',
        'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'https://api.moonshot.cn/v1',
        '自定义', 'pickModel()', 'model_not_allowed',
        '白名单，精确匹配',
    ]:
        assert needle in raw, "管理页缺预置内容：%s" % needle


def test_admin_page_release_form():
    # 管理页应含发布新版表单：文件框 + 版本号 + 更新说明 + 上传按钮 + 上传逻辑
    status, _, raw, _ = http_req("GET", "/admin", headers=auth_headers())
    assert status == 200, "管理页期望 200，得到 %s" % status
    for needle in [
        "发布新版", 'id="releaseFile"', 'id="releaseVersion"',
        'id="releaseNotes"', 'id="releaseBtn"', 'id="releaseMsg"',
        "uploadRelease()", "/api/admin/release",
        "正在上传", "512MB", "1.0.1",
        "发布钥匙", 'id="releaseTokenStatus"', "release_token_set",
    ]:
        assert needle in raw, "管理页缺发布表单内容：%s" % needle
    # 表单与上传逻辑里不含任何真实 Key/Token
    assert API_KEY not in raw, "管理页泄露了 api_key 原值"
    assert APP_TOKEN not in raw, "管理页泄露了 app_token 原值"


def test_release_flow():
    # 注意：此时 relay 是测试 15 重启后的无 Key 配置，app_token 是 APP_TOKEN，
    # 管理员会话在 STATE["cookie"] 里。
    token_hdr = {"X-App-Token": APP_TOKEN}
    # 无发布时 version / download 都是 404
    status, data, raw, _ = http_get("/api/version", headers=token_hdr)
    assert status == 404, "无发布 version 期望 404，得到 %s：%s" % (status, raw)
    assert data == {"error": "no_release"}, "错误体不对：%s" % raw
    status, _, raw, _ = http_get("/api/version")
    assert status == 401, "无 token version 期望 401，得到 %s：%s" % (status, raw)
    status, _, raw, _ = http_get("/api/version", headers={"X-App-Token": "wrong"})
    assert status == 401, "错 token version 期望 401，得到 %s：%s" % (status, raw)
    status, data, raw, _ = http_get("/download/latest", headers=token_hdr)
    assert status == 404, "无发布 download 期望 404，得到 %s：%s" % (status, raw)
    assert data == {"error": "no_release"}, "错误体不对：%s" % raw
    # 未登录上传 → 401
    z1 = make_test_zip("one")
    body, ctype = multipart_body([("version", "1.0.1")],
                                 [("file", "pkg.zip", z1)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body, {"Content-Type": ctype})
    assert status == 401, "未登录上传期望 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw
    # 只有 version 没有文件 → 400
    body, ctype = multipart_body([("version", "1.0.1")], [])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, **auth_headers()})
    assert status == 400, "无文件上传期望 400，得到 %s：%s" % (status, raw)
    assert data == {"error": "no_file"}, "错误体不对：%s" % raw
    # 版本格式不对 → 400
    body, ctype = multipart_body([("version", "1.0")],
                                 [("file", "pkg.zip", z1)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, **auth_headers()})
    assert status == 400, "坏版本上传期望 400，得到 %s：%s" % (status, raw)
    assert data == {"error": "invalid_version"}, "错误体不对：%s" % raw
    # 正常上传 1.0.1
    body, ctype = multipart_body([("version", "1.0.1"), ("notes", "第一版")],
                                 [("file", "pkg.zip", z1)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, **auth_headers()})
    assert status == 200, "上传 1.0.1 期望 200，得到 %s：%s" % (status, raw)
    assert data == {"ok": True, "version": "1.0.1"}, "返回体不对：%s" % raw
    # version 对得上：版本号 / 大小 / sha256 / 说明
    status, data, raw, _ = http_get("/api/version", headers=token_hdr)
    assert status == 200, "上传后 version 期望 200，得到 %s：%s" % (status, raw)
    assert data["version"] == "1.0.1", "版本号不对：%s" % raw
    assert data["size"] == len(z1), "大小不对：%s" % raw
    assert data["sha256"] == hashlib.sha256(z1).hexdigest(), "sha256 不对：%s" % raw
    assert data["notes"] == "第一版", "说明不对：%s" % raw
    # 下载内容与上传的字节完全一致
    status, _, raw_bytes, ctype = http_req_raw(
        "GET", "/download/latest", None, token_hdr)
    assert status == 200, "下载期望 200，得到 %s" % status
    assert ctype and ctype.startswith("application/zip"), "下载类型不对：%s" % ctype
    assert raw_bytes == z1, "下载内容与上传不一致（%d vs %d 字节）" % (
        len(raw_bytes), len(z1))
    # 未带 token 下载 → 401
    status, _, _, _ = http_req_raw("GET", "/download/latest", None, {})
    assert status == 401, "无 token 下载期望 401，得到 %s" % status
    # 再传 1.0.2 覆盖旧版
    z2 = make_test_zip("two")
    assert z2 != z1, "两个测试 zip 内容应不同"
    body, ctype = multipart_body([("version", "1.0.2")],
                                 [("file", "pkg.zip", z2)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, **auth_headers()})
    assert status == 200 and data == {"ok": True, "version": "1.0.2"}, \
        "覆盖上传期望 200，得到 %s：%s" % (status, raw)
    status, data, raw, _ = http_get("/api/version", headers=token_hdr)
    assert data["version"] == "1.0.2", "覆盖后版本号不对：%s" % raw
    assert data["sha256"] == hashlib.sha256(z2).hexdigest(), "覆盖后 sha256 不对"
    status, _, raw_bytes, _ = http_req_raw(
        "GET", "/download/latest", None, token_hdr)
    assert status == 200 and raw_bytes == z2, "覆盖后下载内容不对"


def test_release_token_auth():
    # 此时 relay 是测试 15 的配置（无 release_token），先验 fail closed：
    # 未配置发布钥匙时，带任何钥匙头上传都应 401
    z = make_test_zip("key-one")
    body, ctype = multipart_body([("version", "1.0.3")],
                                 [("file", "pkg.zip", z)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, "X-Release-Token": "anything"})
    assert status == 401, "未配置发布钥匙时带钥匙头应 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw
    # 换一份配了 release_token 的配置重启 relay，重新 setup + 登录
    # （注意：重启后 app_token 回到写配置时的 APP_TOKEN，STATE["app_token"] 是旧轮换值，别用它）
    HOLD["relay"].stop()
    d4 = tempfile.mkdtemp(prefix="relay-test-reltoken-")
    HOLD["tmpdirs"].append(d4)
    cfg_path = os.path.join(d4, "config.json")
    RELEASE_TOKEN = "test-release-token-xyz"
    write_config(cfg_path, release_token=RELEASE_TOKEN)
    relay4 = RelayProc(cfg_path)
    relay4.start()
    HOLD["relay"] = relay4
    status, _, raw, cookie = http_req(
        "POST", "/api/admin/setup", body={"password": ADMIN_PW})
    assert status == 200, "setup 期望 200，得到 %s：%s" % (status, raw)
    STATE["cookie"] = cookie.split(";")[0]
    # 管理页含发布钥匙状态行，且不含真实钥匙值
    status, _, raw, _ = http_req("GET", "/admin", headers=auth_headers())
    assert status == 200, "管理页期望 200，得到 %s" % status
    assert "发布钥匙" in raw, "管理页缺发布钥匙状态行"
    assert 'id="releaseTokenStatus"' in raw, "管理页缺 releaseTokenStatus 元素"
    assert RELEASE_TOKEN not in raw, "管理页泄露了发布钥匙原值"
    # config 读到 release_token_set=true，且不含原值
    status, data, raw, _ = http_req("GET", "/api/admin/config", headers=auth_headers())
    assert status == 200, "config 期望 200，得到 %s：%s" % (status, raw)
    assert data.get("release_token_set") is True, "release_token_set 应为 true：%s" % raw
    assert RELEASE_TOKEN not in raw, "config 泄露了发布钥匙原值"
    # 钥匙正确、无会话 → 200
    body, ctype = multipart_body([("version", "1.0.3"), ("notes", "钥匙发布")],
                                 [("file", "pkg.zip", z)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, "X-Release-Token": RELEASE_TOKEN})
    assert status == 200, "正确钥匙上传期望 200，得到 %s：%s" % (status, raw)
    assert data == {"ok": True, "version": "1.0.3"}, "返回体不对：%s" % raw
    # version 对得上：版本号 / 大小 / sha256 / 说明
    status, data, raw, _ = http_get("/api/version", headers={"X-App-Token": APP_TOKEN})
    assert status == 200, "钥匙上传后 version 期望 200，得到 %s：%s" % (status, raw)
    assert data["version"] == "1.0.3", "版本号不对：%s" % raw
    assert data["size"] == len(z), "大小不对：%s" % raw
    assert data["sha256"] == hashlib.sha256(z).hexdigest(), "sha256 不对：%s" % raw
    assert data["notes"] == "钥匙发布", "说明不对：%s" % raw
    # 错钥匙、无会话 → 401
    z2 = make_test_zip("key-two")
    body, ctype = multipart_body([("version", "1.0.4")],
                                 [("file", "pkg.zip", z2)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, "X-Release-Token": "wrong-key"})
    assert status == 401, "错钥匙上传期望 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw
    # 无钥匙、无会话 → 401
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body, {"Content-Type": ctype})
    assert status == 401, "无钥匙无会话上传期望 401，得到 %s：%s" % (status, raw)
    assert data == {"error": "unauthorized"}, "错误体不对：%s" % raw
    # 管理员会话仍能上传（不带钥匙头）
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, **auth_headers()})
    assert status == 200, "管理员会话上传期望 200，得到 %s：%s" % (status, raw)
    assert data == {"ok": True, "version": "1.0.4"}, "返回体不对：%s" % raw
    # 错钥匙 + 有效会话 → 200（会话通过，OR 逻辑）
    z3 = make_test_zip("key-three")
    body, ctype = multipart_body([("version", "1.0.5")],
                                 [("file", "pkg.zip", z3)])
    status, data, raw, _ = http_req_raw(
        "POST", "/api/admin/release", body,
        {"Content-Type": ctype, "X-Release-Token": "wrong-key", **auth_headers()})
    assert status == 200, "错钥匙+有效会话上传期望 200，得到 %s：%s" % (status, raw)
    assert data == {"ok": True, "version": "1.0.5"}, "返回体不对：%s" % raw


TESTS = [
    ("chat 200 返回桩文本", test_chat_200),
    ("错 Token 401", test_wrong_token_401),
    ("无 Token 401", test_no_token_401),
    ("不允许的模型 400", test_bad_model_400),
    ("health 200 形状对", test_health_shape),
    ("管理端 setup→login→config→改 model→轮换 token", test_admin_flow),
    ("stats 有计数", test_stats),
    ("拉模型列表去重排序", test_models_list),
    ("未登录拉模型 401", test_models_unauth),
    ("草稿 Key 优先拉模型", test_models_draft_priority),
    ("上游 401 时拉模型 401", test_models_upstream_401),
    ("上游挂了 → 502", test_upstream_down_502),
    ("ai_enabled=false 时 chat 503", test_ai_disabled_503),
    ("daily_limit=2 时第 3 次 429", test_daily_limit_429),
    ("无 Key 拉模型 400", test_models_no_key),
    ("管理页含服务商预置下拉框与白名单说明", test_admin_page_presets),
    ("管理页含发布新版表单", test_admin_page_release_form),
    ("自动更新：上传发布 → version/download 核对", test_release_flow),
    ("发布钥匙鉴权：未配置 401 / 正确钥匙通 / 错钥匙 401 / 会话仍通", test_release_token_auth),
]


# ---------------- 主流程 ----------------

def ensure_port_free(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        print("端口 %d 已被占用，请先停掉占用它的进程" % port)
        return False
    finally:
        s.close()
    return True


def check(name, fn):
    try:
        fn()
    except Exception as e:
        RESULTS.append((name, False, str(e)))
        print("FAIL %s：%s" % (name, e))
    else:
        RESULTS.append((name, True, ""))
        print("PASS %s" % name)


def main():
    if not ensure_port_free(STUB_PORT) or not ensure_port_free(RELAY_PORT):
        return 2
    tmpdir = tempfile.mkdtemp(prefix="relay-test-")
    HOLD["tmpdirs"].append(tmpdir)
    cfg_path = os.path.join(tmpdir, "config.json")
    write_config(cfg_path)
    HOLD["stub"] = start_stub()
    relay = RelayProc(cfg_path)
    HOLD["relay"] = relay
    try:
        relay.start()
        for name, fn in TESTS:
            check(name, fn)
    finally:
        try:
            HOLD["relay"].stop()
        except Exception:
            pass
        try:
            stop_stub(HOLD["stub"])
        except Exception:
            pass
        for d in HOLD["tmpdirs"]:
            shutil.rmtree(d, ignore_errors=True)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print("通过 %d/%d" % (passed, len(RESULTS)))
    if passed != len(RESULTS):
        for name, ok, err in RESULTS:
            if not ok:
                print("  未通过：%s（%s）" % (name, err))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
