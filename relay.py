#!/usr/bin/env python3
"""简历猎手 AI 云端中转服务（Python 标准库，零依赖）。

exe 不再直连 AI 服务商、不再带 Key，改为调本中转；
服务商 Key 只放在服务器上的配置文件里。

接口：
  POST /api/ai/chat        聊天补全（需 X-App-Token 请求头）
  GET  /api/ai/health      健康检查
  GET  /admin              管理页（设密码 / 登录 / 改配置）
  POST /api/admin/setup    首次设置管理员密码
  POST /api/admin/login    管理员登录
  POST /api/admin/logout   管理员退出
  GET  /api/admin/config   读配置（掩码，绝不返回原值）
  POST /api/admin/config   改配置（立即写盘）
  GET  /api/admin/stats    当天调用统计

配置：环境变量 RELAY_CONFIG，默认 /root/jianli-relay/config.json。
日志只打 stdout，绝不记录 Key / Token / 密码原值。
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DEFAULT_APP_TOKEN=""  # 默认空：部署时由 TAT 命令写入 config.json，绝不硬编码

DEFAULTS = {
    "provider": "zhipu",
    "model": "glm-4.7-flash",
    "base_url": "https://open.bigmodel.cn/api/paas/v4",
    "api_key": "",
    "ai_enabled": True,
    "app_token": DEFAULT_APP_TOKEN,
    "allowed_models": ["glm-4.7-flash", "glm-4-flash-250414"],
    "admin_password_hash": None,
    "port": 8687,
    "daily_limit_per_ip": 200,
}

SESSION_TTL = 12 * 3600  # 管理员会话 12 小时
PBKDF2_ITERATIONS = 200000

CONFIG = None   # 在 main() 里初始化
USAGE = None    # 在 main() 里初始化
UPSTREAM_LOCK = threading.Lock()  # 上游全局并发 1

SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def log(msg):
    sys.stdout.write("[%s] %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stdout.flush()


# ---------------- 配置 ----------------

class Config:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.data = dict(DEFAULTS)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    self.data.update(loaded)
            except Exception as e:
                log("config load failed (%s), using defaults" % type(e).__name__)
        # 缺字段用默认值补齐，并写回（0600）
        self.save()

    def save(self):
        with self.lock:
            d = os.path.dirname(self.path) or "."
            os.makedirs(d, exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)


def config_snapshot():
    with CONFIG.lock:
        return dict(CONFIG.data)


# ---------------- 每日用量 ----------------

class Usage:
    """每 IP 每天调用计数：内存 + 每天写回配置文件旁的 usage-YYYYMMDD.json。"""

    def __init__(self, config_dir):
        self.dir = config_dir
        self.lock = threading.Lock()
        self.today = date.today().isoformat()
        self.counts = {}
        self._load()

    def _path(self):
        return os.path.join(self.dir, "usage-%s.json" % self.today)

    def _load(self):
        p = self._path()
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.counts = {str(k): int(v) for k, v in data.items()}
            except Exception:
                self.counts = {}

    def _save(self):
        tmp = self._path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.counts, f, ensure_ascii=False)
        os.replace(tmp, self._path())

    def check_and_count(self, ip, limit):
        """未超限时计数 +1 返回 True；超限返回 False（不计数）。"""
        with self.lock:
            today = date.today().isoformat()
            if today != self.today:
                self.today = today
                self.counts = {}
                self._load()
            n = self.counts.get(ip, 0)
            if n >= limit:
                return False
            self.counts[ip] = n + 1
            self._save()
            return True

    def snapshot(self):
        with self.lock:
            return self.today, dict(self.counts)


# ---------------- 密码 / 会话 ----------------

def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERATIONS, salt.hex(), dk.hex())


def verify_password(password, stored):
    try:
        _algo, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def mask_secret(value):
    """掩码：前 3 + ... + 后 4，短值只给 ***，空给空串。绝不返回原值。"""
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return value[:3] + "..." + value[-4:]


def create_session():
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token


def check_session(token):
    if not token:
        return False
    now = time.time()
    with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < now:
            del SESSIONS[token]
            return False
        return True


def drop_session(token):
    if token:
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


def session_cookie_header(token):
    if token:
        return "relay_session=%s; HttpOnly; SameSite=Lax; Path=/; Max-Age=%d" % (
            token, SESSION_TTL)
    return "relay_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"


# ---------------- 管理页 HTML ----------------

PAGE_SETUP = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>简历猎手 AI 中转 - 设置管理员密码</title>
<style>
body{font-family:sans-serif;max-width:560px;margin:40px auto;padding:0 16px}
input,button{font-size:16px;padding:8px;margin:4px 0}
input{width:100%;box-sizing:border-box}
button{cursor:pointer}
#msg{color:#b00}
</style>
</head>
<body>
<h1>简历猎手 AI 中转</h1>
<h2>设置管理员密码</h2>
<p>首次使用，请设置管理员密码（至少 6 位）。设置后即登录管理页。</p>
<input id="pw" type="password" placeholder="管理员密码（≥6 位）" autocomplete="new-password">
<button onclick="setup()">设置并登录</button>
<p id="msg"></p>
<script>
async function setup(){
  var pw=document.getElementById('pw').value;
  var r=await fetch('/api/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  var d=await r.json().catch(function(){return {};});
  if(r.ok){location.reload();}
  else{document.getElementById('msg').textContent='失败：'+(d.error||('HTTP '+r.status));}
}
</script>
</body>
</html>
"""

PAGE_LOGIN = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>简历猎手 AI 中转 - 管理员登录</title>
<style>
body{font-family:sans-serif;max-width:560px;margin:40px auto;padding:0 16px}
input,button{font-size:16px;padding:8px;margin:4px 0}
input{width:100%;box-sizing:border-box}
button{cursor:pointer}
#msg{color:#b00}
</style>
</head>
<body>
<h1>简历猎手 AI 中转</h1>
<h2>管理员登录</h2>
<input id="pw" type="password" placeholder="管理员密码" autocomplete="current-password">
<button onclick="login()">登录</button>
<p id="msg"></p>
<script>
async function login(){
  var pw=document.getElementById('pw').value;
  var r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  var d=await r.json().catch(function(){return {};});
  if(r.ok){location.reload();}
  else{document.getElementById('msg').textContent='登录失败：'+(d.error||('HTTP '+r.status));}
}
</script>
</body>
</html>
"""

PAGE_CONFIG = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>简历猎手 AI 中转 - 管理</title>
<style>
body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
label{display:block;margin:12px 0 4px;font-weight:bold}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;font-size:15px;padding:8px}
button{font-size:15px;padding:8px 16px;margin:8px 8px 0 0;cursor:pointer}
.hint{color:#666;font-size:13px}
#msg{color:#b00}
#newToken{color:#080;word-break:break-all}
</style>
</head>
<body>
<h1>简历猎手 AI 中转 - 管理</h1>
<p id="stats" class="hint"></p>
<label>服务商 provider</label>
<input id="provider" type="text">
<label>模型 model</label>
<input id="model" type="text">
<label>Base URL</label>
<input id="base_url" type="text">
<label>服务商 Key（留空表示沿用）</label>
<input id="api_key" type="password" placeholder="留空表示沿用" autocomplete="off">
<p id="apiKeyMasked" class="hint"></p>
<p id="appTokenMasked" class="hint"></p>
<label><input id="ai_enabled" type="checkbox"> 启用 AI（关掉后 exe 回落本地规则）</label>
<label>允许的模型（逗号分隔）</label>
<input id="allowed_models" type="text">
<label>每 IP 每天限额（次）</label>
<input id="daily_limit" type="text">
<label>改管理员密码（留空表示不改，≥6 位）</label>
<input id="new_password" type="password" placeholder="留空表示不改" autocomplete="new-password">
<div>
<button onclick="save()">保存</button>
<button onclick="rotate()">轮换 App-Token</button>
<button onclick="logout()">退出登录</button>
</div>
<p id="newToken"></p>
<p id="msg"></p>
<script>
async function api(path,method,body){
  var opts={method:method||'GET',headers:{'Content-Type':'application/json'}};
  if(body!==undefined){opts.body=JSON.stringify(body);}
  var r=await fetch(path,opts);
  var d=await r.json().catch(function(){return {};});
  return {ok:r.ok,status:r.status,data:d};
}
async function load(){
  var c=await api('/api/admin/config');
  if(!c.ok){document.getElementById('msg').textContent='未登录或会话过期，请刷新重新登录。';return;}
  var d=c.data;
  document.getElementById('provider').value=d.provider||'';
  document.getElementById('model').value=d.model||'';
  document.getElementById('base_url').value=d.base_url||'';
  document.getElementById('apiKeyMasked').textContent='当前 Key：'+(d.api_key_masked||'（未填）');
  document.getElementById('appTokenMasked').textContent='当前 App-Token：'+(d.app_token_masked||'（未设）');
  document.getElementById('ai_enabled').checked=!!d.ai_enabled;
  document.getElementById('allowed_models').value=(d.allowed_models||[]).join(', ');
  document.getElementById('daily_limit').value=d.daily_limit_per_ip||'';
  var s=await api('/api/admin/stats');
  if(s.ok){document.getElementById('stats').textContent='今天（'+s.data.date+'）调用 '+s.data.total_calls+' 次；分 IP：'+JSON.stringify(s.data.by_ip||{});}
}
async function save(){
  var body={
    provider:document.getElementById('provider').value.trim(),
    model:document.getElementById('model').value.trim(),
    base_url:document.getElementById('base_url').value.trim(),
    api_key:document.getElementById('api_key').value,
    ai_enabled:document.getElementById('ai_enabled').checked,
    allowed_models:document.getElementById('allowed_models').value.split(',').map(function(x){return x.trim();}).filter(Boolean)
  };
  var dl=parseInt(document.getElementById('daily_limit').value,10);
  if(!isNaN(dl)&&dl>0){body.daily_limit_per_ip=dl;}
  var np=document.getElementById('new_password').value;
  if(np){body.new_password=np;}
  var r=await api('/api/admin/config','POST',body);
  document.getElementById('msg').textContent=r.ok?'已保存。':'保存失败：'+(r.data.error||('HTTP '+r.status));
  if(r.ok){load();}
}
async function rotate(){
  if(!confirm('确定轮换 App-Token 吗？旧 Token 立即失效，exe 里的 Token 也要同步换成新的。')){return;}
  var r=await api('/api/admin/config','POST',{rotate_app_token:true});
  if(r.ok&&r.data.app_token){
    document.getElementById('newToken').textContent='新 App-Token（只显示一次，请立即复制到 exe 配置）：'+r.data.app_token;
    load();
  } else {
    document.getElementById('msg').textContent='轮换失败：'+(r.data.error||('HTTP '+r.status));
  }
}
async function logout(){
  await api('/api/admin/logout','POST',{});
  location.reload();
}
load();
</script>
</body>
</html>
"""


# ---------------- HTTP 处理 ----------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # 只记请求行，不记任何 header / body（可能含 Token / Key / 密码）
        sys.stdout.write("%s - %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()

    # ---- 工具 ----
    def send_json(self, status, obj, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_html(self, status, html):
        body = html.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > 10 * 1024 * 1024:
            return None
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def drain_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(length)

    def session_token(self):
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("relay_session="):
                return part[len("relay_session="):]
        return None

    def require_login(self):
        if not check_session(self.session_token()):
            self.send_json(401, {"error": "unauthorized"})
            return False
        return True

    # ---- 路由 ----
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            try:
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.send_header("Content-Length", "0")
                self.end_headers()
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif path == "/api/ai/health":
            self.handle_health()
        elif path == "/admin":
            self.handle_admin_page()
        elif path == "/api/admin/config":
            self.handle_admin_config_get()
        elif path == "/api/admin/stats":
            self.handle_admin_stats()
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/ai/chat":
            self.handle_chat()
        elif path == "/api/admin/setup":
            self.handle_setup()
        elif path == "/api/admin/login":
            self.handle_login()
        elif path == "/api/admin/logout":
            self.handle_logout()
        elif path == "/api/admin/config":
            self.handle_admin_config_post()
        else:
            self.drain_body()
            self.send_json(404, {"error": "not_found"})

    # ---- /api/ai ----
    def handle_health(self):
        cfg = config_snapshot()
        self.send_json(200, {
            "ok": True,
            "provider": cfg["provider"],
            "model": cfg["model"],
            "ai_enabled": cfg["ai_enabled"],
        })

    def handle_chat(self):
        cfg = config_snapshot()
        token = self.headers.get("X-App-Token")
        if not token or not hmac.compare_digest(token, cfg.get("app_token") or ""):
            return self.send_json(401, {"error": "unauthorized"})
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return self.send_json(400, {"error": "invalid_request"})
        model = body.get("model") or cfg["model"]
        if not isinstance(model, str) or model not in cfg["allowed_models"]:
            return self.send_json(400, {"error": "model_not_allowed"})
        if not cfg["ai_enabled"]:
            return self.send_json(503, {"error": "ai_disabled"})
        ip = self.client_address[0]
        try:
            limit = int(cfg["daily_limit_per_ip"])
        except (TypeError, ValueError):
            limit = DEFAULTS["daily_limit_per_ip"]
        if not USAGE.check_and_count(ip, limit):
            return self.send_json(429, {"error": "rate_limited"})
        if not UPSTREAM_LOCK.acquire(timeout=30):
            return self.send_json(429, {"error": "rate_limited"})
        try:
            self.call_upstream(cfg, model, messages, body)
        finally:
            UPSTREAM_LOCK.release()

    def call_upstream(self, cfg, model, messages, body):
        if not cfg.get("api_key"):
            log("upstream skipped: api_key not configured")
            return self.send_json(502, {"error": "upstream_failed"})
        payload = {"model": model, "messages": messages}
        if "temperature" in body:
            payload["temperature"] = body["temperature"]
        if "max_tokens" in body:
            payload["max_tokens"] = body["max_tokens"]
        url = cfg["base_url"].rstrip("/") + "/chat/completions"
        req = urllib.request.Request(
            url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + cfg["api_key"])
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            log("upstream HTTP %s" % e.code)
            return self.send_json(502, {"error": "upstream_failed"})
        except Exception as e:
            log("upstream error: %s" % type(e).__name__)
            return self.send_json(502, {"error": "upstream_failed"})
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ---- /admin 页面 ----
    def handle_admin_page(self):
        cfg = config_snapshot()
        if not cfg.get("admin_password_hash"):
            self.send_html(200, PAGE_SETUP)
        elif not check_session(self.session_token()):
            self.send_html(200, PAGE_LOGIN)
        else:
            self.send_html(200, PAGE_CONFIG)

    # ---- /api/admin ----
    def handle_setup(self):
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        pw = body.get("password")
        if not isinstance(pw, str) or len(pw) < 6:
            return self.send_json(400, {"error": "password_too_short"})
        with CONFIG.lock:
            if CONFIG.data.get("admin_password_hash"):
                return self.send_json(400, {"error": "already_setup"})
            CONFIG.data["admin_password_hash"] = hash_password(pw)
            CONFIG.save()
        token = create_session()
        self.send_json(200, {"ok": True},
                       {"Set-Cookie": session_cookie_header(token)})

    def handle_login(self):
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        pw = body.get("password")
        stored = config_snapshot().get("admin_password_hash")
        if not stored:
            return self.send_json(400, {"error": "not_setup"})
        if not isinstance(pw, str) or not verify_password(pw, stored):
            return self.send_json(401, {"error": "invalid_password"})
        token = create_session()
        self.send_json(200, {"ok": True},
                       {"Set-Cookie": session_cookie_header(token)})

    def handle_logout(self):
        drop_session(self.session_token())
        self.send_json(200, {"ok": True},
                       {"Set-Cookie": session_cookie_header("")})

    def handle_admin_config_get(self):
        if not self.require_login():
            return
        cfg = config_snapshot()
        self.send_json(200, {
            "provider": cfg["provider"],
            "model": cfg["model"],
            "base_url": cfg["base_url"],
            "api_key_masked": mask_secret(cfg["api_key"]),
            "ai_enabled": cfg["ai_enabled"],
            "app_token_masked": mask_secret(cfg["app_token"]),
            "allowed_models": list(cfg["allowed_models"]),
            "daily_limit_per_ip": cfg["daily_limit_per_ip"],
        })

    def handle_admin_config_post(self):
        if not self.require_login():
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        result = {}
        with CONFIG.lock:
            cfg = CONFIG.data
            # 先算新值并全部校验通过，再应用（避免半改状态）
            new_allowed = cfg["allowed_models"]
            if "allowed_models" in body:
                am = body["allowed_models"]
                if (not isinstance(am, list) or not am
                        or not all(isinstance(x, str) and x for x in am)):
                    return self.send_json(400, {"error": "invalid_allowed_models"})
                new_allowed = am
            new_model = cfg["model"]
            if "model" in body:
                m = body["model"]
                if not isinstance(m, str) or not m:
                    return self.send_json(400, {"error": "invalid_model"})
                new_model = m
            if new_model not in new_allowed:
                return self.send_json(400, {"error": "model_not_allowed"})
            new_pw_hash = None
            new_pw = body.get("new_password")
            if isinstance(new_pw, str) and new_pw:
                if len(new_pw) < 6:
                    return self.send_json(400, {"error": "password_too_short"})
                new_pw_hash = hash_password(new_pw)
            # 校验通过，应用
            if "provider" in body and isinstance(body["provider"], str) and body["provider"]:
                cfg["provider"] = body["provider"]
            if "base_url" in body and isinstance(body["base_url"], str) and body["base_url"]:
                cfg["base_url"] = body["base_url"].rstrip("/")
            if "ai_enabled" in body and isinstance(body["ai_enabled"], bool):
                cfg["ai_enabled"] = body["ai_enabled"]
            if "daily_limit_per_ip" in body and type(body["daily_limit_per_ip"]) is int \
                    and body["daily_limit_per_ip"] > 0:
                cfg["daily_limit_per_ip"] = body["daily_limit_per_ip"]
            if "api_key" in body and isinstance(body["api_key"], str) and body["api_key"]:
                cfg["api_key"] = body["api_key"]
            cfg["allowed_models"] = new_allowed
            cfg["model"] = new_model
            if new_pw_hash:
                cfg["admin_password_hash"] = new_pw_hash
            if body.get("rotate_app_token") is True:
                cfg["app_token"] = secrets.token_hex(16)
                result["app_token"] = cfg["app_token"]  # 只返回一次
            CONFIG.save()
        result["ok"] = True
        self.send_json(200, result)

    def handle_admin_stats(self):
        if not self.require_login():
            return
        today, counts = USAGE.snapshot()
        self.send_json(200, {
            "date": today,
            "total_calls": sum(counts.values()),
            "by_ip": counts,
        })


# ---------------- 启动 ----------------

def main():
    global CONFIG, USAGE
    config_path = os.environ.get("RELAY_CONFIG") or "/root/jianli-relay/config.json"
    CONFIG = Config(config_path)
    config_dir = os.path.dirname(os.path.abspath(config_path))
    USAGE = Usage(config_dir)
    cfg = config_snapshot()
    try:
        port = int(cfg["port"])
    except (TypeError, ValueError):
        port = DEFAULTS["port"]
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    log("relay listening on 0.0.0.0:%d provider=%s model=%s ai_enabled=%s" % (
        port, cfg["provider"], cfg["model"], cfg["ai_enabled"]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
