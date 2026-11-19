#!/usr/bin/env python3
"""简历猎手 AI 云端中转服务（Python 标准库，零依赖）。

exe 不再直连 AI 服务商、不再带 Key，改为调本中转；
服务商 Key 只放在服务器上的配置文件里。

接口：
  POST /api/ai/chat        聊天补全（需 X-App-Token 请求头）
  GET  /api/ai/health      健康检查
  GET  /api/version        最新发布信息（需 X-App-Token 请求头；读 version.json）
  GET  /download/latest    下载最新安装包（需 X-App-Token 请求头；流式发回）
  GET  /admin              管理页（设密码 / 登录 / 改配置）
  GET  /logo.jpg           项目 logo（静态 image/jpeg，取自 relay.py 同目录的 logo.jpg）
  POST /api/admin/setup    首次设置管理员密码
  POST /api/admin/login    管理员登录
  POST /api/admin/logout   管理员退出
  GET  /api/admin/config   读配置（掩码，绝不返回原值）
  POST /api/admin/config   改配置（立即写盘）
  GET  /api/admin/stats    当天调用统计
  POST /api/admin/models   拉模型列表（需管理员登录，草稿 Key 优先）
  POST /api/admin/release  上传新版安装包（管理员登录 或 X-Release-Token 发布钥匙，multipart 表单）
  POST /api/auth/info      查授权状态（需 X-App-Token + HMAC 签名；新机送 1 小时试用）
  POST /api/auth/activate  激活卡密（需 X-App-Token + HMAC 签名；天卡 +24h，周卡 +7d）
  POST /api/admin/cards/generate  生成卡密（需管理员登录；同批卡共享 batch_id）
  GET  /api/admin/cards    卡密列表（需管理员登录；支持 status/type/batch/q 筛选与搜索，返回总数与各状态计数）
  POST /api/admin/cards/delete  删除卡密（需管理员登录；按卡号列表或按筛选条件删；默认只删未用/已过期，已用卡须 confirm_used=true 才删）
  POST /api/admin/machines/extend  给机器延长时间（需管理员登录）
  POST /api/admin/master-card  设万能卡（需管理员登录；空字符串 = 清掉）
  GET  /api/admin/master-card  万能卡是否已设置 + 使用记录（需管理员登录）

发布文件：安装包放配置目录下的 releases/latest.zip，
版本信息放配置目录下的 version.json（{"version","size","sha256","notes"}）。
deploy.sh 只下载 relay.py、config.example.json、jianli-relay.service、
deploy.sh、logo.jpg 五个文件，version.json 与 releases/ 不会被覆盖。

配置：环境变量 RELAY_CONFIG，默认 /root/jianli-relay/config.json。
日志只打 stdout，绝不记录 Key / Token / 密码原值。
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

DEFAULT_APP_TOKEN=""  # 默认空：部署时由 TAT 命令写入 config.json，绝不硬编码

DEFAULTS = {
    "provider": "zhipu",
    "model": "glm-4.7-flash",
    "base_url": "https://open.bigmodel.cn/api/paas/v4",
    "api_key": "",
    "ai_enabled": True,
    "app_token": DEFAULT_APP_TOKEN,
    "release_token": "",  # 发布钥匙：空表示未设置；由服务器端生成，只存 config.json
    "master_card": "",  # 万能卡：空表示未设置；由管理员在管理页设定，只存 config.json
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


# ---------------- 发布（自动更新） ----------------
# 安装包与版本信息放在配置目录旁，不进 config.json：
#   releases/latest.zip   安装包（上传时覆盖旧的）
#   version.json          {"version","size","sha256","notes"}
# deploy.sh 只下载四个代码文件，绝不碰这两个路径。

RELEASE_LOCK = threading.Lock()  # 上传串行化：同一时刻只处理一份安装包
MAX_RELEASE_BYTES = 512 * 1024 * 1024  # 单个安装包上限 512MB，超了返回 413


def release_dir():
    """配置目录（生产上是 /root/jianli-relay，测试里是临时目录）。"""
    return os.path.dirname(os.path.abspath(CONFIG.path))


def read_release_info(rdir):
    """读 version.json；不存在或格式不对返回 None（调用方当 no_release 处理）。"""
    path = os.path.join(rdir, "version.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            info = json.load(f)
    except Exception:
        return None
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    size = info.get("size")
    sha256 = info.get("sha256")
    notes = info.get("notes", "")
    if not isinstance(version, str) or not version:
        return None
    if type(size) is not int or size < 0:
        return None
    if not isinstance(sha256, str) or len(sha256) != 64:
        return None
    if not isinstance(notes, str):
        notes = ""
    return {"version": version, "size": size, "sha256": sha256, "notes": notes}


def write_release_info(rdir, info):
    """原子写 version.json（先写临时文件再替换，0600）。"""
    path = os.path.join(rdir, "version.json")
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


# ---------------- 鉴权（机器码绑定 + 纯时间制卡密） ----------------
# 存储（配置目录旁，deploy.sh 只下载四个代码文件，绝不碰它们）：
#   auth_machines.json  {machine_id: {"expire_at": int, "created_at": int, "trial": bool}}
#   auth_cards.json     {code: {"type": "day"|"week", "machine_id": str|None,
#                               "used_at": int|None, "created_at": int,
#                               "batch_id": str|None}}
#   批次：一次生成调用里的卡共享一个 batch_id（B + 生成时刻 UTC + 2 位随机码，
#   例 B20261119123045XK）和一个 batch_seq（全库单调递增的批次序号，
#   “最新批次”按它判定，不靠秒级 created_at）；2026-11-19 之前生成的旧卡
#   没有 batch_id/batch_seq，列表里按“旧批次”归类。
#   状态（列表接口现算）：used = 已绑定机器；expired = 未用且生成超过 CARD_STALE_DAYS 天
#   （只作筛选/清理标记，不影响激活——久置的卡照样能激活）；其余未用 = unused。
#   auth_master_uses.json  [{"machine_id": str, "used_at": int}, ...]（万能卡使用记录，只留最近 200 条）
# HMAC 密钥复用 app_token；请求签名 = HMAC-SHA256 hex，签 machine_id + "|" + timestamp；
# 响应签名 = HMAC-SHA256 hex，签 machine_id + "|" + expire_at + "|" +
# remaining_seconds + "|" + server_time。时间戳与服务端相差超 300 秒拒收（防重放）。
# 规范见 AUTH_API.md。

AUTH_LOCK = threading.Lock()  # 机器/卡密读写串行化
TRIAL_SECONDS = 3600        # 新机免费试用 1 小时
DAY_SECONDS = 86400         # 天卡 24 小时
WEEK_SECONDS = 604800       # 周卡 7 天
MASTER_SECONDS = 315360000  # 万能卡 10 年（可叠加、可重复用、不限机器）
MASTER_USES_MAX = 200       # 万能卡使用记录最多保留条数
AUTH_TIME_WINDOW = 300      # 时间戳允差 ±300 秒
MACHINE_ID_RE = re.compile(r"[0-9a-f]{64}")
CARD_CODE_RE = re.compile(r"JL-[DW]-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}")
CARD_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 去掉 0/O/1/I/L
CARD_STALE_DAYS = 90  # 未使用的卡超过这么多天算“已过期”（仅筛选/清理标记，不影响激活）
CARD_LIST_LIMIT_MAX = 1000  # 列表与按条件删除的单次上限
CARD_DELETE_MAX = 1000  # 单次删除上限（按卡号列表或按筛选条件都一样）


def _new_batch_id(now, existing):
    """一次生成调用的批次号：B + 生成时刻（UTC，精确到秒）+ 2 位随机码（防同秒碰撞）。"""
    base = "B" + datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = "".join(secrets.choice(CARD_ALPHABET) for _ in range(2))
    while base + suffix in existing:
        suffix = "".join(secrets.choice(CARD_ALPHABET) for _ in range(2))
    return base + suffix


def _card_status(c, now):
    """卡密状态：used 已用 / expired 久置未用（超 CARD_STALE_DAYS 天）/ unused 未用。"""
    if c.get("machine_id"):
        return "used"
    created = c.get("created_at")
    if isinstance(created, int) and created > 0 and now - created > CARD_STALE_DAYS * 86400:
        return "expired"
    return "unused"


def _auth_path(name):
    return os.path.join(release_dir(), name)


def _load_auth_store(name):
    """读鉴权存储文件；不存在或格式不对返回空 dict。"""
    try:
        with open(_auth_path(name), "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _save_auth_store(name, data):
    """原子写鉴权存储文件（先写临时文件再替换，0600）。"""
    path = _auth_path(name)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _load_master_uses():
    """读万能卡使用记录；不存在或格式不对返回空列表。"""
    try:
        with open(_auth_path("auth_master_uses.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    return data if isinstance(data, list) else []


def _record_master_use(machine_id, now):
    """记一条万能卡使用记录（调用方须已持有 AUTH_LOCK），只留最近 200 条。"""
    uses = _load_master_uses()
    uses.append({"machine_id": machine_id, "used_at": now})
    _save_auth_store("auth_master_uses.json", uses[-MASTER_USES_MAX:])


def _auth_hmac(key, message):
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _auth_sign_request(key, machine_id, timestamp):
    return _auth_hmac(key, "%s|%d" % (machine_id, timestamp))


def _auth_sign_response(key, machine_id, expire_at, remaining, server_time):
    return _auth_hmac(key, "%s|%d|%d|%d" % (machine_id, expire_at, remaining, server_time))


def _gen_card_code(card_type):
    prefix = "JL-D-" if card_type == "day" else "JL-W-"
    groups = "-".join(
        "".join(secrets.choice(CARD_ALPHABET) for _ in range(4))
        for _ in range(3))
    return prefix + groups


def _parse_boundary(content_type):
    """从 multipart Content-Type 里取 boundary（bytes），取不到返回 None。"""
    if not content_type:
        return None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            b = part[len("boundary="):].strip().strip('"')
            if b:
                return b.encode("utf-8", "ignore")
    return None


class _BodyReader:
    """按 Content-Length 精确读 body 的包装，支持 unread 回放。

    _remaining = 还没从 socket 读出的字节数；_buf = 已读出但回放的字节。
    read(n) 绝不超过剩余字节——keep-alive 连接上读超了会一直阻塞等
    永远不会来的数据。"""

    def __init__(self, rfile, length):
        self._r = rfile
        self._remaining = max(0, length)
        self._buf = b""

    def read(self, n):
        if n <= 0:
            return b""
        out = b""
        if self._buf:
            out = self._buf[:n]
            self._buf = self._buf[n:]
            if len(out) >= n:
                return out
        want = n - len(out)
        if want > 0 and self._remaining > 0:
            chunk = self._r.read(min(want, self._remaining))
            self._remaining -= len(chunk)
            out += chunk
        return out

    def readline(self, limit=-1):
        out = bytearray()
        while True:
            if self._buf:
                idx = self._buf.find(b"\n")
                if idx >= 0:
                    end = idx + 1
                    if limit >= 0:
                        end = min(end, limit - len(out))
                    if end <= 0:
                        return bytes(out)
                    out += self._buf[:end]
                    self._buf = self._buf[end:]
                    return bytes(out)
                if limit >= 0:
                    take = min(len(self._buf), limit - len(out))
                    out += self._buf[:take]
                    self._buf = self._buf[take:]
                    if len(out) >= limit:
                        return bytes(out)
                else:
                    out += self._buf
                    self._buf = b""
            if self._remaining <= 0:
                return bytes(out)
            want = 8192
            if limit >= 0:
                want = min(want, limit - len(out))
                if want <= 0:
                    return bytes(out)
            chunk = self._r.read(min(want, self._remaining))
            if not chunk:
                return bytes(out)
            self._remaining -= len(chunk)
            self._buf = chunk

    def unread(self, data):
        if data:
            self._buf = data + self._buf

    def drain(self):
        """丢弃 body 剩余部分（解析失败后保持连接干净）。"""
        while self._remaining > 0:
            chunk = self._r.read(min(65536, self._remaining))
            if not chunk:
                break
            self._remaining -= len(chunk)
        self._buf = b""


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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>简历猎手 AI 中转 - 设置管理员密码</title>
<style>
:root{
  --brand:#0B7285; --brand-dark:#096576; --ink:#1c2b31; --muted:#66787f;
  --line:#dde6e9; --bg:#f2f7fa; --card:#fff; --err:#b3261e;
  --radius:14px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  font-size:16px;line-height:1.55}
.wrap{max-width:440px;margin:0 auto;padding:64px 16px calc(40px + env(safe-area-inset-bottom))}
.logo{display:block;width:72px;height:72px;border-radius:18px;margin:0 auto 14px;
  box-shadow:0 1px 3px rgba(16,42,51,.15)}
h1{font-size:23px;line-height:1.3;margin:0;text-align:center}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:20px 18px;margin:20px 0;box-shadow:0 1px 3px rgba(16,42,51,.06)}
.card>h2{font-size:17px;line-height:1.4;margin:0 0 4px}
.hint{color:var(--muted);font-size:13px;line-height:1.6;margin:8px 0}
input[type=password]{width:100%;min-height:44px;margin-top:10px;
  font-size:16px;padding:10px 12px;border:1px solid #c3d0d5;border-radius:10px;background:#fff;color:var(--ink)}
input:focus{outline:2px solid var(--brand);outline-offset:1px;border-color:var(--brand)}
button{font-family:inherit;font-size:15px;min-height:44px;padding:10px 18px;
  border-radius:10px;border:1px solid var(--brand);background:var(--brand);color:#fff;cursor:pointer}
button:active{background:var(--brand-dark)}
.btn-block{width:100%;margin:12px 0 0}
#msg{color:var(--err);font-size:14px;margin:12px 0 0;min-height:1.4em}
@media (min-width:768px){
  .wrap{padding-top:110px}
  h1{font-size:26px}
  .card{padding:24px}
}
</style>
</head>
<body>
<div class="wrap">
<img class="logo" src="/logo.jpg" alt="简历猎手">
<h1>简历猎手 AI 中转</h1>
<div class="card">
<h2>设置管理员密码</h2>
<p class="hint">首次使用，请设置管理员密码（至少 6 位）。设置后即登录管理页。</p>
<input id="pw" type="password" placeholder="管理员密码（≥6 位）" autocomplete="new-password">
<button class="btn-block" onclick="setup()">设置并登录</button>
<p id="msg"></p>
</div>
</div>
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>简历猎手 AI 中转 - 管理员登录</title>
<style>
:root{
  --brand:#0B7285; --brand-dark:#096576; --ink:#1c2b31; --muted:#66787f;
  --line:#dde6e9; --bg:#f2f7fa; --card:#fff; --err:#b3261e;
  --radius:14px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  font-size:16px;line-height:1.55}
.wrap{max-width:440px;margin:0 auto;padding:64px 16px calc(40px + env(safe-area-inset-bottom))}
.logo{display:block;width:72px;height:72px;border-radius:18px;margin:0 auto 14px;
  box-shadow:0 1px 3px rgba(16,42,51,.15)}
h1{font-size:23px;line-height:1.3;margin:0;text-align:center}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:20px 18px;margin:20px 0;box-shadow:0 1px 3px rgba(16,42,51,.06)}
.card>h2{font-size:17px;line-height:1.4;margin:0 0 4px}
input[type=password]{width:100%;min-height:44px;margin-top:10px;
  font-size:16px;padding:10px 12px;border:1px solid #c3d0d5;border-radius:10px;background:#fff;color:var(--ink)}
input:focus{outline:2px solid var(--brand);outline-offset:1px;border-color:var(--brand)}
button{font-family:inherit;font-size:15px;min-height:44px;padding:10px 18px;
  border-radius:10px;border:1px solid var(--brand);background:var(--brand);color:#fff;cursor:pointer}
button:active{background:var(--brand-dark)}
.btn-block{width:100%;margin:12px 0 0}
#msg{color:var(--err);font-size:14px;margin:12px 0 0;min-height:1.4em}
@media (min-width:768px){
  .wrap{padding-top:110px}
  h1{font-size:26px}
  .card{padding:24px}
}
</style>
</head>
<body>
<div class="wrap">
<img class="logo" src="/logo.jpg" alt="简历猎手">
<h1>简历猎手 AI 中转</h1>
<div class="card">
<h2>管理员登录</h2>
<input id="pw" type="password" placeholder="管理员密码" autocomplete="current-password">
<button class="btn-block" onclick="login()">登录</button>
<p id="msg"></p>
</div>
</div>
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>管理面板</title>
<style>
:root{
  --brand:#0B7285; --brand-dark:#096576; --ink:#1c2b31; --muted:#66787f;
  --line:#dde6e9; --bg:#f2f7fa; --card:#fff; --ok:#0b7a4b; --err:#b3261e;
  --radius:14px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  font-size:16px;line-height:1.55}
.wrap{max-width:720px;margin:0 auto;padding:20px 16px calc(40px + env(safe-area-inset-bottom))}
.logo{display:block;width:56px;height:56px;border-radius:14px;margin:0 0 12px;
  box-shadow:0 1px 3px rgba(16,42,51,.15)}
h1{font-size:23px;line-height:1.3;margin:0}
.sub{color:var(--muted);font-size:14px;margin:6px 0 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:18px 16px;margin:18px 0;box-shadow:0 1px 3px rgba(16,42,51,.06)}
.card>h2{font-size:17px;line-height:1.4;margin:0 0 4px}
label{display:block;margin:16px 0 6px;font-weight:600;font-size:15px}
input[type=text],input[type=password],select{width:100%;min-height:44px;
  font-size:16px;padding:10px 12px;border:1px solid #c3d0d5;border-radius:10px;background:#fff;color:var(--ink)}
input[type=file]{width:100%;font-size:15px;padding:10px 0}
input:focus,select:focus{outline:2px solid var(--brand);outline-offset:1px;border-color:var(--brand)}
button{font-family:inherit;font-size:15px;min-height:44px;padding:10px 18px;margin:8px 8px 0 0;
  border-radius:10px;border:1px solid #c3d0d5;background:#fff;color:var(--ink);cursor:pointer}
button:active{background:#eef3f5}
button:disabled{opacity:.6;cursor:default}
.btn-primary{background:var(--brand);border-color:var(--brand);color:#fff}
.btn-primary:active{background:var(--brand-dark)}
.btn-sm{min-height:38px;padding:6px 14px;font-size:14px}
.btn-row{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.btn-row button{margin:0}
.form-row{display:flex;gap:8px;flex-wrap:wrap;align-items:stretch}
.form-row select{flex:1 1 150px;min-width:0}
.form-row .count{flex:0 0 110px;width:110px}
.form-row button{margin:0;flex:none}
#modelSelect{flex:1 1 160px;min-width:0}
.hint{color:var(--muted);font-size:13px;line-height:1.6;margin:8px 0}
#msg{color:var(--err);font-size:14px}
#newToken{color:var(--ok);word-break:break-all;font-size:14px}
.check{display:flex;align-items:flex-start;gap:10px;font-weight:600;cursor:pointer}
.check input{width:20px;height:20px;margin:2px 0 0;flex:none;accent-color:var(--brand)}
.list-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:14px 0 4px}
.list-head .hint{margin:0}
.list-head button{margin:0;flex:none}
.code-list{margin:4px 0}
.code-row{border:1px solid var(--line);border-radius:12px;background:#fff;padding:12px;margin:10px 0}
.code-top{display:flex;align-items:flex-start;gap:10px}
.code-top .code{flex:1;min-width:0}
.code-top button{flex:none}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:15px;
  word-break:break-all;overflow-wrap:anywhere}
.code-meta{margin-top:8px;font-size:13px;color:var(--muted);line-height:1.7}
.code-meta .t{white-space:nowrap}
.badge{display:inline-block;font-size:12px;font-weight:700;line-height:1.5;padding:2px 9px;border-radius:999px;vertical-align:1px}
.badge-unused{background:#dcf2e5;color:var(--ok)}
.badge-used{background:#e8edef;color:#5b6b72}
.badge-expired{background:#fdeeda;color:#9a6a12}
.btn-danger{color:var(--err);border-color:#e3b7b7}
.btn-danger:active{background:#fbeeee}
.btn-block{width:100%;margin:10px 0 0}
.filter-bar{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 4px}
.filter-bar input[type=search]{flex:2 1 180px;min-width:0;min-height:44px;font-size:16px;
  padding:10px 12px;border:1px solid #c3d0d5;border-radius:10px;background:#fff;color:var(--ink)}
.filter-bar select{flex:1 1 120px;min-width:0}
.filter-bar button{margin:0;flex:none}
.check-inline{display:inline-flex;align-items:center;gap:8px;font-weight:600;cursor:pointer;
  min-height:44px;margin:0}
.check-inline input{width:22px;height:22px;margin:0;flex:none;accent-color:var(--brand)}
.code-row{display:block;padding:10px 12px;margin:8px 0}
.code-line1{display:flex;align-items:center;gap:10px}
.code-line1 .code{flex:1;min-width:0;font-size:14px}
.code-line2{display:flex;align-items:center;gap:8px;margin-top:8px}
.code-line2 .code-sub{flex:1;min-width:0}
.code-row .row-check{flex:none;width:40px;height:40px;display:flex;align-items:center;
  justify-content:center;margin:0 -6px;cursor:pointer}
.code-row .row-check input{width:22px;height:22px;margin:0;accent-color:var(--brand)}
.code-row .badge{flex:none}
.row-btn{min-height:44px;padding:6px 12px;font-size:14px;flex:none}
.fab-wrap{position:fixed;right:14px;bottom:16px;display:flex;flex-direction:column;gap:10px;z-index:40}
.fab-wrap button{width:52px;height:52px;min-height:52px;border-radius:50%;padding:0;margin:0;
  font-size:14px;background:#fff;box-shadow:0 4px 14px rgba(11,60,70,.28)}
body.has-selection .fab-wrap{bottom:86px}
.batch-bar{position:fixed;left:0;right:0;bottom:0;z-index:50;display:flex;align-items:center;
  gap:10px;padding:10px 14px calc(10px + env(safe-area-inset-bottom));background:#fff;
  border-top:1px solid var(--line);box-shadow:0 -4px 14px rgba(11,60,70,.14)}
.batch-bar .bar-text{flex:1;min-width:0;font-size:15px;font-weight:600}
.batch-bar button{margin:0;flex:none}
.modal{position:fixed;inset:0;z-index:60;background:rgba(10,30,35,.45);display:flex;
  align-items:center;justify-content:center;padding:20px}
.modal-card{background:#fff;border-radius:14px;padding:20px;max-width:420px;width:100%;
  box-shadow:0 8px 28px rgba(10,30,35,.3)}
.modal-card p{margin:0 0 12px;font-size:15px;line-height:1.7}
.modal-card .check{margin:4px 0 12px}
.use-row{display:flex;justify-content:space-between;gap:12px;padding:11px 2px;border-bottom:1px solid var(--line)}
.use-row:last-child{border-bottom:0}
.use-row .mid{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;word-break:break-all}
.use-row .time{color:var(--muted);font-size:13px;white-space:nowrap;flex:none}
.empty{color:var(--muted);font-size:14px;padding:12px 2px}
@media (min-width:768px){
  .wrap{padding-top:32px}
  h1{font-size:26px}
  .card{padding:22px 24px}
}
</style>
</head>
<body>
<div class="wrap">
<img class="logo" src="/logo.jpg" alt="简历猎手">
<h1>管理面板</h1>
<p class="sub">简历猎手 AI 中转</p>
<p id="stats" class="hint"></p>

<section class="card">
<h2>AI 设置</h2>
<label>服务商（选一个，地址自动填好；Key 仍需自己贴）</label>
<select id="providerPreset" onchange="applyPreset()">
<option value="zhipu">智谱</option>
<option value="deepseek">DeepSeek</option>
<option value="qwen">通义千问</option>
<option value="moonshot">月之暗面 Kimi</option>
<option value="custom">自定义</option>
</select>
<label>服务商 provider</label>
<input id="provider" type="text">
<label>模型 model</label>
<input id="model" type="text">
<div class="btn-row">
<button id="fetchModelsBtn" onclick="fetchModels()">获取模型列表</button>
<select id="modelSelect" style="display:none" onchange="pickModel()"></select>
</div>
<p id="modelsMsg" class="hint"></p>
<label>Base URL</label>
<input id="base_url" type="text">
<label>服务商 Key（留空表示沿用）</label>
<input id="api_key" type="password" placeholder="留空表示沿用" autocomplete="off">
<p id="apiKeyMasked" class="hint"></p>
<p id="appTokenMasked" class="hint"></p>
<label class="check"><input id="ai_enabled" type="checkbox"><span>启用 AI（关掉后 exe 回落本地规则）</span></label>
<label>允许的模型（逗号分隔）</label>
<input id="allowed_models" type="text">
<p class="hint">白名单，精确匹配。「模型」栏当前填的值必须一字不差地列在这里，否则 exe 的请求会被拒（model_not_allowed）。</p>
<label>每 IP 每天限额（次）</label>
<input id="daily_limit" type="text">
<label>改管理员密码（留空表示不改，≥6 位）</label>
<input id="new_password" type="password" placeholder="留空表示不改" autocomplete="new-password">
<div class="btn-row">
<button class="btn-primary" onclick="save()">保存</button>
<button onclick="rotate()">轮换 App-Token</button>
<button onclick="logout()">退出登录</button>
</div>
<p id="newToken"></p>
<p id="msg"></p>
</section>

<section class="card">
<h2>发布新版</h2>
<p class="hint">上传新的安装包（zip），用户打开面板时会自动收到更新提示。只传 zip，超过 512MB 传不上去。</p>
<p id="releaseTokenStatus" class="hint"></p>
<label>安装包（zip）</label>
<input id="releaseFile" type="file" accept=".zip,application/zip">
<label>版本号</label>
<input id="releaseVersion" type="text" placeholder="例如 1.0.1" inputmode="numeric">
<label>更新说明</label>
<input id="releaseNotes" type="text" placeholder="例如：修复了投递失败的问题（可选）">
<div class="btn-row">
<button id="releaseBtn" class="btn-primary" onclick="uploadRelease()">上传并发布</button>
</div>
<p id="releaseMsg"></p>
</section>

<section class="card">
<h2>卡密管理</h2>
<p class="hint">天卡 24 小时，周卡 7 天。卡密首次激活即绑定那台机器并作废，别人再用会报错；同一台机器多张卡时间叠加。</p>
<label>生成卡密</label>
<div class="form-row">
<select id="cardType">
<option value="day">天卡（24 小时）</option>
<option value="week">周卡（7 天）</option>
</select>
<input id="cardCount" class="count" type="text" value="1" placeholder="数量 1-100" inputmode="numeric">
<button class="btn-primary" onclick="genCards()">生成</button>
</div>
<p id="cardsNew" class="hint"></p>
<div id="cardsNewHead" class="list-head" style="display:none">
<span id="cardsNewCount" class="hint"></span>
<button class="btn-sm" onclick="copyNewAll(this)">复制全部</button>
</div>
<div id="cardsNewList" class="code-list"></div>
<p class="hint">卡密列表（最新在前，只显示机器码前 12 位；未使用的卡超过 90 天算“已过期”，只作清理筛选，照样能激活）。默认只显示前 10 张。</p>
<div class="filter-bar">
<input id="cardSearch" type="search" placeholder="搜卡密或机器码" autocomplete="off">
<select id="cardStatus">
<option value="all">全部状态</option>
<option value="unused">未使用</option>
<option value="used">已使用</option>
<option value="expired">已过期</option>
</select>
<select id="cardTypeFilter">
<option value="all">全部类型</option>
<option value="day">天卡</option>
<option value="week">周卡</option>
</select>
<label class="check-inline"><input id="cardLatest" type="checkbox"><span>仅看最新批次</span></label>
<button class="btn-primary" onclick="loadCards()">筛选</button>
<button onclick="copyFiltered(this)">复制当前筛选结果</button>
<button class="btn-danger" onclick="deleteFiltered(this)">删除当前筛选结果</button>
</div>
<div id="cardsHead" class="list-head" style="display:none">
<label class="check-inline"><input id="cardsSelectAll" type="checkbox" onchange="toggleSelectAll(this)"><span id="cardsCount" class="hint">共 0 张</span></label>
<span id="cardsSelCount" class="hint"></span>
</div>
<div id="cardsTable" class="code-list"></div>
<button id="cardsExpand" class="btn-block" style="display:none" onclick="expandCards()">展开全部</button>
<p id="cardsMsg"></p>
<label>给机器延长时间（售后手动）</label>
<input id="extendMachine" type="text" placeholder="机器码（64 位）">
<input id="extendDays" type="text" placeholder="延长天数，如 7（支持小数，0.5 = 12 小时）">
<div class="btn-row"><button class="btn-primary" onclick="extendMachine()">延长</button></div>
<p id="extendMsg"></p>
</section>

<section class="card">
<h2>万能卡</h2>
<p class="hint">内部测试与售后补时用：输入这张卡，任何机器都能直接加 10 年，可重复用、不绑定机器。只留给自己人，绝不要发给买家。</p>
<label>万能卡（至少 12 个字符）</label>
<input id="masterCard" type="password" placeholder="输入后点「保存/更换」；留空保存 = 清掉万能卡">
<p id="masterCardStatus" class="hint"></p>
<div class="btn-row"><button class="btn-primary" onclick="saveMasterCard()">保存/更换</button></div>
<p id="masterCardMsg"></p>
<p class="hint">使用记录（最新在前，只显示机器码前 12 位）</p>
<div class="btn-row"><button onclick="loadMasterCard()">刷新使用记录</button></div>
<div id="masterUsesTable" class="use-list"></div>
<p id="masterUsesMsg"></p>
</section>
</div>
<div class="fab-wrap">
<button onclick="window.scrollTo({top:0,behavior:'smooth'})">回顶</button>
<button onclick="window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})">到底</button>
</div>
<div id="batchBar" class="batch-bar" style="display:none">
<span id="batchBarText" class="bar-text"></span>
<button onclick="copySelected(this)">复制所选</button>
<button class="btn-danger" onclick="deleteSelected(this)">删除所选</button>
</div>
<div id="confirmModal" class="modal" style="display:none">
<div class="modal-card">
<p id="confirmText"></p>
<label id="confirmUsedWrap" class="check" style="display:none"><input id="confirmUsed" type="checkbox"><span>同时删除已使用的卡</span></label>
<div class="btn-row"><button class="btn-primary" onclick="confirmDelete()">确认删除</button><button onclick="closeConfirm()">取消</button></div>
</div>
</div>
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
  document.getElementById('releaseTokenStatus').textContent='发布钥匙：'+(d.release_token_set?'已设置':'未设置');
  document.getElementById('ai_enabled').checked=!!d.ai_enabled;
  document.getElementById('allowed_models').value=(d.allowed_models||[]).join(', ');
  document.getElementById('daily_limit').value=d.daily_limit_per_ip||'';
  syncPreset();
  var s=await api('/api/admin/stats');
  if(s.ok){document.getElementById('stats').textContent='今天（'+s.data.date+'）调用 '+s.data.total_calls+' 次；分 IP：'+JSON.stringify(s.data.by_ip||{});}
  loadCards();
  loadMasterCard();
}
var PRESETS={
  zhipu:{provider:'zhipu',base_url:'https://open.bigmodel.cn/api/paas/v4'},
  deepseek:{provider:'deepseek',base_url:'https://api.deepseek.com/v1'},
  qwen:{provider:'qwen',base_url:'https://dashscope.aliyuncs.com/compatible-mode/v1'},
  moonshot:{provider:'moonshot',base_url:'https://api.moonshot.cn/v1'}
};
function applyPreset(){
  var p=PRESETS[document.getElementById('providerPreset').value];
  if(!p){return;} // 自定义：provider 与 Base URL 保持手填，不自动改
  document.getElementById('provider').value=p.provider;
  document.getElementById('base_url').value=p.base_url;
}
function syncPreset(){
  // 按当前 provider / Base URL 反推下拉框应选哪项，对不上就选自定义
  var pv=document.getElementById('provider').value.trim();
  var bu=document.getElementById('base_url').value.trim().replace(/\/+$/,'');
  var sel=document.getElementById('providerPreset');
  sel.value='custom';
  Object.keys(PRESETS).forEach(function(k){
    if(PRESETS[k].provider===pv&&PRESETS[k].base_url===bu){sel.value=k;}
  });
}
async function fetchModels(){
  var btn=document.getElementById('fetchModelsBtn');
  var sel=document.getElementById('modelSelect');
  var msg=document.getElementById('modelsMsg');
  btn.disabled=true;
  btn.textContent='拉取中…';
  msg.textContent='';
  var r=await api('/api/admin/models','POST',{
    base_url:document.getElementById('base_url').value.trim(),
    api_key:document.getElementById('api_key').value
  });
  btn.disabled=false;
  btn.textContent='获取模型列表';
  if(!r.ok||!Array.isArray(r.data.models)){
    if(r.status===401){msg.textContent='拉取失败：Key 无效或地址不对';}
    else if(r.status===400){msg.textContent='拉取失败：请先填写服务商 Key';}
    else{msg.textContent='拉取失败：服务商地址不对或网络不通';}
    return;
  }
  var models=r.data.models;
  sel.innerHTML='';
  var ph=document.createElement('option');
  ph.value=''; ph.textContent='请选择模型…'; sel.appendChild(ph);
  models.forEach(function(m){
    var o=document.createElement('option');
    o.value=m; o.textContent=m; sel.appendChild(o);
  });
  sel.style.display=models.length?'':'none';
  msg.textContent=models.length?('已拉到 '+models.length+' 个模型，选一个填入后点「保存」生效。'):'拉取成功，但该服务商没有返回模型。';
}
function pickModel(){
  var sel=document.getElementById('modelSelect');
  var v=sel.value;
  if(!v){return;}
  document.getElementById('model').value=v;
  var am=document.getElementById('allowed_models').value.split(',').map(function(x){return x.trim();}).filter(Boolean);
  if(am.indexOf(v)===-1){am.push(v);document.getElementById('allowed_models').value=am.join(', ');}
  document.getElementById('modelsMsg').textContent='已选 '+v+'，点「保存」生效。';
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
var MAX_RELEASE_BYTES=512*1024*1024; // 后端上限 512MB，超了返回 413
function fmtSize(n){
  if(n>=1024*1024){return (n/1024/1024).toFixed(1)+' MB';}
  if(n>=1024){return (n/1024).toFixed(1)+' KB';}
  return n+' 字节';
}
function releaseErrText(code,status){
  // 后端错误码转大白话（后端原样返回，这里只做文案映射）
  var map={
    unauthorized:'未登录或会话过期，请刷新页面重新登录。',
    no_file:'没有选择安装包，请先选一个 zip 文件。',
    invalid_version:'版本号格式不对，应为 x.y.z，例如 1.0.1。',
    too_large:'安装包太大了，超过 512MB，传不上去。',
    invalid_multipart:'上传失败，文件可能有问题，请重新选择再试。',
    invalid_content_type:'上传失败，请重试。',
    invalid_request:'上传失败，请重试。'
  };
  if(code&&map[code]){return map[code];}
  if(status===413){return '安装包太大了，超过 512MB，传不上去。';}
  if(status===401){return '未登录或会话过期，请刷新页面重新登录。';}
  return '上传失败，请稍后重试。';
}
async function uploadRelease(){
  var fileInput=document.getElementById('releaseFile');
  var versionInput=document.getElementById('releaseVersion');
  var notesInput=document.getElementById('releaseNotes');
  var btn=document.getElementById('releaseBtn');
  var msg=document.getElementById('releaseMsg');
  var file=fileInput.files&&fileInput.files[0];
  if(!file){msg.style.color='#b00';msg.textContent='请先选择安装包（zip）。';return;}
  if(file.size>MAX_RELEASE_BYTES){
    msg.style.color='#b00';
    msg.textContent='安装包太大了（'+fmtSize(file.size)+'），超过 512MB，传不上去。';
    return;
  }
  var version=versionInput.value.trim();
  if(!/^\d+\.\d+\.\d+$/.test(version)){
    msg.style.color='#b00';
    msg.textContent='版本号格式不对，应为 x.y.z，例如 1.0.1。';
    return;
  }
  var fd=new FormData();
  fd.append('file',file);
  fd.append('version',version);
  fd.append('notes',notesInput.value);
  btn.disabled=true;
  btn.textContent='正在上传…';
  msg.style.color='';
  msg.textContent='';
  try{
    var r=await fetch('/api/admin/release',{method:'POST',body:fd});
    var d=await r.json().catch(function(){return {};});
    if(r.ok){
      msg.style.color='#080';
      msg.textContent='已发布新版 '+(d.version||version)+'（'+fmtSize(file.size)+'），用户打开面板时会自动收到更新提示。';
      fileInput.value='';
      versionInput.value='';
      notesInput.value='';
    }else{
      msg.style.color='#b00';
      msg.textContent='发布失败：'+releaseErrText(d.error,r.status);
    }
  }catch(e){
    msg.style.color='#b00';
    msg.textContent='发布失败：网络不通，请检查后重试。';
  }finally{
    btn.disabled=false;
    btn.textContent='上传并发布';
  }
}
function fmtTime(ts){
  if(!ts){return '—';}
  var d=new Date(ts*1000);
  function p(n){return ('0'+n).slice(-2);}
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes());
}
// 复制：http 页面 navigator.clipboard 不可用，用 textarea + execCommand 兜底；
// iOS 要先 focus 再 setSelectionRange，调用必须在点击手势里同步发生。
function copyText(text,btn){
  function done(ok){
    if(!btn){return;}
    var old=btn.textContent;
    btn.textContent=ok?'已复制':'复制失败';
    btn.disabled=true;
    setTimeout(function(){btn.textContent=old;btn.disabled=false;},1500);
  }
  function fallback(){
    var ta=document.createElement('textarea');
    ta.value=text;
    ta.setAttribute('readonly','');
    ta.style.cssText='position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:0;outline:0;opacity:0;';
    document.body.appendChild(ta);
    ta.focus();
    ta.setSelectionRange(0,ta.value.length);
    var ok=false;
    try{ok=document.execCommand('copy');}catch(e){ok=false;}
    document.body.removeChild(ta);
    done(ok);
  }
  if(window.isSecureContext&&navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){done(true);},fallback);
  }else{
    fallback();
  }
}
function copyListCodes(containerId,btn){
  var codes=[];
  var els=document.getElementById(containerId).querySelectorAll('.code');
  for(var i=0;i<els.length;i++){codes.push(els[i].textContent);}
  if(!codes.length){return;}
  copyText(codes.join('\\n'),btn);
}
function copyNewAll(btn){copyListCodes('cardsNewList',btn);}
var cardState={cards:[],total:0,counts:{unused:0,used:0,expired:0},expanded:false,selected:{},pendingDelete:null};
var CARD_PAGE_SIZE=10;
function statusLabel(st){return st==='used'?'已用':(st==='expired'?'已过期':'未用');}
function statusBadge(st){return st==='used'?'badge-used':(st==='expired'?'badge-expired':'badge-unused');}
function fmtBatch(b){
  if(!b){return '旧批次';}
  var m=/^B(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(b);
  if(!m){return '批次 '+b;}
  return '批次 '+m[2]+'-'+m[3]+' '+m[4]+':'+m[5];
}
function cardFilters(){
  return {
    q:document.getElementById('cardSearch').value.trim(),
    status:document.getElementById('cardStatus').value,
    type:document.getElementById('cardTypeFilter').value,
    batch:document.getElementById('cardLatest').checked?'latest':'all'
  };
}
function cardQuery(f,limit,offset){
  var p=[];
  if(f.q){p.push('q='+encodeURIComponent(f.q));}
  if(f.status!=='all'){p.push('status='+f.status);}
  if(f.type!=='all'){p.push('type='+f.type);}
  if(f.batch!=='all'){p.push('batch='+f.batch);}
  p.push('limit='+(limit||500));
  p.push('offset='+(offset||0));
  return '/api/admin/cards?'+p.join('&');
}
function codeRow(c,withActions){
  var row=document.createElement('div'); row.className='code-row';
  var l1=document.createElement('div'); l1.className='code-line1';
  if(withActions){
    var lab=document.createElement('label'); lab.className='row-check';
    var cb=document.createElement('input'); cb.type='checkbox';
    cb.checked=!!cardState.selected[c.code];
    cb.onchange=function(){onCardCheck(c.code,cb.checked);};
    lab.appendChild(cb); l1.appendChild(lab);
  }
  var code=document.createElement('div'); code.className='code'; code.textContent=c.code;
  l1.appendChild(code);
  var badge=document.createElement('span');
  badge.className='badge '+statusBadge(c.status); badge.textContent=statusLabel(c.status);
  l1.appendChild(badge);
  row.appendChild(l1);
  var l2=document.createElement('div'); l2.className='code-line2';
  var sub=[c.type==='day'?'天卡':'周卡'];
  if(c.machine_id){sub.push('机器 '+(c.machine_id.slice(0,12)+'…'));}
  if(c.used_at){sub.push('激活 '+fmtTime(c.used_at));}
  sub.push(fmtBatch(c.batch_id));
  var s=document.createElement('div'); s.className='code-sub'; s.textContent=sub.join(' · ');
  l2.appendChild(s);
  var b=document.createElement('button'); b.type='button';
  b.className='row-btn'; b.textContent='复制';
  b.onclick=function(){copyText(c.code,b);};
  l2.appendChild(b);
  if(withActions){
    var d=document.createElement('button'); d.type='button';
    d.className='row-btn btn-danger'; d.textContent='删除';
    d.onclick=function(){openConfirm('one',[c.code]);};
    l2.appendChild(d);
  }
  row.appendChild(l2);
  return row;
}
function visibleCards(){
  return cardState.expanded?cardState.cards:cardState.cards.slice(0,CARD_PAGE_SIZE);
}
function renderCards(){
  var box=document.getElementById('cardsTable');
  box.innerHTML='';
  visibleCards().forEach(function(c){box.appendChild(codeRow(c,true));});
  if(!cardState.cards.length){
    var e=document.createElement('div'); e.className='empty'; e.textContent='没有符合条件的卡密。';
    box.appendChild(e);
  }
  document.getElementById('cardsHead').style.display=cardState.total?'':'none';
  document.getElementById('cardsCount').textContent='共 '+cardState.total+' 张（未用 '+(cardState.counts.unused||0)+' · 已用 '+(cardState.counts.used||0)+' · 已过期 '+(cardState.counts.expired||0)+'）';
  var ex=document.getElementById('cardsExpand');
  if(cardState.total>CARD_PAGE_SIZE&&!cardState.expanded){
    ex.style.display=''; ex.textContent='展开全部（共 '+cardState.total+' 张）';
  }else{
    ex.style.display='none';
  }
  syncSelectAll();
  updateBatchBar();
}
function expandCards(){cardState.expanded=true;renderCards();}
function syncSelectAll(){
  var list=visibleCards();
  document.getElementById('cardsSelectAll').checked=list.length>0&&list.every(function(c){return cardState.selected[c.code];});
}
function onCardCheck(code,checked){
  if(checked){cardState.selected[code]=true;}else{delete cardState.selected[code];}
  syncSelectAll(); updateBatchBar();
}
function toggleSelectAll(cb){
  visibleCards().forEach(function(c){
    if(cb.checked){cardState.selected[c.code]=true;}else{delete cardState.selected[c.code];}
  });
  renderCards();
}
function selectedCodes(){return Object.keys(cardState.selected);}
function updateBatchBar(){
  var n=selectedCodes().length;
  document.getElementById('batchBarText').textContent='已选 '+n+' 张';
  document.getElementById('cardsSelCount').textContent=n?('已选 '+n+' 张'):'';
  document.getElementById('batchBar').style.display=n?'':'none';
  document.body.classList.toggle('has-selection',!!n);
}
async function loadCards(){
  var r=await api(cardQuery(cardFilters(),500,0));
  var msg=document.getElementById('cardsMsg');
  if(!r.ok){
    msg.style.color='#b00';msg.textContent='读取失败：'+(r.data.error||('HTTP '+r.status));return;
  }
  msg.textContent='';
  cardState.cards=r.data.cards||[];
  cardState.total=r.data.total||0;
  cardState.counts=r.data.counts||{};
  cardState.expanded=false;
  cardState.selected={};
  renderCards();
}
async function genCards(){
  var type=document.getElementById('cardType').value;
  var count=parseInt(document.getElementById('cardCount').value,10);
  var msg=document.getElementById('cardsNew');
  if(isNaN(count)||count<1||count>100){
    msg.style.color='#b00';msg.textContent='数量应为 1-100 的整数。';return;
  }
  var r=await api('/api/admin/cards/generate','POST',{type:type,count:count});
  if(!r.ok){
    msg.style.color='#b00';msg.textContent='生成失败：'+(r.data.error||('HTTP '+r.status));return;
  }
  msg.style.color='#080';
  msg.textContent='已生成 '+r.data.codes.length+' 张：';
  var list=document.getElementById('cardsNewList');
  list.innerHTML='';
  r.data.codes.forEach(function(code){
    list.appendChild(codeRow({code:code,type:type,status:'unused',batch_id:r.data.batch_id,machine_id:null,used_at:null},false));
  });
  document.getElementById('cardsNewCount').textContent='本次生成 '+r.data.codes.length+' 张';
  document.getElementById('cardsNewHead').style.display='';
  document.getElementById('cardLatest').checked=true;
  loadCards();
}
async function copyFiltered(btn){
  var r=await api(cardQuery(cardFilters(),1000,0));
  var msg=document.getElementById('cardsMsg');
  if(!r.ok){msg.style.color='#b00';msg.textContent='复制失败：'+(r.data.error||('HTTP '+r.status));return;}
  var codes=(r.data.cards||[]).map(function(c){return c.code;});
  if(!codes.length){msg.style.color='#b00';msg.textContent='当前筛选下没有卡密。';return;}
  copyText(codes.join('\\n'),btn);
  msg.style.color='#080';msg.textContent='已复制当前筛选结果 '+codes.length+' 张。';
}
function copySelected(btn){
  var codes=selectedCodes();
  if(!codes.length){return;}
  copyText(codes.join('\\n'),btn);
}
function deleteSelected(){if(selectedCodes().length){openConfirm('selected',selectedCodes());}}
function deleteFiltered(){if(cardState.total){openConfirm('filter',null);}}
function openConfirm(kind,codes){
  cardState.pendingDelete={kind:kind,codes:codes||null};
  var total=0,used=0;
  if(kind==='filter'){
    total=cardState.total; used=cardState.counts.used||0;
  }else{
    total=codes.length;
    used=codes.filter(function(code){
      for(var i=0;i<cardState.cards.length;i++){
        if(cardState.cards[i].code===code){return cardState.cards[i].status==='used';}
      }
      return false;
    }).length;
  }
  var text=(kind==='filter'?'确定删除当前筛选结果（共 '+total+' 张）吗？删掉后无法恢复。':'确定删除这 '+total+' 张卡密吗？删掉后无法恢复。');
  if(used>0){text+='其中有 '+used+' 张已使用：删掉只会去掉这张卡的记录，机器上已到账的时间不受影响。';}
  document.getElementById('confirmText').textContent=text;
  document.getElementById('confirmUsedWrap').style.display=used>0?'':'none';
  document.getElementById('confirmUsed').checked=false;
  document.getElementById('confirmModal').style.display='';
}
function closeConfirm(){document.getElementById('confirmModal').style.display='none';cardState.pendingDelete=null;}
async function confirmDelete(){
  var p=cardState.pendingDelete;
  if(!p){closeConfirm();return;}
  var usedShown=document.getElementById('confirmUsedWrap').style.display!=='none';
  var confirmUsed=usedShown&&document.getElementById('confirmUsed').checked;
  var body={confirm_used:confirmUsed};
  if(p.kind==='filter'){body.filter=cardFilters();}
  else{body.codes=p.codes;}
  var r=await api('/api/admin/cards/delete','POST',body);
  var msg=document.getElementById('cardsMsg');
  if(!r.ok){
    if(r.data.error==='has_used'){
      document.getElementById('confirmText').textContent='这次删除里有 '+r.data.used_count+' 张已使用的卡。为防止误删，已帮你拦下来了：勾选「同时删除已使用的卡」再点确认删除，就会一起删掉。';
      document.getElementById('confirmUsedWrap').style.display='';
      return;
    }
    closeConfirm();
    msg.style.color='#b00';msg.textContent='删除失败：'+(r.data.error||('HTTP '+r.status));return;
  }
  closeConfirm();
  cardState.selected={};
  await loadCards();
  msg.style.color='#080';msg.textContent='已删除 '+r.data.deleted_count+' 张。';
}
async function extendMachine(){
  var mid=document.getElementById('extendMachine').value.trim();
  var days=parseFloat(document.getElementById('extendDays').value);
  var msg=document.getElementById('extendMsg');
  if(!/^[0-9a-f]{64}$/.test(mid)){
    msg.style.color='#b00';msg.textContent='机器码格式不对，应为 64 位小写字母数字。';return;
  }
  if(isNaN(days)||days<=0){
    msg.style.color='#b00';msg.textContent='天数应为大于 0 的数字。';return;
  }
  var r=await api('/api/admin/machines/extend','POST',{machine_id:mid,add_seconds:Math.round(days*86400)});
  if(!r.ok){
    msg.style.color='#b00';msg.textContent='延长失败：'+(r.data.error||('HTTP '+r.status));return;
  }
  msg.style.color='#080';
  msg.textContent='已延长，新过期时间 '+fmtTime(r.data.expire_at)+'，剩余约 '+Math.floor(r.data.remaining_seconds/3600)+' 小时。';
}
async function loadMasterCard(){
  var r=await api('/api/admin/master-card');
  var st=document.getElementById('masterCardStatus');
  var box=document.getElementById('masterUsesTable');
  var msg=document.getElementById('masterUsesMsg');
  if(!r.ok){
    st.textContent='万能卡：读取失败';
    msg.style.color='#b00';msg.textContent='读取失败：'+(r.data.error||('HTTP '+r.status));return;
  }
  st.textContent='万能卡：'+(r.data.set?'已设置':'未设置');
  msg.textContent='';
  var uses=r.data.uses||[];
  box.innerHTML='';
  uses.forEach(function(u){
    var row=document.createElement('div'); row.className='use-row';
    var m=document.createElement('span'); m.className='mid';
    m.textContent=u.machine_id?u.machine_id.slice(0,12)+'…':'—';
    var t=document.createElement('span'); t.className='time'; t.textContent=fmtTime(u.used_at);
    row.appendChild(m); row.appendChild(t); box.appendChild(row);
  });
  if(!uses.length){
    var e=document.createElement('div'); e.className='empty'; e.textContent='还没有使用记录。';
    box.appendChild(e);
  }
}
async function saveMasterCard(){
  var code=document.getElementById('masterCard').value;
  var msg=document.getElementById('masterCardMsg');
  var r=await api('/api/admin/master-card','POST',{code:code});
  if(!r.ok){
    msg.style.color='#b00';
    msg.textContent=r.data.error==='invalid_master_card'?'保存失败：万能卡至少 12 个字符（留空保存 = 清掉）。':'保存失败：'+(r.data.error||('HTTP '+r.status));
    return;
  }
  msg.style.color='#080';
  msg.textContent=code?'已保存万能卡。':'已清掉万能卡。';
  document.getElementById('masterCard').value='';
  loadMasterCard();
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
        while length > 0:
            chunk = self.rfile.read(min(65536, length))
            if not chunk:
                break
            length -= len(chunk)

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
        elif path == "/logo.jpg":
            self.handle_logo()
        elif path == "/api/ai/health":
            self.handle_health()
        elif path == "/api/version":
            self.handle_version()
        elif path == "/download/latest":
            self.handle_download_latest()
        elif path == "/admin":
            self.handle_admin_page()
        elif path == "/api/admin/config":
            self.handle_admin_config_get()
        elif path == "/api/admin/stats":
            self.handle_admin_stats()
        elif path == "/api/admin/cards":
            self.handle_admin_cards_list()
        elif path == "/api/admin/master-card":
            self.handle_admin_master_card_get()
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
        elif path == "/api/admin/models":
            self.handle_admin_models()
        elif path == "/api/admin/release":
            self.handle_admin_release()
        elif path == "/api/auth/info":
            self.handle_auth_info()
        elif path == "/api/auth/activate":
            self.handle_auth_activate()
        elif path == "/api/admin/cards/generate":
            self.handle_admin_cards_generate()
        elif path == "/api/admin/cards/delete":
            self.handle_admin_cards_delete()
        elif path == "/api/admin/machines/extend":
            self.handle_admin_machines_extend()
        elif path == "/api/admin/master-card":
            self.handle_admin_master_card_post()
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

    # ---- 自动更新：版本与下载 ----
    def _check_app_token(self):
        """和 /api/ai/chat 同样的鉴权：X-App-Token 对不上返回 401。"""
        cfg = config_snapshot()
        token = self.headers.get("X-App-Token")
        if not token or not hmac.compare_digest(token, cfg.get("app_token") or ""):
            self.send_json(401, {"error": "unauthorized"})
            return None
        return cfg

    def handle_version(self):
        if self._check_app_token() is None:
            return
        info = read_release_info(release_dir())
        if info is None:
            return self.send_json(404, {"error": "no_release"})
        self.send_json(200, info)

    def handle_download_latest(self):
        if self._check_app_token() is None:
            return
        path = os.path.join(release_dir(), "releases", "latest.zip")
        if not os.path.isfile(path):
            return self.send_json(404, {"error": "no_release"})
        try:
            size = os.path.getsize(path)
            f = open(path, "rb")
        except OSError:
            return self.send_json(404, {"error": "no_release"})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", 'attachment; filename="latest.zip"')
            self.end_headers()
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            f.close()

    # ---- 鉴权：机器码绑定 + 纯时间制卡密 ----
    def _auth_app_token(self):
        """鉴权接口共用：X-App-Token 不对返回 401（与 /api/ai/chat 同方式）。"""
        cfg = config_snapshot()
        token = self.headers.get("X-App-Token")
        if not token or not hmac.compare_digest(token, cfg.get("app_token") or ""):
            self.send_json(401, {"error": "unauthorized"})
            return None
        return cfg

    def _auth_check_request(self, cfg, body, sig_err_status):
        """校验鉴权请求的 machine_id / timestamp / signature。

        通过返回 (machine_id, timestamp)，失败已回错误并返回 None。
        machine_id 格式错一律 400；签名错 / 时间戳过期按调用方给的
        sig_err_status 回（info 用 401，activate 用 400，约定见 AUTH_API.md）。"""
        machine_id = body.get("machine_id")
        if not isinstance(machine_id, str) or not MACHINE_ID_RE.fullmatch(machine_id):
            self.send_json(400, {"error": "invalid_machine_id"})
            return None
        ts = body.get("timestamp")
        if type(ts) is not int:
            self.send_json(sig_err_status, {"error": "stale_timestamp"})
            return None
        now = int(time.time())
        if abs(now - ts) > AUTH_TIME_WINDOW:
            self.send_json(sig_err_status, {"error": "stale_timestamp"})
            return None
        sig = body.get("signature")
        expected = _auth_sign_request(cfg.get("app_token") or "", machine_id, ts)
        if not isinstance(sig, str) or not hmac.compare_digest(sig, expected):
            self.send_json(sig_err_status, {"error": "bad_signature"})
            return None
        hdr_sig = self.headers.get("X-Auth-Sign")
        if hdr_sig is not None and not hmac.compare_digest(hdr_sig, expected):
            self.send_json(sig_err_status, {"error": "bad_signature"})
            return None
        return machine_id, ts

    def handle_auth_info(self):
        cfg = self._auth_app_token()
        if cfg is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        checked = self._auth_check_request(cfg, body, 401)
        if checked is None:
            return
        machine_id, _ts = checked
        now = int(time.time())
        with AUTH_LOCK:
            machines = _load_auth_store("auth_machines.json")
            rec = machines.get(machine_id)
            if rec is None:
                # 新机首次来：建记录，送 1 小时试用（服务端记，删本地文件也没用）
                rec = {"expire_at": now + TRIAL_SECONDS,
                       "created_at": now, "trial": True}
                machines[machine_id] = rec
                _save_auth_store("auth_machines.json", machines)
            expire_at = int(rec.get("expire_at") or 0)
            trial = bool(rec.get("trial"))
        remaining = max(0, expire_at - now)
        if remaining <= 0:
            status = "expired"
        elif trial:
            status = "trial"
        else:
            status = "active"
        sig = _auth_sign_response(cfg.get("app_token") or "", machine_id,
                                  expire_at, remaining, now)
        self.send_json(200, {
            "machine_id": machine_id,
            "expire_at": expire_at,
            "remaining_seconds": remaining,
            "status": status,
            "signature": sig,
            "server_time": now,
        })

    def handle_auth_activate(self):
        cfg = self._auth_app_token()
        if cfg is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        checked = self._auth_check_request(cfg, body, 400)
        if checked is None:
            return
        machine_id, _ts = checked
        code = body.get("card_code")
        now = int(time.time())
        # 万能卡优先：命中则直接加 10 年，可叠加、可重复用、不限机器；
        # 绝不写进卡库（auth_cards.json）。没命中再走原有卡密流程。
        master = cfg.get("master_card") or ""
        if master and isinstance(code, str) and hmac.compare_digest(code, master):
            with AUTH_LOCK:
                machines = _load_auth_store("auth_machines.json")
                rec = machines.get(machine_id)
                if rec is None:
                    rec = {"expire_at": now, "created_at": now, "trial": False}
                    machines[machine_id] = rec
                expire_at = max(now, int(rec.get("expire_at") or 0)) + MASTER_SECONDS
                rec["expire_at"] = expire_at
                rec["trial"] = False
                _save_auth_store("auth_machines.json", machines)
                _record_master_use(machine_id, now)
            return self.send_json(200, {
                "expire_at": expire_at,
                "remaining_seconds": max(0, expire_at - now),
                "added_seconds": MASTER_SECONDS,
                "card_type": "master",
            })
        if not isinstance(code, str) or not CARD_CODE_RE.fullmatch(code):
            return self.send_json(400, {"error": "invalid_card"})
        card_type = "day" if code[3] == "D" else "week"
        add = DAY_SECONDS if card_type == "day" else WEEK_SECONDS
        err = None
        result = None
        with AUTH_LOCK:
            cards = _load_auth_store("auth_cards.json")
            card = cards.get(code)
            if card is None:
                err = "invalid_card"
            else:
                bound = card.get("machine_id")
                if bound:
                    err = "card_used" if bound == machine_id else "card_bound_other"
                else:
                    machines = _load_auth_store("auth_machines.json")
                    rec = machines.get(machine_id)
                    if rec is None:
                        rec = {"expire_at": now, "created_at": now, "trial": False}
                        machines[machine_id] = rec
                    expire_at = max(now, int(rec.get("expire_at") or 0)) + add
                    rec["expire_at"] = expire_at
                    rec["trial"] = False
                    card["machine_id"] = machine_id
                    card["used_at"] = now
                    _save_auth_store("auth_cards.json", cards)
                    _save_auth_store("auth_machines.json", machines)
                    result = {"expire_at": expire_at,
                              "remaining_seconds": max(0, expire_at - now),
                              "added_seconds": add,
                              "card_type": card_type}
        if err is not None:
            return self.send_json(400, {"error": err})
        self.send_json(200, result)

    def handle_admin_cards_generate(self):
        if not self.require_login():
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        card_type = body.get("type")
        if card_type not in ("day", "week"):
            return self.send_json(400, {"error": "invalid_type"})
        count = body.get("count")
        if type(count) is not int or count < 1 or count > 100:
            return self.send_json(400, {"error": "invalid_count"})
        now = int(time.time())
        with AUTH_LOCK:
            cards = _load_auth_store("auth_cards.json")
            batch_id = _new_batch_id(now, {c.get("batch_id") for c in cards.values()})
            batch_seq = 0
            for c in cards.values():
                s = c.get("batch_seq") or 0
                if s > batch_seq:
                    batch_seq = s
            batch_seq += 1
            codes = []
            for _ in range(count):
                for _try in range(100):
                    code = _gen_card_code(card_type)
                    if code not in cards:
                        break
                else:
                    continue  # 100 次都撞码（几乎不可能），跳过这一张
                cards[code] = {"type": card_type, "machine_id": None,
                               "used_at": None, "created_at": now,
                               "batch_id": batch_id, "batch_seq": batch_seq}
                codes.append(code)
            _save_auth_store("auth_cards.json", cards)
        self.send_json(200, {"codes": codes, "batch_id": batch_id})

    def _cards_filtered(self, cards, params, now):
        """按筛选条件筛卡密（列表与按条件删除共用）。
        params: {status, type, batch, q}，均为字符串；status 只能是
        all/unused/used/expired，type 只能是 all/day/week，
        batch 只能是 all/latest/<具体 batch_id>，q 为关键词（不区分大小写，
        同时匹配卡密与机器码）。返回 (匹配到的 [(code, c, status)] 列表,
        各状态计数)。计数在 status 之外其他条件已筛完的基础上算，
        供筛选栏显示“未使用 N · 已使用 N · 已过期 N”。"""
        status_f = params.get("status", "all")
        type_f = params.get("type", "all")
        batch_f = params.get("batch", "all")
        q = (params.get("q") or "").strip().lower()
        if status_f not in ("all", "unused", "used", "expired"):
            return None, "invalid_status"
        if type_f not in ("all", "day", "week"):
            return None, "invalid_type"
        latest_batch = None
        if batch_f == "latest":
            with_batch = [(c.get("batch_seq") or 0, c.get("created_at") or 0,
                           c.get("batch_id"))
                          for c in cards.values() if c.get("batch_id")]
            if with_batch:
                latest_batch = max(with_batch)[2]
        matched = []
        counts = {"unused": 0, "used": 0, "expired": 0}
        for code, c in cards.items():
            if type_f != "all" and c.get("type") != type_f:
                continue
            if batch_f == "latest":
                if c.get("batch_id") != latest_batch:
                    continue
            elif batch_f != "all" and c.get("batch_id") != batch_f:
                continue
            if q and q not in code.lower() and q not in (c.get("machine_id") or "").lower():
                continue
            st = _card_status(c, now)
            counts[st] += 1
            if status_f != "all" and st != status_f:
                continue
            matched.append((code, c, st))
        matched.sort(key=lambda x: ((x[1].get("created_at") or 0), x[0]), reverse=True)
        return (matched, counts), None

    def handle_admin_cards_list(self):
        if not self.require_login():
            return
        qs = parse_qs(urlsplit(self.path).query)
        params = {
            "status": qs.get("status", ["all"])[0] or "all",
            "type": qs.get("type", ["all"])[0] or "all",
            "batch": qs.get("batch", ["all"])[0] or "all",
            "q": qs.get("q", [""])[0],
        }
        try:
            limit = int(qs.get("limit", ["500"])[0])
            offset = int(qs.get("offset", ["0"])[0])
        except ValueError:
            return self.send_json(400, {"error": "invalid_paging"})
        if limit < 1 or limit > CARD_LIST_LIMIT_MAX or offset < 0:
            return self.send_json(400, {"error": "invalid_paging"})
        now = int(time.time())
        with AUTH_LOCK:
            cards = _load_auth_store("auth_cards.json")
        result, err = self._cards_filtered(cards, params, now)
        if err:
            return self.send_json(400, {"error": err})
        matched, counts = result
        total = len(matched)
        page = matched[offset:offset + limit]
        items = [{
            "code": code,
            "type": c.get("type"),
            "status": st,
            "batch_id": c.get("batch_id"),
            "machine_id": c.get("machine_id"),
            "used_at": c.get("used_at"),
            "created_at": c.get("created_at"),
        } for code, c, st in page]
        batches = {}
        for code, c in cards.items():
            b = c.get("batch_id")
            if not b:
                continue
            cur = batches.get(b)
            created = c.get("created_at") or 0
            seq = c.get("batch_seq") or 0
            if cur is None or created > cur["created_at"]:
                cur = {"batch_id": b, "count": 0, "created_at": created, "seq": seq}
                batches[b] = cur
            cur["count"] += 1
            if seq > cur["seq"]:
                cur["seq"] = seq
        batch_list = sorted(batches.values(),
                            key=lambda x: (x["seq"], x["created_at"], x["batch_id"]),
                            reverse=True)
        for b in batch_list:
            del b["seq"]
        self.send_json(200, {"total": total, "counts": counts,
                             "batches": batch_list, "cards": items})

    def handle_admin_cards_delete(self):
        if not self.require_login():
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        codes = body.get("codes")
        filt = body.get("filter")
        confirm_used = body.get("confirm_used") is True
        if codes is not None and filt is not None:
            return self.send_json(400, {"error": "ambiguous"})
        if codes is not None:
            if (not isinstance(codes, list)
                    or not all(isinstance(x, str) for x in codes)
                    or not codes or len(codes) > CARD_DELETE_MAX):
                return self.send_json(400, {"error": "invalid_codes"})
            target_codes = list(dict.fromkeys(codes))  # 去重，保序
        elif isinstance(filt, dict):
            params = {k: filt.get(k, "all") if k != "q" else (filt.get(k) or "")
                      for k in ("status", "type", "batch", "q")}
            now = int(time.time())
            with AUTH_LOCK:
                cards = _load_auth_store("auth_cards.json")
            result, err = self._cards_filtered(cards, params, now)
            if err:
                return self.send_json(400, {"error": err})
            matched, _counts = result
            if len(matched) > CARD_DELETE_MAX:
                return self.send_json(400, {"error": "too_many"})
            target_codes = [code for code, _c, _st in matched]
            if not target_codes:
                return self.send_json(200, {"deleted": [], "deleted_count": 0,
                                            "not_found": []})
        else:
            return self.send_json(400, {"error": "invalid_request"})
        now = int(time.time())
        with AUTH_LOCK:
            cards = _load_auth_store("auth_cards.json")
            found = {code: cards[code] for code in target_codes if code in cards}
            not_found = [code for code in target_codes if code not in cards]
            used = [code for code, c in found.items()
                    if _card_status(c, now) == "used"]
            if used and not confirm_used:
                return self.send_json(400, {"error": "has_used",
                                            "used_count": len(used),
                                            "used": used[:10]})
            for code in found:
                del cards[code]
            _save_auth_store("auth_cards.json", cards)
        deleted = sorted(found)
        self.send_json(200, {"deleted": deleted, "deleted_count": len(deleted),
                             "not_found": not_found})

    def handle_admin_machines_extend(self):
        if not self.require_login():
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        machine_id = body.get("machine_id")
        if not isinstance(machine_id, str) or not MACHINE_ID_RE.fullmatch(machine_id):
            return self.send_json(400, {"error": "invalid_machine_id"})
        add = body.get("add_seconds")
        if type(add) is not int or add <= 0:
            return self.send_json(400, {"error": "invalid_add_seconds"})
        now = int(time.time())
        with AUTH_LOCK:
            machines = _load_auth_store("auth_machines.json")
            rec = machines.get(machine_id)
            if rec is None:
                rec = {"expire_at": now + add, "created_at": now, "trial": False}
                machines[machine_id] = rec
            else:
                rec["expire_at"] = max(now, int(rec.get("expire_at") or 0)) + add
            _save_auth_store("auth_machines.json", machines)
            expire_at = int(rec["expire_at"])
        self.send_json(200, {
            "expire_at": expire_at,
            "remaining_seconds": max(0, expire_at - now),
        })

    def handle_admin_master_card_get(self):
        """万能卡状态 + 使用记录：只返回是否已设置，绝不返回卡值。"""
        if not self.require_login():
            return
        cfg = config_snapshot()
        with AUTH_LOCK:
            uses = _load_master_uses()
        # 使用记录是追加式日志，本身按时间正序；倒过来即最新在前
        # （不用 used_at 排序：同一秒内的多次激活时间戳相同，会乱序）
        uses = list(reversed(uses))[:100]
        self.send_json(200, {
            "set": bool(cfg.get("master_card")),
            "uses": [{"machine_id": u.get("machine_id"),
                      "used_at": u.get("used_at")}
                     for u in uses[:100]],
        })

    def handle_admin_master_card_post(self):
        """设万能卡：code 至少 12 个字符；空字符串 = 清掉。立即写盘即生效，不用重启。"""
        if not self.require_login():
            return
        body = self.read_json_body()
        if body is None:
            return self.send_json(400, {"error": "invalid_json"})
        code = body.get("code")
        if not isinstance(code, str):
            return self.send_json(400, {"error": "invalid_master_card"})
        if code != "" and len(code) < 12:
            return self.send_json(400, {"error": "invalid_master_card"})
        with CONFIG.lock:
            CONFIG.data["master_card"] = code
            CONFIG.save()
        self.send_json(200, {"ok": True, "set": bool(code)})

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
    def handle_logo(self):
        """项目 logo：取 relay.py 同目录的 logo.jpg，静态回 image/jpeg。
        文件缺失时 404（不 500），不走任何鉴权。"""
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "logo.jpg")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            self.send_json(404, {"error": "not_found"})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_admin_page(self):
        cfg = config_snapshot()
        if not cfg.get("admin_password_hash"):
            self.send_html(200, PAGE_SETUP)
        elif not check_session(self.session_token()):
            self.send_html(200, PAGE_LOGIN)
        else:
            self.send_html(200, PAGE_CONFIG)

    # ---- /api/admin ----
    def handle_admin_models(self):
        """拉模型列表：GET {base_url}/models，草稿 base_url / api_key 优先于已保存配置。"""
        if not self.require_login():
            return
        body = self.read_json_body() or {}
        cfg = config_snapshot()
        base_url = cfg["base_url"]
        if isinstance(body.get("base_url"), str) and body["base_url"].strip():
            base_url = body["base_url"].strip()
        api_key = cfg.get("api_key")
        if isinstance(body.get("api_key"), str) and body["api_key"]:
            api_key = body["api_key"]
        if not api_key:
            return self.send_json(400, {"error": "no_api_key"})
        url = (base_url or "").rstrip("/") + "/models"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", "Bearer " + api_key)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return self.send_json(401, {"error": "upstream_unauthorized"})
            log("models upstream HTTP %s" % e.code)
            return self.send_json(502, {"error": "upstream_failed"})
        except Exception as e:
            log("models upstream error: %s" % type(e).__name__)
            return self.send_json(502, {"error": "upstream_failed"})
        try:
            payload = json.loads(raw.decode("utf-8"))
            items = payload.get("data")
            if not isinstance(items, list):
                raise ValueError("bad models payload")
            ids = sorted({it["id"] for it in items
                          if isinstance(it, dict) and isinstance(it.get("id"), str) and it["id"]})
        except Exception:
            return self.send_json(502, {"error": "upstream_failed"})
        self.send_json(200, {"models": ids})

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
            "release_token_set": bool(cfg.get("release_token")),
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

    # ---- 自动更新：上传新版（管理员 或 发布钥匙） ----
    def _check_release_token(self):
        """发布钥匙鉴权：X-Release-Token 对上 config.json 里的 release_token。

        未配置（空值）时一律失败（fail closed），只认管理员会话。"""
        cfg = config_snapshot()
        expected = cfg.get("release_token") or ""
        if not expected:
            return False
        provided = self.headers.get("X-Release-Token")
        if not provided:
            return False
        try:
            return hmac.compare_digest(provided.encode("utf-8"),
                                       expected.encode("utf-8"))
        except Exception:
            return False

    def handle_admin_release(self):
        # 管理员会话 OR 发布钥匙，任一通过即可；都不过返回 401
        if not check_session(self.session_token()) and not self._check_release_token():
            return self.send_json(401, {"error": "unauthorized"})
        ctype = self.headers.get("Content-Type") or ""
        if "multipart/form-data" not in ctype:
            self.drain_body()
            return self.send_json(400, {"error": "invalid_content_type"})
        boundary = _parse_boundary(ctype)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not boundary or length <= 0:
            self.drain_body()
            return self.send_json(400, {"error": "invalid_request"})
        if length > MAX_RELEASE_BYTES:
            self.drain_body()
            return self.send_json(413, {"error": "too_large"})
        with RELEASE_LOCK:
            self._do_release(length, boundary)

    def _do_release(self, length, boundary):
        rdir = release_dir()
        rel_dir = os.path.join(rdir, "releases")
        os.makedirs(rel_dir, exist_ok=True)
        tmp_path = os.path.join(rel_dir, "latest.zip.tmp")
        reader = _BodyReader(self.rfile, length)
        try:
            fields, file_info = self._parse_multipart(reader, boundary, tmp_path)
        except ValueError as e:
            reader.drain()
            self._cleanup_tmp(tmp_path)
            log("release upload failed: %s" % e)
            return self.send_json(400, {"error": "invalid_multipart"})
        reader.drain()  # 丢弃最终边界后的 epilogue，保持连接干净
        if file_info is None:
            self._cleanup_tmp(tmp_path)
            return self.send_json(400, {"error": "no_file"})
        _filename, size, sha256 = file_info
        if size <= 0:
            self._cleanup_tmp(tmp_path)
            return self.send_json(400, {"error": "no_file"})
        version = (fields.get("version") or "").strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            self._cleanup_tmp(tmp_path)
            return self.send_json(400, {"error": "invalid_version"})
        notes = fields.get("notes", "")
        final_path = os.path.join(rel_dir, "latest.zip")
        os.replace(tmp_path, final_path)
        info = {"version": version, "size": size, "sha256": sha256, "notes": notes}
        write_release_info(rdir, info)
        log("release published: version=%s size=%d" % (version, size))
        self.send_json(200, {"ok": True, "version": version})

    @staticmethod
    def _cleanup_tmp(tmp_path):
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    def _parse_multipart(self, reader, boundary, tmp_path):
        """流式解析 multipart/form-data。

        返回 (fields, file_info)：fields 是 {name: str}，file_info 是
        (filename, size, sha256_hex) 或 None（没有文件 part 时）。
        文件体边读边写临时文件、边算 sha256，不进内存；文本字段单个超 1MB 报错。
        出错 raise ValueError，调用方负责清理临时文件。"""
        delim = b"--" + boundary
        # 首行应为 boundary，之前只允许空行（preamble）
        for _ in range(10):
            line = reader.readline(65536)
            if not line:
                raise ValueError("bad preamble")
            if line.rstrip(b"\r\n") == delim:
                break
            if line.strip() != b"":
                raise ValueError("bad preamble")
        else:
            raise ValueError("bad preamble")
        fields = {}
        file_info = None
        while True:
            headers = {}
            while True:
                line = reader.readline(65536)
                if not line:
                    raise ValueError("truncated headers")
                line = line.rstrip(b"\r\n")
                if line == b"":
                    break
                if b":" not in line:
                    raise ValueError("bad header line")
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
            cd = headers.get("content-disposition", "")
            name = None
            filename = None
            for part in cd.split(";"):
                part = part.strip()
                if part.startswith("name="):
                    name = part[5:].strip().strip('"')
                elif part.startswith("filename="):
                    filename = part[9:].strip().strip('"')
            if name is None:
                raise ValueError("part without name")
            final, info = self._read_part_body(reader, delim, name, filename,
                                               fields, tmp_path)
            if info is not None:
                file_info = info
            if final:
                break
        return fields, file_info

    def _read_part_body(self, reader, delim, name, filename, fields, tmp_path):
        """读一个 part 的 body，直到下一个 boundary。
        返回 (是否最终边界, file_info 或 None)。"""
        needle = b"\r\n" + delim
        tail = b""
        if filename is not None:
            h = hashlib.sha256()
            size = 0
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = reader.read(65536)
                    if not chunk:
                        raise ValueError("truncated body")
                    data = tail + chunk
                    idx = data.find(needle)
                    if idx >= 0:
                        out.write(data[:idx])
                        h.update(data[:idx])
                        size += idx
                        final = self._delim_tail(reader, data[idx + len(needle):])
                        break
                    keep = len(delim) + 2  # 尾巴里可能藏着半个 boundary
                    if len(data) > keep:
                        out.write(data[:-keep])
                        h.update(data[:-keep])
                        size += len(data) - keep
                        tail = data[-keep:]
                    else:
                        tail = data
            return final, (filename, size, h.hexdigest())
        buf = bytearray()
        while True:
            chunk = reader.read(65536)
            if not chunk:
                raise ValueError("truncated body")
            data = tail + chunk
            idx = data.find(needle)
            if idx >= 0:
                buf += data[:idx]
                final = self._delim_tail(reader, data[idx + len(needle):])
                break
            keep = len(delim) + 2
            if len(data) > keep:
                buf += data[:-keep]
                tail = data[-keep:]
            else:
                tail = data
            if len(buf) > 1024 * 1024:
                raise ValueError("field too large")
        fields[name] = bytes(buf).decode("utf-8", "replace")
        return final, None

    @staticmethod
    def _delim_tail(reader, rest):
        """boundary 后面的收尾：b"--" 是最终边界，b"\r\n" 是还有后续 part。
        rest 里多出的字节（下个 part 的开头）要回放，绝不能丢。"""
        buf = rest
        while len(buf) < 2:
            more = reader.read(2 - len(buf))
            if not more:
                raise ValueError("truncated boundary")
            buf += more
        if buf[:2] == b"--":
            return True
        if buf[:2] == b"\r\n":
            if len(buf) > 2:
                reader.unread(buf[2:])
            return False
        raise ValueError("bad boundary tail")


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
