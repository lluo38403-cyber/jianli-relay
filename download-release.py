#!/usr/bin/env python3
"""从 GitHub Release 直接下载简历猎手发布包并发布到中转。

替代 tmpfiles 传包：服务器用一个只读 fine-grained PAT（只读
lluo38403-cyber/jianli-lieshou-bh 的 Contents）直接从 GitHub Release
下载 8 个分块，验大小+sha256，拼合再验，调中转发布接口。

用法（在服务器上跑，先 export https_proxy=http://127.0.0.1:7890）：
  python3 download-release.py --version 1.1.3 --size 67087027 \\
      --sha256 <整包sha256> \\
      --chunks "v17-part00.zip:8388608:<sha>,v17-part01.zip:8388608:<sha>,..." \\
      --notes "版本备注" [--check-only] [--outdir /root/v17-gh]

--check-only 只下载+校验+拼合，不调发布接口（用来验证令牌和链路）。
令牌只从 /root/.github-release-token 读（600，root 专属），绝不打印；
发布钥匙与应用令牌只从 /root/jianli-relay/config.json 内存读取，绝不打印。
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

OWNER = "lluo38403-cyber"
REPO = "jianli-lieshou-bh"
TOKEN_FILE = "/root/.github-release-token"
CONFIG_FILE = "/root/jianli-relay/config.json"
RELAY_BASE = "http://127.0.0.1:8687"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随跳转，让调用方拿到 Location 后再无鉴权下载。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github_api(path, token):
    url = "https://api.github.com" + path
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "jianli-relay-release-downloader",
    })
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def download_asset(asset_url, token, dest):
    """先带鉴权拿 302 的 Location，再无鉴权下载（令牌绝不发给 CDN）。"""
    req = urllib.request.Request(asset_url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/octet-stream",
        "User-Agent": "jianli-relay-release-downloader",
    })
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=120) as r:
            # 未跳转：直接就是文件体（少见）
            _stream_to(r, dest)
            return
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            location = e.headers.get("Location")
            if not location:
                raise RuntimeError("下载跳转没有 Location")
            req2 = urllib.request.Request(location, headers={
                "User-Agent": "jianli-relay-release-downloader",
            })
            with urllib.request.urlopen(req2, timeout=600) as r2:
                _stream_to(r2, dest)
            return
        raise


def _stream_to(resp, dest):
    with open(dest, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--size", required=True, type=int)
    ap.add_argument("--sha256", required=True)
    ap.add_argument("--chunks", required=True,
                    help="name:size:sha256，逗号分隔，按顺序")
    ap.add_argument("--notes", default="")
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    with open(TOKEN_FILE, "r") as f:
        token = f.read().strip()
    if not token:
        print("FAIL：令牌文件为空", file=sys.stderr)
        return 2

    chunks = []
    for item in args.chunks.split(","):
        name, size, sha = item.split(":")
        chunks.append((name, int(size), sha))
    outdir = args.outdir or "/root/v%s-gh" % args.version.replace(".", "")
    os.makedirs(outdir, exist_ok=True)

    rel = github_api("/repos/%s/%s/releases/tags/v%s" % (OWNER, REPO, args.version), token)
    assets = {a["name"]: a["url"] for a in rel.get("assets", [])}
    print("Release v%s：找到 %d 个 assets" % (args.version, len(assets)))

    paths = []
    for name, size, sha in chunks:
        if name not in assets:
            print("FAIL：Release 里没有 %s" % name, file=sys.stderr)
            return 2
        dest = os.path.join(outdir, name)
        print("下载 %s ..." % name)
        download_asset(assets[name], token, dest)
        got_size = os.path.getsize(dest)
        got_sha = sha256_file(dest)
        ok = got_size == size and got_sha == sha
        print("%s：大小 %d（应 %d）、sha256 %s —— %s"
              % (name, got_size, size, got_sha[:12], "OK" if ok else "FAIL"))
        if not ok:
            return 2
        paths.append(dest)
    print("ALL_PARTS_OK")

    merged = os.path.join(outdir, "v%s.zip" % args.version)
    with open(merged, "wb") as out:
        for p in paths:
            with open(p, "rb") as f:
                while True:
                    block = f.read(1 << 20)
                    if not block:
                        break
                    out.write(block)
    total_size = os.path.getsize(merged)
    total_sha = sha256_file(merged)
    total_ok = total_size == args.size and total_sha == args.sha256
    print("拼合：大小 %d（应 %d）、sha256 %s —— %s"
          % (total_size, args.size, total_sha, "TOTAL_OK" if total_ok else "TOTAL_FAIL"))
    if not total_ok:
        return 2

    if args.check_only:
        print("CHECK_ONLY_OK：只校验，不发布")
        return 0

    with open(CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    release_token = cfg["release_token"]
    app_token = cfg["app_token"]

    boundary = "----jianli-release-%d" % os.getpid()
    body = b""
    for field, value in (("version", args.version), ("notes", args.notes)):
        body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                 % (boundary, field, value)).encode("utf-8")
    with open(merged, "rb") as f:
        data = f.read()
    body += ("--%s\r\nContent-Disposition: form-data; name=\"file\"; "
             "filename=\"v%s.zip\"\r\nContent-Type: application/zip\r\n\r\n"
             % (boundary, args.version)).encode("utf-8")
    body += data + ("\r\n--%s--\r\n" % boundary).encode("utf-8")
    req = urllib.request.Request(
        RELAY_BASE + "/api/admin/release", data=body, headers={
            "X-Release-Token": release_token,
            "Content-Type": "multipart/form-data; boundary=" + boundary,
        })
    with urllib.request.urlopen(req, timeout=600) as r:
        print("发布接口：HTTP %d %s" % (r.status, r.read().decode("utf-8", "replace")))

    req = urllib.request.Request(RELAY_BASE + "/api/version",
                                 headers={"X-App-Token": app_token})
    with urllib.request.urlopen(req, timeout=60) as r:
        ver = json.load(r)
    print("核对 /api/version：version=%s size=%s sha256=%s"
          % (ver.get("version"), ver.get("size"), ver.get("sha256")))
    if (str(ver.get("version")) != args.version or ver.get("size") != args.size
            or ver.get("sha256") != args.sha256):
        print("FAIL：/api/version 与预期不一致", file=sys.stderr)
        return 2
    with urllib.request.urlopen(RELAY_BASE + "/api/ai/health", timeout=60) as r:
        print("核对 /api/ai/health：%s" % r.read().decode("utf-8", "replace").strip())
    n = subprocess.run(["pgrep", "-fc", "bot.js"],
                       capture_output=True, text=True).stdout.strip()
    print("核对 bot.js 进程数：%s" % n)
    print("PUBLISH_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
