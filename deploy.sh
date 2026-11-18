#!/bin/bash
# 简历猎手 AI 云端中转 - 一键部署脚本
# 幂等、非交互、root 运行。
#
# 用法（腾讯云控制台 TAT「执行命令」）：
#   1. 先把本目录文件（relay.py、config.example.json、jianli-relay.service、
#      deploy.sh）传到服务器 /root/jianli-relay/
#   2. TAT 里执行一键命令：bash /root/jianli-relay/deploy.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "错误：请用 root 运行本脚本" >&2
  exit 1
fi

command -v python3 >/dev/null || { echo "错误：服务器上没有 python3" >&2; exit 1; }
command -v curl >/dev/null || { echo "错误：服务器上没有 curl" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "错误：服务器上没有 systemctl" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/root/jianli-relay"

mkdir -p "$INSTALL_DIR"

# relay.py（脚本与目标同一文件时不重复拷贝）
if [ "$SCRIPT_DIR/relay.py" != "$INSTALL_DIR/relay.py" ]; then
  cp -f "$SCRIPT_DIR/relay.py" "$INSTALL_DIR/relay.py"
fi
chmod 644 "$INSTALL_DIR/relay.py"

# 配置：没有才从模板创建，已有的绝不覆盖
if [ ! -f "$INSTALL_DIR/config.json" ]; then
  cp "$SCRIPT_DIR/config.example.json" "$INSTALL_DIR/config.json"
  echo "已从模板创建 config.json（部署后请到管理页设置密码、填服务商 Key）"
else
  echo "config.json 已存在，不覆盖"
fi
chmod 600 "$INSTALL_DIR/config.json"

# systemd 单元
cp -f "$SCRIPT_DIR/jianli-relay.service" /etc/systemd/system/jianli-relay.service
chmod 644 /etc/systemd/system/jianli-relay.service

systemctl daemon-reload
systemctl enable jianli-relay
systemctl restart jianli-relay

# 验证：等服务起来后调健康检查（最多等 20 秒）
for i in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:8687/api/ai/health" 2>/dev/null; then
    echo
    echo "部署成功：中转服务正在运行"
    echo "管理页：http://43.139.24.90:8687/admin"
    exit 0
  fi
  sleep 1
done

echo "错误：服务启动后健康检查失败，请检查 systemctl status jianli-relay" >&2
systemctl status jianli-relay --no-pager || true
exit 1
