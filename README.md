# 简历猎手 AI 云端中转

Python 标准库、零依赖的中转服务。exe 以后不再直连 AI 服务商、不再带 Key，
改为调这个中转；服务商 Key 只放在服务器上的配置文件里。

链路：`exe → 中转（X-App-Token 鉴权、每 IP 每天限流、上游并发 1）→ 智谱`

- 中转地址：`http://43.139.24.90:8687`
- 聊天接口：`POST http://43.139.24.90:8687/api/ai/chat`，请求头带 `X-App-Token`
- 健康检查：`GET http://43.139.24.90:8687/api/ai/health`
- 管理页：`http://43.139.24.90:8687/admin`

## 文件清单

| 文件 | 说明 |
|---|---|
| `relay.py` | 中转服务本体（`http.server` ThreadingHTTPServer，监听 0.0.0.0:8687） |
| `config.example.json` | 配置模板（`api_key` 为空，`admin_password_hash` 为 null） |
| `jianli-relay.service` | systemd 单元 |
| `deploy.sh` | 一键部署脚本（幂等、非交互、root 运行） |
| `test_relay.py` | 本地验证脚本（桩上游 + relay，10 组断言） |
| `README.md` | 本文件 |

## 配置（`/root/jianli-relay/config.json`，0600）

| 字段 | 默认值 | 说明 |
|---|---|---|
| `provider` | `zhipu` | 服务商 |
| `model` | `glm-4.7-flash` | 默认模型 |
| `base_url` | `https://open.bigmodel.cn/api/paas/v4` | 服务商 Base URL |
| `api_key` | `""` | 服务商 Key（只放服务器，绝不进 exe、不进仓库明文） |
| `ai_enabled` | `true` | 关掉后 chat 返回 503，exe 回落本地规则 |
| `app_token` | `""`（部署时由 TAT 命令写入） | exe 调中转用的共享令牌（两边一致） |
| `allowed_models` | `["glm-4.7-flash", "glm-4-flash-250414"]` | 允许的模型白名单 |
| `admin_password_hash` | `null` | 管理员密码哈希（PBKDF2-HMAC-SHA256，20 万次迭代） |
| `port` | `8687` | 监听端口 |
| `daily_limit_per_ip` | `200` | 每 IP 每天最多调用次数 |

启动时缺字段用默认值补齐。调用计数按日期记在配置文件旁的
`usage-YYYYMMDD.json` 里。

## 部署（腾讯云 Lighthouse 43.139.24.90）

服务器上 QQ 机器人占 3010–3013 / 6100–6101，8687 不冲突。

1. 把本目录文件传到服务器 `/root/jianli-relay/`（控制台文件上传 / scp / git 任选）。
2. 腾讯云控制台 → TAT「执行命令」，一键跑：

```bash
bash /root/jianli-relay/deploy.sh
```

脚本会：拷贝 `relay.py` 和 systemd 单元；没有 `config.json` 时才从模板创建
（已有的绝不覆盖）；`daemon-reload`、`enable`、`restart`；最后 curl 健康检查并打印结果。

手动检查：`systemctl status jianli-relay`，看日志：`journalctl -u jianli-relay -f`。

## lucky 下一步

1. 打开管理页 http://43.139.24.90:8687/admin ，首次设置管理员密码（≥6 位）。
2. 在管理页填智谱 Key（GLM-4.7-Flash 免费模型），保存。
3. 确认健康检查返回 `{"ok": true, ...}`，再让 exe 切到中转地址。

## 到期风险

- 腾讯云 Lighthouse 免费试用到 **2026-12-13**，到期不续费中转就停了；
  exe 要有回落：中转不通 / 返回 503 时用本地规则评分，不要卡死。
- 免费试用服务器本身也可能被回收，`config.json`（含 Key 和管理员密码哈希）
  请另外备份一份在自己手里。

## 安全说明

- **只放行免费模型**：`allowed_models` 白名单只有 `glm-4.7-flash` 和
  `glm-4-flash-250414`，chat 指定别的模型直接 400，改白名单要进管理页。
- **App-Token 不是服务商 Key**：它只是挡滥用的共享令牌，丢了在管理页点
  「轮换 App-Token」生成新的，exe 里同步换掉就行；服务商 Key 不会因此泄露。
- **Key 绝不外泄**：管理页只显示掩码（如 `sk-...real`）；日志只打请求行，
  不记任何 header / body；上游失败只返回 `{"error": "upstream_failed"}`，
  不把上游返回体带出来。
- **限流**：每 IP 每天默认 200 次，超了 429；上游全局并发 1，拿不到锁等 30 秒，
  超时 429。管理员会话 12 小时过期，HttpOnly Cookie。
- **不要在 exe 里再放服务商 Key**，也不要把填好 Key 的 `config.json` 发给别人。

## 本地验证

```bash
python3 test_relay.py
```

起桩上游（127.0.0.1:18099）+ relay（127.0.0.1:18098，临时配置），
10 组断言：chat 200、错/无 Token 401、不允许的模型 400、health 形状、
管理端 setup→login→config 掩码→改 model 生效→轮换 token、stats 计数、
上游挂了 502、ai_enabled=false 时 503、daily_limit=2 时第 3 次 429。
