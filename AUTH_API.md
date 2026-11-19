# 简历猎手鉴权接口规范（机器码绑定 + 纯时间制卡密）

极简鉴权：无账号密码。客户端按硬件特征算出 `machine_id`，服务端只给每个
`machine_id` 记一个过期时间 `expire_at`，有效期内不限投递次数。

- 试用：新机器首次调 `/api/auth/info`，服务端自动送 1 小时（服务端记，删本地文件也没用）。
- 天卡：+24 小时；周卡：+7 天。新过期时间 = `max(现在, 原过期时间) + 时长`，多张卡可叠加。
- 单卡单机：卡密首次激活即绑定当前机器并作废，别人再用报错，自己重复用也报错。

## 密钥与签名（HMAC-SHA256）

- 密钥：复用中转的 App-Token（`X-App-Token` 那个值），只存在服务器 `config.json` 与 exe 配置里。
- 请求签名：`signature = HMAC-SHA256 hex(App-Token, machine_id + "|" + timestamp)`，
  `timestamp` 为 Unix 秒（整数）。请求头带 `X-Auth-Sign`，body 里也要带 `machine_id`、
  `timestamp`、`signature`，两者值相同；服务端校验 body 的 `signature`，`X-Auth-Sign`
  请求头如果带了也会一并校验，对不上同样拒收。
- 响应签名：`signature = HMAC-SHA256 hex(App-Token, machine_id + "|" + expire_at + "|" + remaining_seconds + "|" + server_time)`，
  `server_time` 为服务端当前 Unix 秒。客户端收到 `/api/auth/info` 后应按此式验签，
  验不过就当服务端数据不可信。
- 时间窗：请求 `timestamp` 与服务端时间相差超过 300 秒拒收（防重放）。客户端不要用
  本地系统时间算剩余时长——倒计时以服务端返回的 `remaining_seconds` 为准。
- 所有鉴权接口同时要求 `X-App-Token` 请求头正确（与 `/api/ai/chat` 同方式），不对返回 401。

## 机器码

`machine_id` = 硬件特征（主板序列号、CPU ID、硬盘 UUID 等）拼起来做 SHA-256，
64 位小写 hex。格式不对返回 400 `invalid_machine_id`。

## 接口

### POST /api/auth/info —— 查授权状态

请求：

```json
{"machine_id": "ab12…（64 位）", "timestamp": 1732456789, "signature": "hmac hex"}
```

响应 200：

```json
{"machine_id": "ab12…", "expire_at": 1732463989, "remaining_seconds": 3600,
 "status": "trial", "signature": "hmac hex", "server_time": 1732456789}
```

- `status`：`trial`（试用中）/`active`（卡密有效）/`expired`（已过期，`remaining_seconds` 为 0）。
- 新机器首次调用：建记录，`expire_at = 现在 + 3600`，`status` 为 `trial`；同一机器再查
  不重复送，返回现有过期时间对应的剩余秒数。
- 错误：无/错 App-Token 401 `unauthorized`；签名错 401 `bad_signature`；
  时间戳超 300 秒 401 `stale_timestamp`；`machine_id` 格式错 400 `invalid_machine_id`。

### POST /api/auth/activate —— 激活卡密

请求：

```json
{"machine_id": "ab12…", "card_code": "JL-D-AB12-CD34-EF56", "timestamp": 1732456789, "signature": "hmac hex"}
```

响应 200：

```json
{"expire_at": 1732550389, "remaining_seconds": 93600, "added_seconds": 86400, "card_type": "day"}
```

- 错误（均为 400）：`invalid_card`（格式不对或查无此码）、`card_used`（这台机器重复用）、
  `card_bound_other`（这张卡已绑别的机器）、`bad_signature`、`stale_timestamp`。
  无/错 App-Token 401 `unauthorized`；`machine_id` 格式错 400 `invalid_machine_id`。
- 注意：info 的签名/时间戳问题返回 401，activate 的同类问题返回 400（约定如此）。
- 万能卡（见下节）走同一接口：命中时返回 `card_type: "master"`、`added_seconds: 315360000`。

## 万能卡（管理员内部测试与售后补时）

- 设定：在管理页“万能卡”区输入后点「保存/更换」，或调 `POST /api/admin/master-card`
 （需管理员登录），值存在服务器 `config.json` 的 `master_card` 字段里，保存后立即生效，
  不用重启。空字符串 = 未设置、功能关闭。**万能卡值绝不在任何接口响应、管理页、日志里出现；
  管理页只显示“已设置/未设置”。**
- 激活行为：`POST /api/auth/activate` 先校验万能卡（仅当已设置时，用
  `hmac.compare_digest` 比对提交的 `card_code`），命中则新过期时间 =
  `max(现在, 原过期时间) + 315360000 秒`（10 年），可叠加、可重复用、不限机器，返回
  `{expire_at, remaining_seconds, added_seconds: 315360000, card_type: "master"}`。
  命中万能卡时绝不把该码写进卡库。没命中再走原有卡密流程。
- 轮换：管理页重新保存一个新值即可，旧码立即失效；留空保存 = 清掉万能卡，清掉后该码激活
  报 `invalid_card`。
- 审计：每次万能卡激活记一条 `{machine_id, used_at}`，存在 `auth_master_uses.json`
  （只留最近 200 条），`GET /api/admin/master-card` 返回 `{set: true/false,
  uses: [{machine_id, used_at}, ...]}`（最新在前，最多 100 条）。
- 错误：设万能卡时 code 少于 12 个字符报 400 `invalid_master_card`；
  未设置万能卡时，拿任意码激活都按普通卡密走（查无此码报 `invalid_card`）。

## 卡密格式与规则

- 天卡：`JL-D-XXXX-XXXX-XXXX`，激活 +86400 秒；周卡：`JL-W-XXXX-XXXX-XXXX`，激活 +604800 秒。
- `X` 字符集：`ABCDEFGHJKMNPQRSTUVWXYZ23456789`（去掉容易混淆的 0/O/1/I/L）。
- 叠加：新过期时间 = `max(现在, 原过期时间) + 时长`。没过期先续，相当于顺延；已过期从现在起算。
- 绑定：首次激活即写死 `machine_id` 并作废；同一张卡第二次用，本机报 `card_used`，别机报
  `card_bound_other`；失败的激活（签名错、时间戳过期等）不消耗卡密。

## 管理员接口（需管理员登录会话，与现有管理接口一样）

### POST /api/admin/cards/generate —— 生成卡密

请求：`{"type": "day"|"week", "count": 1..100}`；
响应 200：`{"codes": ["JL-D-…", …], "batch_id": "B20261119123045XK"}`。
同一次调用生成的卡共享一个 `batch_id`（B + 生成时刻 UTC + 2 位随机码，防同秒碰撞），供“仅看最新批次”筛选。
“最新批次”按库内单调递增的批次序号判定，不靠秒级时间戳（同秒连点两次生成也不会认错）。
错误：`invalid_type` / `invalid_count`（400）；未登录 401。

### GET /api/admin/cards —— 卡密列表

查询参数（都可选）：`status=all|unused|used|expired`、`type=all|day|week`、
`batch=all|latest|<batch_id>`、`q=关键词`（不区分大小写，同时匹配卡密与机器码）、
`limit=1..1000`（默认 500）、`offset`（默认 0）。响应 200：

```json
{"total": 12, "counts": {"unused": 9, "used": 2, "expired": 1},
 "batches": [{"batch_id": "B20261119123045", "count": 10, "created_at": 1732456789}],
 "cards": [{"code": "JL-D-…", "type": "day", "status": "unused", "batch_id": "B…",
            "machine_id": null, "used_at": null, "created_at": 1732456789}]}
```

`status`：`used` = 已绑定机器；`expired` = 未用且生成超过 90 天（只作筛选/清理标记，
不影响激活——久置的卡照样能激活）；其余未用 = `unused`。`counts` 是在 status 之外
其他筛选条件已筛完的基础上算的各状态计数；`batches` 是全部批次（最新在前）。
列表按生成时间倒序。错误：`invalid_status` / `invalid_type` / `invalid_paging`（400）；未登录 401。

### POST /api/admin/cards/delete —— 删除卡密

请求二选一：`{"codes": ["JL-D-…", …]}`（按卡号列表，≤1000 张）或
`{"filter": {"status": …, "type": …, "batch": …, "q": …}}`（按筛选条件删，
与列表接口同一套筛选语义）。默认只删未用/已过期的卡：如果目标里有已用卡，
不带 `confirm_used: true` 会返回 400 `{"error": "has_used", "used_count": N, "used": […]}`，
一张也不删；带上 `confirm_used: true` 才会连已用卡一起删。
成功响应 200：`{"deleted": […], "deleted_count": N, "not_found": […]}`。
错误：`ambiguous`（卡号与筛选条件同给）/ `invalid_codes` / `invalid_request` /
`too_many`（按条件删超过 1000 张）/ `has_used`（400）；未登录 401。

### POST /api/admin/machines/extend —— 给机器延长时间（售后手动）

请求：`{"machine_id": "ab12…", "add_seconds": 3600}`（正整数秒）；
响应 200：`{"expire_at": 1732460389, "remaining_seconds": 10800}`。
机器不存在时新建记录，从现在起算（不送试用）；已存在则按叠加规则延长。
错误：`invalid_machine_id` / `invalid_add_seconds`（400）；未登录 401。

### POST /api/admin/master-card —— 设万能卡

请求：`{"code": "至少 12 个字符"}`；响应 200：`{"ok": true, "set": true}`。
`code` 为空字符串 = 清掉万能卡（响应 `{"ok": true, "set": false}`）。
错误：`invalid_master_card`（少于 12 个字符或非字符串，400）；未登录 401。
保存后立即生效，不用重启；值只存 `config.json`，绝不在响应里回显。

### GET /api/admin/master-card —— 万能卡状态与使用记录

响应 200：`{"set": true, "uses": [{"machine_id": "ab12…", "used_at": 1732456900}]}`。
`set` 表示是否已设置；`uses` 最新在前，最多 100 条。未登录 401。

管理页也有“卡密管理”区：生成卡密（类型 + 数量）、卡密列表（码、类型、状态、绑定机器前 12 位、
批次），带搜索框、状态/类型筛选、“仅看最新批次”开关、“复制当前筛选结果”，列表默认只显示前 10 张
（可展开全部），右下角有“回顶”“到底”悬浮按钮；每行可勾选，勾选后底部弹出批量操作栏（复制所选 /
删除所选），也支持单条删除和按筛选条件批量删除，删已用卡或批量删时要二次确认；给机器延长时间
（机器码 + 天数），不用调接口。管理页还有“万能卡”区：密码框式输入 +
「保存/更换」按钮，只显示“已设置/未设置”，下面列出使用记录（机器码前 12 位 + 使用时间）。

## 存储

与 `config.json` 同目录，两个 JSON 文件，原子写（先写临时文件再替换，0600），只用标准库。
`deploy.sh` 只下载四个代码文件，不覆盖它们。

- `auth_machines.json`：`{machine_id: {"expire_at": 1732463989, "created_at": 1732456789, "trial": true}}`
  （`trial` 为 true 表示还在试用期；激活过卡密或售后延长过的为 false）
- `auth_cards.json`：`{code: {"type": "day", "machine_id": "ab12…", "used_at": 1732456900, "created_at": 1732456789, "batch_id": "B20261119123045"}}`
  （`machine_id`、`used_at` 为 null 表示未使用；`batch_id` 为同批生成的批次号，2026-11-19 之前的旧卡没有这一项）
- `auth_master_uses.json`：`[{"machine_id": "ab12…", "used_at": 1732456900}]`
  （万能卡使用记录，只留最近 200 条；万能卡本身存在 `config.json` 的 `master_card` 字段里，不进卡库）

## 客户端流程（建议）

1. 启动时调 `/api/auth/info` 拿 `remaining_seconds`，在内存里倒计时刷新授权状态栏，
   倒计时基准以服务端返回为准，不要信本地系统时间。
2. 投递主循环里每隔几分钟或每次换岗位前重查一次 `/api/auth/info` 同步状态；
   一旦 `remaining_seconds` 为 0，立即停掉所有平台投递，提示“授权已到期，请输入天卡或周卡继续使用”。
3. 每次请求都带当前 Unix 秒 + 新算的 HMAC 签名；响应验签不过就当失败处理，不要信里面的时间。
