# 配对服务器协议 v1

协议未正式发布；当前字段必须精确匹配。未知字段、缺字段、重复字段、null、尾随 JSON、超过 64 KiB 的请求均拒绝。成功返回 JSON，失败为 `{"code":"p2p.<错误码>"}`；不返回 SQL/密码/私钥。

## 认证与资源边界

普通 HTTPS 客户端校验服务器 TLS。用户接口使用 `Authorization: Bearer <token>`，设备接口使用签发的 Ed25519 mTLS 证书。两种身份不能互换，不能通过 body.userId、网络 ID 或自报 deviceId 授权。禁止 URL 查询携带凭证，禁止重定向携带旧认证材料。

ID 为 32 位小写十六进制随机值；服务公钥指纹为 SHA-256 小写十六进制。所有时间为 Unix 秒。账号用户名 3–64 位 ASCII 字母/数字/`_.-`，必须以字母或数字开始；密码 12–72 字节。名称 1–256 UTF-8 字节，拒绝首尾空白、换行和 NUL。

## 用户管理 API

除 login 外，下表均要求用户 bearer。GET 不带 body；没有业务字段的写操作发送 `{}`，不省略请求体。

| 方法与路径 | body | 结果 |
| --- | --- | --- |
| POST `/v1/login` | username, password | user, token, expiresAt |
| GET `/v1/user` | — | userId, username |
| POST `/v1/logout` | `{}` | loggedOut |
| GET `/v1/networks` | — | 自己的有效网络数组 |
| POST `/v1/networks` | name | networkId, userId, name |
| PATCH `/v1/networks/:networkId` | name | 原 networkId、更新名称 |
| DELETE `/v1/networks/:networkId` | `{}` | deleted |
| POST `/v1/networks/:networkId/enrollment-tokens` | `{}` | token, networkId, expiresAt |
| GET `/v1/devices` | — | 自己的设备数组 |
| GET `/v1/networks/:networkId/devices` | — | 该网络的有效绑定设备 |
| POST `/v1/networks/:networkId/devices` | deviceId | bound；仅限自己已有设备 |
| DELETE `/v1/networks/:networkId/devices/:deviceId` | `{}` | unbound |
| GET `/v1/networks/:networkId/pairs` | — | 该网络的配对及终态 |
| DELETE `/v1/networks/:networkId/pairs/:pairId` | `{}` | deleted |

网络删除是保留审计的逻辑删除；绑定、凭证及配对同事务失效。解绑只影响指定网络，重新绑定不恢复旧配对。没有用户凭证或失效凭证返回 401；跨用户资源访问返回 403，正文不泄露资源归属。

## 设备登记与配对

无需设备证书：

| POST 路径 | body | 说明 |
| --- | --- | --- |
| `/v1/identity` | nonce | 服务身份/端点签名说明，nonce 必须为随机 ID |
| `/v1/enroll` | requestId, token, csr, name | 单次网络绑定凭证 + PEM CSR；返回 deviceId/userId/publicKey/name/certificate |
| `/v1/enrollment-query` | requestId, publicKey, issuedAt, signature | 60 秒内私钥持有证明，查询丢失的登记结果 |
| `/v1/recover-certificate` | deviceId, requestId, csr, token | 已到期证书、同密钥及同用户已绑定网络的新凭证 |

设备 mTLS：GET `/v1/me`、GET `/v1/pairs`；POST `/v1/heartbeat`（`{}`）、`/v1/renew-certificate`（requestId, csr）。publicKey/certificate 为 JSON 标准 base64 字节串。

1. B 调用 POST `/v1/share`，body 为 `{networkId}`；返回签名的 Share。
2. A 调用 POST `/v1/invite`，body 为 `{share}`，其中 share 是 Share JSON 的无填充 base64url。必须双方有该网络绑定且用户相同。
3. B 调用 POST `/v1/pair-action`，body `{pairId,action:"approve",fingerprint:""}`，或使用 `reject`。
4. A 核对目标公钥指纹后用 action `confirm`、准确 fingerprint 激活关系。单个有效关系内只有一条 active/pending 配对。
5. 已激活关系可用 action `revoke`。用户管理接口也能删除 pending/active 配对。

设备 mTLS `GET /v1/pairs/:pairId/identity` 返回 `{pair,initiator,target}`。两端身份各含 `deviceId,userId,publicKey,name,presence`；不返回 certificate。仅参与者在双方账号/绑定有效时可读取 invited、approved、active 配对；拒绝 rejected/revoked、过期的待确认关系及无关设备。presence 为 offline/online/stale，读取身份本身不授予连接权限。客户端明确核对后固定公钥，后续不能按该接口自动覆盖旧信任。

Share 签名字节是 UTF-8 紧凑 JSON 数组：`["dshker.pair-share.v1",version,serviceId,networkId,deviceId,fingerprint,nonce,expiresAt]`，签名为 Ed25519，编码为无填充 base64url。Share 的所有字段含 signature 都必填。

## 信令与租约

WSS `/v1/signals` 要求设备证书和子协议 `dshker.signal.v1`；禁止浏览器 Origin。每设备仅一条 WSS，会话在线心跳周期 10 秒，30 秒未更新即 stale。

POST `/v1/attempt`：`{pairId,generation}`；POST `/v1/lease` 和 `/v1/end`：`{pairId,attemptId}`。必须双方在线、同网络有效绑定、配对 active。attempt 独占同一配对，重复拨号返回 busy。

租约字段：version, serviceId, userId, networkId, pairId, attemptId, fromDeviceId, toDeviceId, generation, revision, expiresAt, permission, signature。

租约签名字节：`["dshker.lease.v1",version,serviceId,userId,networkId,pairId,attemptId,fromDeviceId,toDeviceId,generation,revision,expiresAt,permission]`。permission 只能为 `dsh-session`。客户端必须用**已固定的**用户、网络、服务公钥、双方身份、配对、attempt/generation 和 revision 验证，不可把收到的字段当成期望值。

信令字段：version, type, messageId, attemptId, generation, fromDeviceId, toDeviceId, pairId, sequence, expiresAt, payload, signature。

签名字节：`["dshker.signal.v1",version,type,messageId,attemptId,generation,fromDeviceId,toDeviceId,pairId,sequence,expiresAt,payload]`。网络由服务器根据 pairId 与已签名租约查询验证，不接受自报网络覆盖。type 只允许 offer/answer/candidate；payload 为对应严格 JSON 的 base64url，不是 DSH 帧。

代际与序号必须为正整数且不超过 JavaScript 精确整数范围；信令有效期不超过 60 秒，每次 attempt 限制 512 条、每设备输出队列 32 条。签名重放、错序、伪造发送者和失效绑定拒绝。offer 先于 answer，candidate 的 sdpHash 必须绑定已接受的 SDP。

服务端仅发送 ready、attempt、signal、revoked 等控制事件。WSS 掉线不能自动改为业务中继；客户端已建立的直连只允许持续至当前租约到期。

## 跨仓兼容

本仓库 `internal/protocol` 与 DSHKer `networking/internal/protocol` 分别实现同一 wire 合约。两仓保留同一规范签名字节与 golden 用例，发布前必须验证；不存在本地 replace、Go runtime 共享依赖或跨仓私有 import。peer 帧不由配对服务器解码转发。
