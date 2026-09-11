# DSHKer Server

独立的 DSHKer 配对与组网认证服务器。**Go + Gin，单二进制，SQLite 本地存储。**

## 功能

- 分用户管理：本地创建/禁用账号，HTTPS 登录、会话到期和登出；用户只能管理自己的资源。
- 私有网络：创建、列表、改名、删除；设备可绑定多个同用户网络。
- 设备绑定：单次限时凭证、CSR 私钥持有证明、设备 mTLS、绑定与解绑。
- 双向配对：目标分享码、邀请、目标批准、发起端指纹确认；可删除配对。
- 组网认证：签名信令、明确网络范围、短期租约；删除网络、解绑或禁用账号后拒绝信令与续租。
- 直连协商：WSS 交换控制消息，自建 UDP STUN；DSH 数据由 DSHKer peer 端到端加密传输，直连不可用时回退到本服务器的 TURN 不透明中继（只转发密文，服务器无法读取业务流量）。

不依赖 NetHopper、OneIsland、NATS、Redis、MySQL、桌面源码、私有模块或其他项目配置。客户端只通过 [协议](docs/protocol.md) 对接，不 import 服务器源码。

当前是开发实现，尚未完成 DSHKer P2P 界面联调及跨物理机验收，不是已发布产品。现有 SSH 功能不因此被替换。

## 构建与测试

需要 `go.mod` 指定的 Go 1.27.0。单独克隆本仓库即可，**无需 go.work 或相邻仓库**。

```sh
go mod download
go test -race ./...
go vet ./...
go run ./tools/check-boundaries
go build -trimpath -o bin/dshker-server ./cmd/dshker-server
```

本仓库不包含 go.work，也不在 CI 或部署命令中关闭/替换它。若开发者主动将项目注册进自己的 workspace，依赖版本和 vendor 由该 workspace 管理，不能据此给服务器添加本地 replace 或私有依赖。

## 部署

需要一台 Linux 主机、域名、有效 TLS 证书及一个 TCP 和一个 UDP 端口。部署服务不需要 Go、Node.js、DSHKer 或外部数据库。

1. 构建或取得与你的服务器架构一致的二进制，放入 `/usr/local/bin/dshker-server`。
2. 创建专用系统用户 `dshker-server`，准备 `/etc/dshker-server` 与归该用户所有的 `/var/lib/dshker-server`（权限 0700）。
3. 复制 `config.example.json` 到 `/etc/dshker-server/config.json`，逐项填写真实地址和文件路径。样例值不是默认配置；核心字段不可省略。中继字段 `turnSharedSecret`/`relayPublicIP` 可选：留空即纯 STUN 服务、不下发 TURN 凭据（对旧配置完全兼容）。
4. 放置 TLS 证书与私钥，确保服务用户可读，私钥仅该用户可读。放行配置的 TCP 8443 和 UDP 3478（可显式修改）。HTTPS/WSS 必须直接终止于服务器，或使用 TCP 透传；不支持由 HTTP 反代终止设备 mTLS 后转发伪造身份头。

### 可选：启用不透明中继（TURN）

在 `config.json` 中设置以下字段并重启服务，UDP 3478 同一 socket 同时应答 STUN Binding 与 TURN 控制：

- `turnSharedSecret`：十六进制字符串，至少 32 字节（`openssl rand -hex 32`），用于按设备派生 24 小时 TURN-REST 凭据（`<unix到期时间戳>:<设备ID>` / HMAC-SHA1），协调器不持久化。
- `relayPublicIP`：服务器公网 IP（NAT 或云 LB 后部署时必需），作为中继分配地址通告给对端。
- `turnListen`：可选，默认与 `stunListen` 相同端口。
- 分配端口由操作系统临时端口范围决定（默认约 49152–65535），不提供固定范围配置。

启用后设备经 `/v1/turn-credentials` 领取自己的中继凭据；直连不可建立时 ICE 走该中继，服务器只转发 DTLS/SCTP 密文。云防火墙须额外放行 UDP 49152–65535（以实际系统临时端口范围为准），并在 `turnSharedSecret` 缺失或太短时报 `p2p.relay_unconfigured`。
5. 使用服务用户初始化全新状态，再创建账号：

```sh
sudo -u dshker-server /usr/local/bin/dshker-server init --config /etc/dshker-server/config.json
systemd-ask-password '新账号密码（12–72 字节）' | sudo -u dshker-server /usr/local/bin/dshker-server user-add --config /etc/dshker-server/config.json --username alice
sudo -u dshker-server /usr/local/bin/dshker-server serve --config /etc/dshker-server/config.json
```

账号密码只从 stdin 读取，不支持密码命令行参数，不生成默认账号。创建成功仅输出 userId 和 username。

需要 systemd 托管时，检查并安装 [服务文件](deploy/dshker-server.service)。模板没有自动失败重试：配置、证书或状态错误会明确退出，修复后由管理员重新启动。

```sh
curl --fail https://你的域名:8443/health/https
```

这个检查只证明 HTTPS 可达；WSS、UDP STUN 和最终 peer 会话必须分别验证。禁止 UDP 或无法打洞的 NAT 下，会话回退到本服务器的 TURN 不透明中继；不使用公共 STUN/TURN，也不自动转成 SSH。

## 使用流程

账号登录 → 创建网络 → 申请网络绑定凭证 → DSHKer 生成自己的私钥并登记 → 目标设备分享配对码 → 邀请、批准、确认指纹 → 申请短期授权并直连。

用户会话有效期 24 小时；登记凭证和分享码有效期 5 分钟且只能消费一次；设备证书有效期 30 天，剩余 7 天可同密钥续期。租约最长 60 秒，客户端每 20 秒续期。解绑/删除会立即拒绝新的授权请求；已签发租约最长仍有 60 秒有效期，不能宣称删除瞬间消灭已离线的连接。

```sh
sudo -u dshker-server /usr/local/bin/dshker-server user-disable --config /etc/dshker-server/config.json --user-id 明确的用户ID
```

禁用账号会撤销其登录会话和配对授权。没有跨用户邀请、公开注册、自动配对或用户身份转移。

## 状态与升级

SQLite 和签发私钥一起构成服务身份，权限必须为 0600。初始化不会覆盖已有路径。当前 schema 为 2，旧原型 schema 明确拒绝，不自动迁移。

普通重启保留当前用户、网络及配对，在线状态和 attempt 重新建立。备份必须停止服务后保存数据库与身份文件的匹配副本；禁止把早于撤销的备份直接覆盖在线状态后沿用旧授权。灾难恢复应在全新路径初始化新服务身份并重新创建用户、绑定、配对；本版本不提供保留旧授权的透明恢复。

构建输出、运行数据库、证书与真实配置不提交 Git。许可见 [LICENSE](LICENSE)。
