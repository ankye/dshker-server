# 独立配对服务器实现记录

## 用户边界

独立 `ankye/dshker-server` 仓库，Gin HTTPS/WSS + UDP STUN + SQLite。无 NetHopper、OneIsland、NATS、Redis、MySQL、私有模块、本地 replace 或客户端源码依赖。客户端 peer 留在 DSHKer，以 wire v1 通信。

本机规划变更为 `add-dshker-user-networks`；上层工作区 OpenSpec 只是开发记录，不是构建/部署前提。仓库内 README、配置样例与协议文档自包含。

## 实现

- 单二进制 serve/init/user-add/user-disable。账号无默认值；密码 stdin 输入、bcrypt 保存；随机 bearer token 仅保存 SHA-256 摘要，24 小时到期。
- 用户私有网络增删改查，多网络设备绑定/解绑，限定网络的单次登记、CSR/mTLS 与证书续期。
- 分享码/配对/租约限定网络与用户，目标批准与指纹确认不可省略；网络删除、解绑、删除配对及禁用账号撤销相应授权。
- 普通 HTTPS、mTLS、WSS 和真实 UDP STUN 测试沿用迁入的生产实现；测试支持不进入 cmd 构建依赖。
- Linux amd64/arm64 静态 ELF 构建通过。CI 文件已提供但尚未推送执行；本机交叉编译不等于 Linux runtime smoke。

## 验证与限制

- `test-gates/standalone-server.json` 为 data_critical，覆盖全部变更 Go 生产/工具文件、六类状态、字段与身份来源；quality-engineering 默认 verify 通过，不是 static 替代。
- `go test -mod=readonly -race ./...`、`go vet -mod=readonly ./...`、`go mod verify` 和 `go run -mod=readonly ./tools/check-boundaries` 通过。
- `tools/smoke` 运行真实已构建服务器进程，经可信测试 TLS 执行账号登录、网络创建/读回、绑定凭证、CSR 登记、成员读回、删除网络与登出后的拒绝；原始事件位于忽略的 `artifacts/server-smoke.json`，不含凭证。
- 本机 go.work 已注册本模块并由 Go 工具更新到 1.27.0。共享 vendor 原先未包含新模块；`go work vendor` 被其他项目缺失的 aiagentdb/runtimeconfig 与 aiworld/objectstore 阻断。未修改这些项目。验证采用官方 `-mod=readonly`，仍使用规定的 go.work，没有关闭/替换工作区；服务器 go.mod 已固定实际验证的公共依赖版本。
- 源码大小 gate 无超过 1000 行文件。依赖图无生产测试支持；实际二进制包含公开 Go 库，不要求这些库对应的外部服务。
- 仍未完成：DSHKer 端用户/网络/P2P UI 联调、完整 peer helper/DSH 数据面与跨机网络矩阵、公网部署。未发布或归档，不能把服务器本地验收等同于整个 P2P 功能验收。
