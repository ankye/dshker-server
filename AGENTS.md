# DSHKer Server

这是独立开源 Go 配对服务器，不是 NetHopper 或 OneIsland 服务。

- 只使用公开 Go module 依赖，不引入 NetHopper、OneIsland、NATS、私有模块、本地 replace 或其他项目配置。
- Gin 处理显式路由与请求校验；服务代码负责用户、网络、设备、配对授权；SQLite 负责事务持久化。
- 不使用 mediator/NATS 服务分层，不生成其他产品协议。客户端仅通过版本化 HTTPS/WSS 协议通信。
- 不提供默认账号、默认根目录、自动降级认证或公共 STUN/TURN。DSH 业务中继仅限自托管服务器的 TURN 不透明中继形式：只转发端到端加密的报文流，服务器不落盘、不读取业务内容。
- 所有凭证来自明确输入。日志不得包含密码、会话 token、私钥或 DSH 数据。
- 新增行为补齐授权失败、竞态、重启读回测试。测试支持代码只放 `_test.go`。
- 构建与部署不能依赖上层 workspace；在已有 go.work 的开发环境遵守其开发命令规范，但不可把工作区依赖写入本模块。
- 验证：`go test -race ./...`、`go vet ./...`、Linux amd64/arm64 构建、依赖边界检查。
