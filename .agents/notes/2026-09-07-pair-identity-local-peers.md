# 配对身份读回及本地双进程验证

- 所属变更：`add-dshker-user-networks`。用户先要求本地稳定性/压力/断连验证，不发布。
- 修复联调缺口：原配对列表只有设备 ID，接收方无法取得用于验证对端签名的公钥。新增设备 mTLS `GET /v1/pairs/:pairId/identity`，仅双方当前参与者可读公开身份/presence，不返回证书或私钥。
- admission 覆盖确认前不授予连接权限、第三方/匿名拒绝、过期/拒绝/撤销/解绑拒绝、重启 presence 不复活。`go test -mod=readonly -race ./internal/coordinator -run TestPairIdentity -count=1` 通过。
- 完整 `go test -mod=readonly -race ./...`、`go vet -mod=readonly ./...`、独立依赖边界、真实制品 HTTPS/持久化 smoke 通过。开发命令保留上层 go.work，服务无 NetHopper/OneIsland/NATS 或客户端源码依赖。
- DSHKer 仓库的 `networking/integration/` 启动此真实制品 + 两个独立 Go 测试进程，覆盖配对、128 MiB 传输、30 次重连、续租、强杀、撤销。驱动只存在测试文件，不进入本服务运行时。
- UI/真实 DSH HTTP/WS、公网、Windows 和跨物理机仍未验证；3.3/3.4 保持未完成。未部署、未推送、未发布。
