# 发布门槛：默认全部未验收

本清单不是一次人工确认字符串就自动完成的测试。测试失败、不支持的场景或缺少证据均不得标成通过。使用测试账户、模拟凭据或测试硬件；禁止把真实主密码、会话令牌、数据库或 PRF 解密材料贴入公开 CI 日志。

## 源码和基础构建

- [ ] 稳定版 1.37.3 与固定 PR feature diff 的冲突逐个解决，未丢失稳定版安全修复。
- [ ] 完整仓库补丁应用、cargo fmt、cargo test 通过；两个原生架构的构建、测试与启动均成功。
- [ ] SQLite/MySQL/PostgreSQL 都通过实际数据库迁移/查询测试，而不只是编译多数据库 feature。
- [ ] 实际 manifest 只包含 linux/amd64 与 linux/arm64；记录各架构 digest、manifest digest、源码 commit、构建 run。
- [ ] 依赖/镜像漏洞扫描结果已人工审查。此候选工作流没有声称已完成容器 CVE 扫描或供应链证明。

## WebAuthn 登录与注册

- [ ] 目标 Web Vault、实际使用的浏览器扩展与硬件/平台 passkey：注册、登录、退出、再次登录均成功。
- [ ] 有 PRF 的凭据可以真正解密现有项目；无 PRF 凭据登录后的主密码解锁行为正确。
- [ ] 两个不同 PRF 凭据均可锁定后解锁；/sync 和 /identity/connect/token 的字段大小写与客户端兼容。
- [ ] 完整有效认证请求顺序重放、并发重放均最多一个成功；counter=0 的模拟同步 passkey 同样成立。
- [ ] 过期 challenge、伪造 JWT、错误签名、错误 RP/origin、错误 userHandle、UV=false 均失败。
- [ ] 注册 challenge 顺序/并发重复提交最多创建一条凭据；过期和轮换之前的旧注册 challenge 失败。
- [ ] 相同 credential ID 跨账户、同账户同时注册均被数据库唯一约束拒绝。
- [ ] 计数器倒退和并发旧状态覆盖被拒绝；合法 counter=0 仍可进行不同 challenge 的登录。

## 策略、生命周期、常规功能

- [ ] PASSKEY_LOGIN_ALLOWED=false 后，签发挑战、登录与 Passkey refresh 被拒绝，删除已有凭据仍可执行。
- [ ] SSO_ONLY=true 场景下，Passkey 新登录和 refresh 不绕过策略；已签发 access token 的失效策略另行确认。
- [ ] 账户禁用、凭据删除、设备登出、安全戳变化、邮箱验证要求和登录失败事件记录符合预期。
- [ ] 单进程中并发注册/账号加密密钥轮换不会留下旧密钥包装；存在 passkey 时轮换明确拒绝且无部分写入。
- [ ] 普通密码修改、KDF 修改、密码重置、组织恢复、紧急访问接管逐个验证；不支持的路径明确阻断并说明。
- [ ] 原主密码登录、TOTP/WebAuthn 2FA、API key、移动端/扩展同步、WebSocket、附件、Send、管理页无回归。
- [ ] 确认只运行一个 Vaultwarden 进程；此候选进程锁不是多副本共库方案。

## 真实数据升级、恢复与运行配置

- [ ] 记录当前正在运行的官方镜像版本/digest，而不是根据 latest 标签猜测。
- [ ] 一致性备份整个 /data（及外部 DB），在备份副本上测试，不双开同一个生产数据目录。
- [ ] 保持生产 DOMAIN/RP/origin 不变；测试域名的凭据不被误认为可以搬回另一个 RP。
- [ ] 验证项目数、组织数据、附件、Send、RSA 密钥、admin 配置和实际解密；不只检查 HTTP 200。
- [ ] 启动/重启、文件权限、现有反向代理、证书、健康检查、数据库连接方式均验证。
- [ ] 恢复升级前备份并运行旧 digest 的回滚演练成功，确认备份后写入如何处理。
- [ ] GitHub package 拉取权限、production-images 审批规则、人工提升 digest 均已配置。

完成后才能使用提升工作流中的 WEB_AUTHN_AND_REAL_DATA_UPGRADE_TESTED 确认字符串。该字符串只记录操作者声明，不是自动化测试证据。
