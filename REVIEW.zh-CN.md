# PR #7370 代码审查

审查日期：2026-09-22。PR：Add passwordless webauthn login。

- PR HEAD：`f7f2007f7bc0de870cb2d482467ab36072e3eed5`，来源 `RaphaelRoumezin/vaultwarden`。
- 审查时上游 base：`0cefa4cca7c9f2a5579dd290f78193b543818c51`。
- PR 元数据：open、未合并、mergeable=false、22 个文件、13 个提交。
- 候选稳定基线：`1.37.3`，官方发布日期 2026-09-13。

## 结论

**不建议把原 PR 直接接到真实密码库。** 登录状态/有效期/消费机制是发布前必须修改的设计问题。PR 讨论里已修的扩展 origin、PRF 字段与 Web Vault 兼容性问题不能代替当前代码审查；本次没有把“某个浏览器测试通过”当成安全通过。

本包是修复候选，不是上游认可的安全补丁，也不是完整安全审计。未编译、未运行 Rust 数据库集成测试、未执行真实 WebAuthn/PRF 客户端验证、未对你的数据作升级或恢复测试。现有 PR 检查接口返回多个 failure，而 Build 的 jobs 查询为空，不能据此断言失败根因是 Rust 编译。

## 主要发现及候选处理

### P1：客户端保存可重复使用的认证状态，JWT 又误用邀请期限

位置：`src/auth.rs::generate_passwordless_claims`；`src/api/identity.rs::get_webauthn_assertion_options`、`webauthn_login`。

原代码把 PasskeyAuthentication 直接放进 JWT，没有服务端一次性消费记录；exp 使用 invitation_expiration_hours，而不是登录挑战的短期限。库要求将认证状态保存在服务端，不能把“密码库密文尚未解密”当成绕过认证无害的理由：认证令牌仍授予 API 操作能力。

这是重放设计风险，不是已执行成功的攻击演示。单有 JWT 不足以伪造 WebAuthn 签名；攻击者还需要捕获有效的完整认证响应。尤其不能依赖 counter=0 的同步凭据来消除重放。

候选：独立 webauthn_challenges 表；JWT 仅携带随机 jti；120 秒有效；SELECT 后条件 DELETE，只有删除一行的请求获得 state；删除时重新核对过期；失败尝试也消费 nonce。挑战签发也应用登录限流。改用 webauthn-rs 正式 discoverable API，移除对私有 ast.credentials JSON 的修改。

### P1：Passkey 刷新令牌不遵循停用和 SSO_ONLY 策略

位置：`src/auth.rs` 的 refresh_claims.sub 分支；`src/api/identity.rs` 的 WebAuthn grant。

原刷新路径将 Webauthn 与 Password 合并，但 SSO_ONLY 的拒绝条件仅覆盖 Password；也没有在 WebAuthn refresh 中检查 passkey_login_allowed。

候选：对新挑战、注册、登录、刷新增加一致的后端检查；关闭后不再提供 /sync 的 PRF 解锁选项。关闭功能不等于撤销所有已经签发的 access token，也无法删除客户端已缓存的离线解密能力；如需会话失效，还要明确执行相应账户/设备会话撤销。

### P2：注册挑战缺少时限，读取/删除不是原子消费

位置：`src/api/core/webauthn.rs::post_webauthn`；`src/db/models/two_factor.rs::delete`。

原代码保存裸 PasskeyRegistration；没有应用层注册时限；读取挑战后调用 delete，但 delete 不区分删除一行与零行。两个并发请求可读到同一状态并都继续执行注册验证。

候选：120 秒注册 envelope；绑定账户 security_stamp；按 uuid、类型和精确 data 消费，并要求影响行数为 1。凭据删除即使在功能关闭后仍可执行。

### P2：凭据唯一性和持久化错误处理不足

位置：`src/db/models/webauthn_credential.rs`、PR 的三类数据库迁移。

原保存逻辑没有跨账户 credential ID 唯一性约束；查询使用 unwrap_or_default 隐藏数据库失败。库明确要求注册凭据不能已存在于其他账户。认证计数器更新也缺少数据库级比较并更新条件。

候选：添加 credential_id_hash 唯一索引；验证完整、非空的 PRF 加密密钥组；认证与注册使用返回 Result 的查询；显式检查计数器递增并对变更做 compare-and-swap。

兼容边界：这是从官方服务器升级的候选。对于已经使用其他 #7370 构建并注册了 passkey 的数据库，新增 hash 字段为空，候选不会静默信任这些旧行：旧登录凭据需删除后重新注册。没有自动解析/回填所有旧实验分支凭据的迁移。原官方镜像不存在这些 PR 特有的登录凭据行。

### P2：账号加密密钥轮换没有更新 Passkey 的加密用户密钥

位置：`src/api/core/accounts.rs::post_rotatekey` / RotateAccountUnlockData，配合 WebauthnCredential.encrypted_user_key。

原轮换处理更新用户密钥/密文，但没有对应的 Passkey key rewrapping，可能使 passkey 解锁持有过期加密密钥。不能靠“更换主密码成功”推断这条路径安全，因为主密码更换和账户加密密钥轮换不是同一个操作。

候选采取保守限制：存在登录 passkey 时，先拒绝账户加密密钥轮换，用户须移除后再轮换、重新注册。注册完成与该轮换路径用同一进程级 async mutex 排序，并在锁后重查账户 security_stamp；注册挑战也绑定 stamp，避免先轮换后提交旧挑战。

**这不是完整 PRF 密钥轮换实现，也不是分布式锁。候选仅面向单个 Vaultwarden 进程；不能宣称支持多个副本共享数据库。** 所有其他可能修改用户密钥的路径（密码重置、紧急接管等）仍须在端到端矩阵中验证。真实密码库上线前，这些验收不可跳过。

### P2：注册请求覆盖算法/UV 参数，容易与库保存的状态不一致

位置：`src/api/core/webauthn.rs::post_webauthn_attestation_options`。

原代码将 userVerification 改为 Preferred，同时手写更大的公钥算法列表。客户端请求和库保存的服务端注册策略应一致；不能仅靠改请求字段扩展算法支持。这里只指出策略一致性和兼容性问题，没有声称已经验证出 UV 绕过。

候选：Required UV，保留库生成的算法列表；继续使用精确的 Chrome/Edge 扩展 origin allowlist，而不是放宽 origin 校验。

## 镜像与发布设计

采用稳定版上游 `docker/Dockerfile.alpine`：运行时 Alpine 3.24；Web Vault 资产已有 digest 固定；运行层包含 CA、curl、openssl、tzdata；保留 /data、80、/start.sh 与 /healthcheck.sh。继续编译 sqlite,mysql,postgresql,enable_mimalloc，不为省少量体积削掉数据库兼容性。不采用 scratch/distroless，因为这会额外改变 shell/启动脚本、健康检查与证书/时区行为。

两个原生 runner：ubuntu-24.04 (amd64)、ubuntu-24.04-arm (arm64)。各自构建和测试，通过后合成多架构 manifest。仅可信分支 push 发布候选；pull_request 不登录 registry，不推镜像，不使用 pull_request_target。Action 版本引用上游稳定版工作流中的完整 SHA。正式 latest 通过独立的人工提升工作流指向已验证 digest，不重新构建。

CI 中的迁移测试只使用官方 1.37.3 初始化的合成空库和哨兵文件；它不证明真实密码库内容、附件、组织数据、2FA、恢复流程或 PRF 解密正常。

## 后续维护

保持 main/上游同步路线与部署分支职责清晰。不要将旧 PR 的完整历史强行覆盖新稳定版；本包仅提取固定 PR 的 feature diff。上游发布新的稳定/安全版本后，重新合入、测试，不能让个人 fork 永久停留在 1.37.3。发生源码冲突时，应逐个审查，不能用整体 --theirs 自动解决。

## 一手来源

- PR 元数据/讨论：https://github.com/dani-garcia/vaultwarden/pull/7370
- 固定登录实现：https://github.com/RaphaelRoumezin/vaultwarden/blob/f7f2007f7bc0de870cb2d482467ab36072e3eed5/src/api/identity.rs
- 固定 JWT/刷新实现：https://github.com/RaphaelRoumezin/vaultwarden/blob/f7f2007f7bc0de870cb2d482467ab36072e3eed5/src/auth.rs
- 固定注册实现：https://github.com/RaphaelRoumezin/vaultwarden/blob/f7f2007f7bc0de870cb2d482467ab36072e3eed5/src/api/core/webauthn.rs
- 固定凭据模型：https://github.com/RaphaelRoumezin/vaultwarden/blob/f7f2007f7bc0de870cb2d482467ab36072e3eed5/src/db/models/webauthn_credential.rs
- 固定密钥轮换：https://github.com/RaphaelRoumezin/vaultwarden/blob/f7f2007f7bc0de870cb2d482467ab36072e3eed5/src/api/core/accounts.rs
- 上游稳定发布：https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.3
- 上游 Alpine Dockerfile：https://github.com/dani-garcia/vaultwarden/blob/1.37.3/docker/Dockerfile.alpine
- 上游 release workflow：https://github.com/dani-garcia/vaultwarden/blob/1.37.3/.github/workflows/release.yml
- webauthn-rs 0.5.5 文档（检索时 latest 指向该版本）：https://docs.rs/webauthn-rs/latest/webauthn_rs/struct.Webauthn.html
- Docker 多平台构建官方文档：https://docs.docker.com/build/ci/github-actions/multi-platform/
