# SSL Checker MCP 使用指南

本文介绍如何把 SSL Checker 作为本地 STDIO MCP Server 提供给 Codex 等 Agent 使用。

## 能力与边界

MCP Server 只注册一个只读工具：

```text
check_ssl_certificate({ host, port? })
```

它可以读取管理员明确授权的公网目标证书信息，包括有效期、剩余天数、证书主题、签发机构、指纹和证书链验证结果。

它不会：

- 读取或修改 `config.txt`、手机号和短信供应商配置；
- 发送测试短信或告警短信；
- 修改定时任务、告警阈值或 Web 管理后台；
- 访问本机、内网、链路本地、保留地址或云元数据地址；
- 自动启用未写入 allowlist 的域名或端口。

当前实现只提供本地 STDIO transport，不提供公网 Streamable HTTP 接口。

## 环境要求

- Node.js 18 或更高版本；
- pnpm；
- 能够访问待检测域名的 DNS 和 TLS 端口。

安装依赖：

```bash
pnpm install --frozen-lockfile
```

## 安全配置

MCP 默认拒绝所有目标。至少需要设置 `SSL_MCP_ALLOWED_HOSTS`：

```bash
SSL_MCP_ALLOWED_HOSTS=example.com pnpm mcp
```

可用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SSL_MCP_ALLOWED_HOSTS` | 无 | 必填。逗号分隔的精确域名、公网 IP、`*.example.com` 或显式 `*` |
| `SSL_MCP_ALLOWED_PORTS` | `443` | 允许访问的 TLS 端口，逗号分隔 |
| `SSL_MCP_TIMEOUT_MS` | `5000` | 单次 TLS 连接超时，范围 250–30000 毫秒 |
| `SSL_MCP_MAX_RETRIES` | `2` | 最大尝试次数，范围 1–3 |
| `SSL_MCP_MAX_CONCURRENCY` | `4` | 最大并发调用数，范围 1–16 |
| `SSL_MCP_MAX_REQUESTS_PER_MINUTE` | `30` | 单进程每分钟调用上限，范围 1–300 |

allowlist 示例：

```bash
# 只允许两个精确域名
SSL_MCP_ALLOWED_HOSTS=www.example.com,api.example.com

# 只允许 example.com 的子域名，不包含 example.com 本身
SSL_MCP_ALLOWED_HOSTS='*.example.com'

# 允许任意公网域名；仍然拒绝内网和保留地址
SSL_MCP_ALLOWED_HOSTS='*'

# 额外允许 8443 端口
SSL_MCP_ALLOWED_PORTS=443,8443
```

生产使用建议配置精确域名。只有确实需要检查任意公网目标时才使用 `*`。

## 接入 Codex

Codex 桌面端、CLI 和 IDE 扩展共享 MCP 配置。可以写入全局 `~/.codex/config.toml`，也可以在受信任项目中使用项目级 `.codex/config.toml`。

建议先使用项目级配置，并保持逐次审批：

```toml
[mcp_servers.ssl_checker]
command = "node"
args = ["/absolute/path/to/ssl-checker/mcp/server.js"]
cwd = "/absolute/path/to/ssl-checker"
env = { SSL_MCP_ALLOWED_HOSTS = "www.example.com,api.example.com", SSL_MCP_ALLOWED_PORTS = "443" }
enabled_tools = ["check_ssl_certificate"]
default_tools_approval_mode = "prompt"
startup_timeout_sec = 10
tool_timeout_sec = 15
enabled = true
```

配置要求：

1. 将两处 `/absolute/path/to/ssl-checker` 替换为仓库绝对路径。
2. 将 `SSL_MCP_ALLOWED_HOSTS` 替换为实际授权域名。
3. 保存后重启 Codex 桌面端或 IDE 扩展。
4. 在 Codex 中输入 `/mcp`，确认 `ssl_checker` 已连接且只包含 `check_ssl_certificate`。

Codex 的 MCP 配置项以 [OpenAI 官方 MCP 文档](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) 为准。

## 使用示例

可以让 Agent 执行：

```text
检查 www.example.com 的 SSL 证书，报告到期时间、剩余天数和证书链是否可信。
```

```text
检查 api.example.com:8443；如果证书链不可信，请说明 authorizationError。
```

成功结果包含：

| 字段 | 含义 |
| --- | --- |
| `target` / `port` | 归一化后的目标和端口 |
| `resolvedAddress` | 通过安全检查后实际连接的公网 IP |
| `validFrom` / `validTo` | 证书生效和到期时间 |
| `daysRemaining` | 按完整天数向下取整的剩余天数；负数表示已过期 |
| `expired` | 证书是否已经过期 |
| `chainVerified` | Node.js 是否信任证书链及主机名 |
| `authorizationError` | 证书链或主机名验证失败原因 |
| `issuer` / `subject` | 有界、结构化处理后的签发者和主题信息 |
| `fingerprint256` | SHA-256 证书指纹 |

工具能够取得证书，不代表证书可信。判断安全状态时必须同时检查 `expired` 和 `chainVerified`。

## 内置安全措施

每次调用按以下顺序处理：

1. 校验输入格式、域名 allowlist 和端口 allowlist；
2. 解析全部 DNS 地址；
3. 只要任一结果属于私网、回环、链路本地、保留或其他非公网范围，整体拒绝；
4. 将 TLS 连接固定到已校验的解析 IP，同时保留原始域名作为 SNI；
5. 执行超时、重试、并发和每分钟限流；
6. 返回有界结构化结果，并把证书 subject/issuer 作为不可信外部文本处理；
7. 只向 stderr 写入不含手机号和密钥的审计日志，保持 stdout 为纯 MCP 协议流。

这些检查由服务端强制执行，Agent 提示词不能放宽。

## 测试

运行全部测试：

```bash
pnpm test
```

测试范围包括：

- MCP `initialize`、`tools/list` 和 `tools/call`；
- 未配置 allowlist 时失败关闭；
- 精确域名和子域名通配规则；
- localhost、RFC 1918、链路本地、IPv6 回环和保留地址拒绝；
- 公网与私网混合 DNS 结果拒绝；
- DNS 结果固定连接，防止 DNS rebinding；
- 非授权端口、并发限制和每分钟限流；
- 原有 Web 配置解析和定时任务回归。

检查生产依赖漏洞：

```bash
pnpm audit --prod
```

## 常见错误

| 错误码 | 原因与处理 |
| --- | --- |
| `MCP_HOST_ALLOWLIST_REQUIRED` | 未配置 `SSL_MCP_ALLOWED_HOSTS`；添加明确授权域名后重启 MCP |
| `HOST_NOT_ALLOWED` | 目标不在域名 allowlist 中；检查精确域名和通配范围 |
| `PORT_NOT_ALLOWED` | 端口不在 `SSL_MCP_ALLOWED_PORTS` 中 |
| `BLOCKED_TARGET` | 目标 IP 属于非公网范围，或 DNS 返回结果中混入非公网地址 |
| `DNS_LOOKUP_FAILED` | 域名没有可用 DNS 记录，或当前 DNS 查询失败 |
| `CHECK_TIMEOUT` | TLS 端口不可达或连接超过超时设置 |
| `CONCURRENCY_LIMITED` | 同时执行的检测达到上限 |
| `RATE_LIMITED` | 一分钟内调用次数达到上限 |

如果调用成功但 `chainVerified` 为 `false`，检查 `authorizationError`。常见原因包括证书过期、自签名证书、证书链不完整和证书域名不匹配。

## 运维说明

- Web 服务仍由 `main.js` 启动；MCP 使用独立的 `mcp/server.js` 进程。
- MCP 不读取 Web 服务的 `AUTH_PASSWORD`、短信密钥或登录 Cookie。
- 更新代码后先运行 `pnpm install --frozen-lockfile`、`pnpm test` 和 `pnpm audit --prod`。
- MCP 配置或 allowlist 修改后，需要重启连接它的 Codex 客户端或对应 MCP 进程。
- 不要把真实密钥写入仓库中的 Markdown、示例配置或 `.codex/config.toml`。
