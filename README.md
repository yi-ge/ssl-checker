# SSL 证书过期监测

部分程序配置了[免费 SSL 证书更新程序](https://www.wyr.me/post/616)，但是更新程序更新证书失败并不会通知到管理员，可能导致业务异常。通过针对域名的 SSL 证书过期监测小程序，作为二道防火墙，避免事故发生。

## 需求

1. 以 cron 风格定时监测 SSL 证书过期和可用状态。
2. 提前 2 天发送短信通知管理员（需要支持多手机号）。
3. 可以在线维护通知列表（`域名`+`手机号`）。
4. 程序要尽量简单，尽量降低后续维护成本。
5. 开发要尽可能快。

## 分析

1. 以简单的 js 脚本在 node.js 平台实现程序，利用现成的[node-schedule](https://github.com/node-schedule/node-schedule)库实现定时任务。
2. 通过`axios`调用第三方接口实现短信发送，参数为`手机号数组`+`域名`+`即将过期天数/-过期天数`。
3. 通过 HTML + JS 实现通知列表的可视化维护，通过登录页和签名会话 Cookie 进行身份认证。需要一个 Web 服务器实现服务器端向客户端输出 HTML 数据和 HTTP API，选择方便快捷的`fastify`。
4. 通过 Node.js 的[tls](https://nodejs.org/api/tls.html)相关 API 直接进行 TLS 握手并获取证书信息。

## 实现

安装可能用到的依赖：

```bash
yarn add node-schedule axios fastify
```

获取某个域名的 SSL 证书信息：

```javascript
const tls = require('tls')

const socket = tls.connect(
  {
    host: 'www.wyr.me',
    port: 443,
    servername: 'www.wyr.me',
    rejectUnauthorized: false,
  },
  () => {
    console.log(socket.getPeerCertificate())
    socket.end()
  },
)
```

直接通过 TLS 握手获取证书，不依赖目标站点是否能正常返回 HTTP 响应，也能更准确地区分 DNS 解析失败、连接超时、端口拒绝连接、非 TLS 服务等错误。

短信模板：

```text
【SSL监控】@var(host)的SSL证书@(day)天过期（负数为已过期）。请及时处理！
```

**其余代码实现参阅：**
[https://github.com/yi-ge/ssl-checker/blob/main/main.js](https://github.com/yi-ge/ssl-checker/blob/main/main.js)

总共不到两百行，代码的意图很明显了，不再赘述。

## 可视化配置编辑界面

![sslchecker.png](https://cdn.wyr.me/post-files/2022-02-08/1644290856827/image.png)

2022年02月08日更新：支持添加注释，优化空格检测，支持不填写手机号。

## 配置与部署

自 `v1.1.0` 起，所有凭证与可调参数均通过**环境变量**配置，仓库中不再保留任何硬编码密钥。

1. 复制示例配置并按需填写：

```bash
cp .env.example .env
# 编辑 .env，至少填写 AUTH_USERNAME / AUTH_PASSWORD（强口令）
```

2. 安装依赖并启动：

```bash
pnpm install   # 或 npm install
node main.js   # 或 pnpm start
```

> 未设置 `AUTH_USERNAME` / `AUTH_PASSWORD` 时程序会**拒绝启动**，避免裸奔。

### 环境变量一览

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `AUTH_USERNAME` | ✅ | — | 登录用户名 |
| `AUTH_PASSWORD` | ✅ | — | 登录密码（请用强口令） |
| `AUTH_SESSION_SECRET` | | `AUTH_PASSWORD` | 登录会话签名密钥 |
| `AUTH_SESSION_TTL_SECONDS` | | `86400` | 登录会话有效期（秒） |
| `AUTH_COOKIE_SECURE` | | `false` | 是否为登录 Cookie 添加 `Secure` 标记；HTTPS 部署建议开启 |
| `PORT` | | `9000` | 监听端口 |
| `HOST` | | `0.0.0.0` | 监听地址（建议生产仅监听 `127.0.0.1` + 反向代理） |
| `CHECK_CRON` | | `0 0 * * *` | 定时巡检 cron 表达式 |
| `WARN_DAYS` | | `3` | 剩余天数低于此值时短信告警 |
| `REQUEST_TIMEOUT` | | `5000` | 单次 TLS 请求超时（毫秒） |
| `MAX_RETRIES` | | `5` | 单域名最大重试次数 |
| `SMS_BASE_URL` `SMS_TEMPLATE_ID` `SMS_APPID` `SMS_APPKEY` `SMS_AUTH` `SMS_TYPE` `SMS_TIMEOUT` | | — | 短信服务配置；不配置则仅记录日志、不发短信 |

使用 PM2 部署时，`.env` 会被自动加载（`dotenv`），亦可在 `ecosystem.config.js` 的 `env` 字段中注入。

## 开源仓库地址

[https://github.com/yi-ge/ssl-checker](https://github.com/yi-ge/ssl-checker)

在线 Demo（运行于腾讯云函数，用户名密码均为`admin`）：[https://service-pnlsi3d9-1251007030.cd.apigw.tencentcs.com](https://service-pnlsi3d9-1251007030.cd.apigw.tencentcs.com)

## 其他说明

查询资料、编写此博文及思考耗时约 25 分钟，代码编写及测试约 65 分钟。一共耗时约个半小时。

请注意，不建议直接运行于腾讯云函数，实例配置数据可能因销毁而丢失，除非使用持久化存储配置信息。腾讯云函数不支持非`/tmp`目录下的`写入`操作，因此需要先复制文件并对应修改相关文件操作：

```javascript
if (!fs.existsSync('/tmp/config.txt')) {
  fs.copyFileSync(path.join(__dirname, 'config.txt'), '/tmp/config.txt')
  fs.copyFileSync(path.join(__dirname, 'index.html'), '/tmp/index.html')
}

...

// example
fastify.get('/api/config', (req, reply) => {
  return {
    code: 1,
    result: fs.readFileSync('/tmp/config.txt', 'utf8'),
  }
})
```

相比之下普通服务器部署会省事一些。

## 文档
- [ARCHITECTURE.md](ARCHITECTURE.md)

## 相关博文

SSL 证书过期监测，博文：[https://www.wyr.me/post/691](https://www.wyr.me/post/691)
