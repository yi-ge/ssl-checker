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
3. 通过 HTML + JS 实现通知列表的可视化维护，通过 Basic Auth 进行身份认证。需要一个 Web 服务器实现服务器端向客户端输出 HTML 数据和 HTTP API，选择方便快捷的`fastify`及其插件`fastify-basic-auth`。
4. 通过 Node.js 的[https](https://nodejs.org/api/https.html)相关 API 实现对证书信息的获取。

## 实现

安装可能用到的依赖：

```bash
yarn add node-schedule axios fastify fastify-basic-auth
```

获取某个域名的 SSL 证书信息：

```javascript
const https = require('https')

const req = https.request(
  {
    host: 'www.wyr.me',
    port: 443,
    method: 'GET',
    rejectUnauthorized: false,
    agent: new https.Agent({
      maxCachedSessions: 0,
    }),
  },
  (res) => {
    console.log(res.connection.getPeerCertificate())
  }
)

req.end()
```

其中，`agent: new https.Agent({ maxCachedSessions: 0 })`是必须的，否则第二次请求的时候将无法获得证书信息。

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
