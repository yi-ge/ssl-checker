# 架构概述

本文档介绍 **ssl-checker** 的技术结构，该项目会监控配置文件中的域名 SSL 证书到期时间，并在必要时通过短信提醒管理员。

## 组件

### Node.js 后端 (`main.js`)
- 使用 **Fastify** 作为 HTTP 服务器
- 提供 Basic Auth 保护的接口：
  - `/` – 返回 `index.html`
  - `/api/config` – 获取或更新 `config.txt` 内容
  - `/api/checkerSSLCertificate` – 查询指定域名和端口的证书信息
- 使用 **node-schedule** 每日检查 `config.txt` 中的域名
- 通过 Node 的 `https` 模块获取证书并缓存到 `ssl_cache.json`
- 当证书距离过期不足三天时，触发 `sendSMS()` 发送提醒

### 短信发送模块 (`sendSMS.js`)
- 基于 **axios** 调用外部短信服务
- 模板和认证信息可通过配置调整（仓库中仅提供占位符）

### 配置文件 (`config.txt`)
- 文本格式，每行 `域名[:端口]|手机号1,手机号2`
- 支持使用 `//` 添加注释

### 前端页面 (`index.html`)
- 使用 Basic Auth 保护的简易 HTML 页面
- 可在文本框中编辑 `config.txt`，并查看当前证书状态表格
- 通过 `fetch` 调用后台接口

## 运行流程
1. 用户通过 Basic Auth 访问 `index.html`
2. 前端调用 `/api/config` 读取配置并填充表格
3. 每个域名通过 `/api/checkerSSLCertificate` 获取证书有效信息
4. 后端定时任务每日检查所有域名，在证书即将过期时发送短信通知

## 依赖
- Node.js
- `fastify`、`@fastify/basic-auth`
- `node-schedule`
- `axios`

应用既可以部署在常规服务器，也可以部署在支持持久化存储的无服务器环境。
