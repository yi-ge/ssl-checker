require('dotenv').config()

const fs = require('fs')
const path = require('path')
const os = require('os')
const https = require('https')
const crypto = require('crypto')
const fastify = require('fastify')({ logger: true })
const sendSMS = require('./sendSMS')

const schedule = require('node-schedule')

// ===== 配置（全部来自环境变量，无硬编码凭证） =====
const USERNAME = process.env.AUTH_USERNAME
const PASSWORD = process.env.AUTH_PASSWORD
const SESSION_SECRET = process.env.AUTH_SESSION_SECRET || PASSWORD
const SESSION_TTL_SECONDS = process.env.AUTH_SESSION_TTL_SECONDS
  ? parseInt(process.env.AUTH_SESSION_TTL_SECONDS, 10)
  : 24 * 60 * 60
const COOKIE_SECURE = process.env.AUTH_COOKIE_SECURE === 'true'
const PORT = parseInt(process.env.PORT, 10) || 9000
const HOST = process.env.HOST || '0.0.0.0'
const CHECK_CRON = process.env.CHECK_CRON || '0 0 * * *' // 每天 0 点
const WARN_DAYS = parseInt(process.env.WARN_DAYS, 10) || 3 // 剩余天数低于此值时告警
const REQUEST_TIMEOUT = parseInt(process.env.REQUEST_TIMEOUT, 10) || 5000
const MAX_RETRIES = parseInt(process.env.MAX_RETRIES, 10) || 5

const CACHE_FILE = path.join(__dirname, 'ssl_cache.json')
const CONFIG_FILE = path.join(__dirname, 'config.txt')
const INDEX_FILE = path.join(__dirname, 'index.html')
const LOGIN_FILE = path.join(__dirname, 'login.html')
const CACHE_EXPIRATION_SUCCESS = 5 * 60 * 1000 // 成功结果缓存 5 分钟
const CACHE_EXPIRATION_ERROR = 1 * 60 * 1000 // 错误结果缓存 1 分钟
const SESSION_COOKIE_NAME = 'ssl_checker_session'

// ===== 启动前置校验：缺少鉴权凭证则拒绝启动（避免裸奔） =====
if (!USERNAME || !PASSWORD) {
  console.error(
    '[FATAL] 缺少鉴权环境变量 AUTH_USERNAME / AUTH_PASSWORD。\n' +
    '        请创建 .env 文件（可参考 .env.example）或通过环境变量注入后再启动。'
  )
  process.exit(1)
}

// 端口范围校验
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error(`[FATAL] 非法端口号: ${process.env.PORT}`)
  process.exit(1)
}

if (!Number.isInteger(SESSION_TTL_SECONDS) || SESSION_TTL_SECONDS <= 0) {
  console.error(`[FATAL] 非法登录会话有效期: ${process.env.AUTH_SESSION_TTL_SECONDS}`)
  process.exit(1)
}

// ===== 工具函数 =====

// 恒定时间比较，避免凭证与签名比较的时序侧信道泄露
function safeEqual (a, b) {
  const bufA = Buffer.from(String(a))
  const bufB = Buffer.from(String(b))
  if (bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

function parseCookies (req) {
  const header = req.headers.cookie
  if (!header) return {}

  const cookies = {}
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index === -1) continue
    const name = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (!name) continue
    try {
      cookies[name] = decodeURIComponent(value)
    } catch (err) {
      cookies[name] = value
    }
  }
  return cookies
}

function serializeSessionCookie (value, maxAge) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`
  ]
  if (COOKIE_SECURE) parts.push('Secure')
  return parts.join('; ')
}

function signSessionPayload (payload) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url')
}

function createSessionToken () {
  const payload = Buffer.from(JSON.stringify({
    u: USERNAME,
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
    nonce: crypto.randomBytes(16).toString('base64url')
  }), 'utf8').toString('base64url')

  return `${payload}.${signSessionPayload(payload)}`
}

function verifySessionToken (token) {
  if (!token || typeof token !== 'string') return false

  const [payload, signature] = token.split('.')
  if (!payload || !signature || token.split('.').length !== 2) return false

  const expectedSignature = signSessionPayload(payload)
  if (!safeEqual(signature, expectedSignature)) return false

  let data
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
  } catch (err) {
    return false
  }

  return Boolean(
    data &&
    safeEqual(data.u, USERNAME) &&
    Number.isFinite(data.exp) &&
    data.exp > Date.now()
  )
}

function isAuthenticated (req) {
  const cookies = parseCookies(req)
  return verifySessionToken(cookies[SESSION_COOKIE_NAME])
}

function requireAuth (req, reply, done) {
  if (isAuthenticated(req)) return done()

  reply.code(401).send({ code: -401, msg: '未登录或登录已过期' })
}

function sendHtmlFile (reply, filePath, errorMsg) {
  try {
    reply.type('text/html')
    reply.header('Cache-Control', 'no-store')
    return fs.readFileSync(filePath)
  } catch (err) {
    reply.code(500)
    return { code: -1, msg: errorMsg }
  }
}

// 校验并归一化端口
function normalizePort (value, fallback = 443) {
  if (value === undefined || value === null || value === '') return fallback
  const port = parseInt(value, 10)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port: ${value}`)
  }
  return port
}

// 基础的主机名/IP 合法性校验，拒绝明显非法或注入字符
function validateHost (host) {
  if (typeof host !== 'string') return false
  const trimmed = host.trim()
  if (!trimmed || trimmed.length > 253) return false
  // 仅允许域名/IP 允许出现的字符
  return /^[a-zA-Z0-9.\-_:[\]]+$/.test(trimmed)
}

async function checkerSSLCertificate (host, port = 443) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (fn, arg) => {
      if (settled) return
      settled = true
      fn(arg)
    }

    let req
    try {
      req = https.request({
        host,
        port,
        method: 'GET',
        rejectUnauthorized: false,
        agent: new https.Agent({
          maxCachedSessions: 0,
          timeout: REQUEST_TIMEOUT
        }),
        timeout: REQUEST_TIMEOUT
      }, function (res) {
        try {
          const certificateInfo = res.socket.getPeerCertificate()
          // 消费并丢弃响应体，避免 socket 挂起
          res.resume()

          if (!certificateInfo || !certificateInfo.valid_from || !certificateInfo.valid_to) {
            return finish(reject, new Error('No certificate information available'))
          }

          const expires = new Date(certificateInfo.valid_to)
          const now = new Date()
          const timeDiff = expires - now

          if (isNaN(timeDiff)) {
            return finish(reject, new Error('Invalid certificate date'))
          }

          const days = Math.floor(timeDiff / (24 * 60 * 60 * 1000))

          finish(resolve, {
            valid_from: certificateInfo.valid_from,
            valid_to: certificateInfo.valid_to,
            days
          })
        } catch (err) {
          finish(reject, err)
        }
      })
    } catch (err) {
      return finish(reject, err)
    }

    req.on('timeout', () => {
      req.destroy()
      finish(reject, new Error('Request timed out'))
    })

    req.on('error', err => {
      finish(reject, err)
    })

    req.end()
  })
}

async function retryRequest (host, port = 443, retries = MAX_RETRIES) {
  let lastErr
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await checkerSSLCertificate(host, port)
    } catch (err) {
      lastErr = err
      fastify.log.warn(`Attempt ${attempt}/${retries} failed for ${host}:${port} - ${err.message}`)
    }
  }
  throw new Error(`Failed after ${retries} attempts: ${lastErr ? lastErr.message : 'unknown error'}`)
}

// ===== 缓存：内存优先 + 原子落盘，规避并发读改写丢失更新 =====
let cache = loadCacheFromDisk()
let cacheWriteScheduled = false

function loadCacheFromDisk () {
  try {
    const raw = fs.readFileSync(CACHE_FILE, 'utf8')
    const parsed = JSON.parse(raw)
    return (parsed && typeof parsed === 'object') ? parsed : {}
  } catch (err) {
    return {}
  }
}

// 原子写入：先写临时文件再 rename，避免进程中断造成缓存文件损坏
function persistCache () {
  cacheWriteScheduled = false
  const tmp = `${CACHE_FILE}.${process.pid}.${Date.now()}.tmp`
  try {
    fs.writeFileSync(tmp, JSON.stringify(cache), 'utf8')
    fs.renameSync(tmp, CACHE_FILE)
  } catch (err) {
    fastify.log.error(`Failed to write cache: ${err.message}`)
    try { fs.existsSync(tmp) && fs.unlinkSync(tmp) } catch (_) { /* ignore */ }
  }
}

// 合并多次同步修改为一次落盘
function scheduleCachePersist () {
  if (cacheWriteScheduled) return
  cacheWriteScheduled = true
  setImmediate(persistCache)
}

async function cachedCheckerSSLCertificate (host, port = 443) {
  const cacheKey = `${host}:${port}`
  const now = Date.now()

  const entry = cache[cacheKey]
  if (entry) {
    const { timestamp, result, error } = entry
    const isError = !!error
    const expiration = isError ? CACHE_EXPIRATION_ERROR : CACHE_EXPIRATION_SUCCESS

    if (now - timestamp < expiration) {
      fastify.log.info(`Using cached ${isError ? 'error' : 'result'} for ${cacheKey}`)
      if (isError) throw new Error(error)
      return result
    }
    delete cache[cacheKey]
  }

  try {
    const result = await retryRequest(host, port)
    cache[cacheKey] = { timestamp: now, result }
    scheduleCachePersist()
    return result
  } catch (err) {
    cache[cacheKey] = { timestamp: now, error: err.message }
    scheduleCachePersist()
    throw err
  }
}

// ===== HTTP 服务 =====
fastify.get('/login', (req, reply) => {
  if (isAuthenticated(req)) return reply.redirect('/')
  return sendHtmlFile(reply, LOGIN_FILE, 'Failed to read login.html')
})

fastify.post('/api/login', (req, reply) => {
  const username = req.body && req.body.username
  const password = req.body && req.body.password

  // 用户名与密码均使用恒定时间比较；先各自求值再判断，避免短路造成的时序差异
  const userOk = safeEqual(username, USERNAME)
  const passOk = safeEqual(password, PASSWORD)
  if (!userOk || !passOk) {
    reply.code(401)
    return { code: -1, msg: '用户名或密码错误' }
  }

  reply.header('Set-Cookie', serializeSessionCookie(createSessionToken(), SESSION_TTL_SECONDS))
  return { code: 1 }
})

fastify.post('/api/logout', (req, reply) => {
  reply.header('Set-Cookie', serializeSessionCookie('', 0))
  return { code: 1 }
})

fastify.get('/', (req, reply) => {
  if (!isAuthenticated(req)) return reply.redirect('/login')
  return sendHtmlFile(reply, INDEX_FILE, 'Failed to read index.html')
})

fastify.get('/api/config', { preHandler: requireAuth }, (req, reply) => {
  try {
    const configData = fs.readFileSync(CONFIG_FILE, 'utf8')
    return { code: 1, result: configData }
  } catch (err) {
    // 配置文件不存在时返回空内容而非报错，便于首次使用
    if (err.code === 'ENOENT') return { code: 1, result: '' }
    reply.code(500)
    return { code: -1, msg: 'Failed to read config' }
  }
})

fastify.post('/api/config', { preHandler: requireAuth }, (req, reply) => {
  const data = req.body && req.body.data
  if (typeof data !== 'string' || !data.trim()) {
    reply.code(400)
    return { code: -2, msg: '内容为空' }
  }
  try {
    // 原子写入配置文件
    const tmp = `${CONFIG_FILE}.${process.pid}.tmp`
    fs.writeFileSync(tmp, data, 'utf8')
    fs.renameSync(tmp, CONFIG_FILE)
    return { code: 1 }
  } catch (err) {
    reply.code(500)
    return { code: -1, msg: '写入文件异常' }
  }
})

fastify.get('/api/checkerSSLCertificate', { preHandler: requireAuth }, async (req, reply) => {
  const host = req.query.host
  if (!host || !validateHost(host)) {
    reply.code(400)
    return { code: -2, msg: 'Host is required or invalid' }
  }

  let port
  try {
    port = normalizePort(req.query.port)
  } catch (err) {
    reply.code(400)
    return { code: -2, msg: err.message }
  }

  try {
    const result = await cachedCheckerSSLCertificate(host.trim(), port)
    return { code: 1, msg: 'ok', result }
  } catch (err) {
    return { code: -1, msg: err.message }
  }
})

fastify.post('/api/testSMS', { preHandler: requireAuth }, async (req, reply) => {
  const phones = req.body && req.body.phones
  if (!Array.isArray(phones) || phones.length === 0) {
    reply.code(400)
    return { code: -2, msg: '手机号不能为空' }
  }
  try {
    const result = await sendSMS(phones, { host: 'test', day: 0 })
    return { code: 1, result }
  } catch (err) {
    return { code: -1, msg: err.message }
  }
})

// ===== 定时巡检 =====
function parseConfigLines (raw) {
  const tasks = []
  for (const lineRaw of raw.split('\n')) {
    let line = lineRaw.trim()
    if (line.includes('//')) line = line.split('//')[0].trim()
    if (!line) continue

    const [hostStr, phones] = line.split('|')
    if (!hostStr || !phones) {
      fastify.log.warn(`Invalid line in config.txt: ${lineRaw}`)
      continue
    }

    const phoneList = phones.split(',').map(p => p.trim()).filter(Boolean)
    const [host, port] = hostStr.trim().split(':')
    if (!host || phoneList.length === 0) {
      fastify.log.warn(`Invalid line in config.txt: ${lineRaw}`)
      continue
    }
    tasks.push({ host: host.trim(), port, phoneList })
  }
  return tasks
}

async function runScheduledCheck () {
  let raw
  try {
    raw = fs.readFileSync(CONFIG_FILE, 'utf8')
  } catch (err) {
    fastify.log.error(`Failed to read config.txt: ${err.message}`)
    return
  }

  const entries = parseConfigLines(raw)
  await Promise.allSettled(entries.map(async ({ host, port, phoneList }) => {
    const usePort = port ? parseInt(port, 10) : 443
    try {
      const { days } = await cachedCheckerSSLCertificate(host, usePort)
      if (days < WARN_DAYS) {
        fastify.log.warn(`SSL certificate for ${host} expires in ${days} days`)
        try {
          const smsResult = await sendSMS(phoneList, {
            host: host.replace(/\./g, '-').substring(0, 15),
            day: days
          })
          fastify.log.info(`SMS sent for ${host}: ${JSON.stringify(smsResult)}`)
        } catch (smsErr) {
          fastify.log.error(`Failed to send SMS for ${host}: ${smsErr.message}`)
        }
      }
    } catch (err) {
      fastify.log.error(`Failed to check SSL for ${host}:${usePort} - ${err.message}`)
    }
  }))
}

const scheduledJob = schedule.scheduleJob(CHECK_CRON, runScheduledCheck)

// ===== 启动与优雅退出 =====
const start = async () => {
  try {
    await fastify.listen({ port: PORT, host: HOST })
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

let shuttingDown = false
async function shutdown (signal) {
  if (shuttingDown) return
  shuttingDown = true
  fastify.log.info(`Received ${signal}, shutting down gracefully...`)
  try {
    if (scheduledJob) scheduledJob.cancel()
    if (cacheWriteScheduled) persistCache() // 落盘待写缓存
    await fastify.close()
  } catch (err) {
    fastify.log.error(`Error during shutdown: ${err.message}`)
  } finally {
    process.exit(0)
  }
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('unhandledRejection', (reason) => {
  fastify.log.error(`Unhandled rejection: ${reason}`)
})

start()
