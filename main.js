require('dotenv').config()

const fs = require('fs')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const fastify = require('fastify')({ logger: true })
const sendSMS = require('./sendSMS')
const {
  createCheckError,
  formatTarget,
  normalizePort,
  normalizeTarget,
  retryRequest: retrySslRequest
} = require('./lib/ssl-check')

const schedule = require('node-schedule')

// ===== 配置（全部来自环境变量，无硬编码凭证） =====
const USERNAME = process.env.AUTH_USERNAME
const PASSWORD = process.env.AUTH_PASSWORD
const SESSION_SECRET = process.env.AUTH_SESSION_SECRET || PASSWORD
const SESSION_TTL_SECONDS = parseIntegerEnv('AUTH_SESSION_TTL_SECONDS', 24 * 60 * 60, 1)
const COOKIE_SECURE = process.env.AUTH_COOKIE_SECURE === 'true'
const PORT = parseIntegerEnv('PORT', 9000, 1, 65535)
const HOST = process.env.HOST || '0.0.0.0'
const CHECK_CRON = process.env.CHECK_CRON || '0 0 * * *' // 每天 0 点
const WARN_DAYS = parseIntegerEnv('WARN_DAYS', 3, 0) // 剩余天数低于此值时告警
const REQUEST_TIMEOUT = parseIntegerEnv('REQUEST_TIMEOUT', 5000, 1)
const MAX_RETRIES = parseIntegerEnv('MAX_RETRIES', 5, 1)

const CACHE_FILE = path.join(__dirname, 'ssl_cache.json')
const CONFIG_FILE = path.join(__dirname, 'config.txt')
const SMS_CONFIG_FILE = path.join(__dirname, 'sms_config.json')
const INDEX_FILE = path.join(__dirname, 'index.html')
const LOGIN_FILE = path.join(__dirname, 'login.html')
const CACHE_EXPIRATION_SUCCESS = 5 * 60 * 1000 // 成功结果缓存 5 分钟
const CACHE_EXPIRATION_ERROR = 1 * 60 * 1000 // 错误结果缓存 1 分钟
const SESSION_COOKIE_NAME = 'ssl_checker_session'
const SMS_SECRET_PLACEHOLDER = '********'
const SMS_CONFIG_FIELDS = [
  'enabled',
  'provider',
  'baseURL',
  'endpoint',
  'templateId',
  'appid',
  'appkey',
  'type',
  'auth',
  'appUUID',
  'timeout'
]
const SMS_SECRET_FIELDS = ['appkey', 'auth']

// ===== 启动前置校验：缺少鉴权凭证则拒绝启动（避免裸奔） =====
if (!USERNAME || !PASSWORD) {
  failFast(
    '缺少鉴权环境变量 AUTH_USERNAME / AUTH_PASSWORD。\n' +
    '        请创建 .env 文件（可参考 .env.example）或通过环境变量注入后再启动。'
  )
}

// ===== 工具函数 =====

function failFast (message) {
  console.error(`[FATAL] ${message}`)
  process.exit(1)
}

function parseIntegerEnv (name, fallback, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER) {
  const raw = process.env[name]
  if (raw === undefined || raw === '') return fallback

  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    failFast(`非法环境变量 ${name}: ${raw}`)
  }
  return value
}

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

function stripInlineComment (line) {
  const trimmed = String(line || '').trim()
  if (trimmed.startsWith('//')) return ''

  const match = trimmed.match(/\s+\/\//)
  if (!match) return trimmed
  return trimmed.slice(0, match.index).trim()
}

function stripPhoneComment (value) {
  const text = String(value || '').trim()
  const commentIndex = text.indexOf('//')
  return commentIndex === -1 ? text : text.slice(0, commentIndex).trim()
}

function hasOwn (target, key) {
  return Object.prototype.hasOwnProperty.call(target, key)
}

function readSmsConfigFromDisk () {
  try {
    const raw = fs.readFileSync(SMS_CONFIG_FILE, 'utf8')
    const parsed = JSON.parse(raw)
    return (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : {}
  } catch (err) {
    return {}
  }
}

function mergeSmsConfig (base, override) {
  const merged = { ...base }
  for (const field of SMS_CONFIG_FIELDS) {
    if (!hasOwn(override, field)) continue
    const value = override[field]
    if (SMS_SECRET_FIELDS.includes(field) && (!value || value === SMS_SECRET_PLACEHOLDER)) continue
    merged[field] = value
  }
  return sendSMS.normalizeConfig(merged)
}

function getEffectiveSmsConfig () {
  return mergeSmsConfig(sendSMS.getEnvConfig(), readSmsConfigFromDisk())
}

function validateSmsConfigForSave (config) {
  if (config.baseURL) {
    let parsedURL
    try {
      parsedURL = new URL(config.baseURL)
    } catch (err) {
      throw new Error('短信服务 Base URL 必须是有效的 HTTP/HTTPS 地址')
    }

    if (!['http:', 'https:'].includes(parsedURL.protocol)) {
      throw new Error('短信服务 Base URL 仅支持 HTTP/HTTPS')
    }
  }

  if (config.endpoint && !config.endpoint.startsWith('/')) {
    throw new Error('短信服务接口路径必须以 / 开头')
  }

  if (config.provider && !/^[a-zA-Z0-9_-]+$/.test(config.provider)) {
    throw new Error('供应商标识只能包含字母、数字、下划线或中划线')
  }

  if (config.type && !/^[a-zA-Z0-9_-]+$/.test(config.type)) {
    throw new Error('短信类型只能包含字母、数字、下划线或中划线')
  }

  if (config.appUUID && !/^[a-zA-Z0-9_.-]+$/.test(config.appUUID)) {
    throw new Error('应用标识只能包含字母、数字、点、下划线或中划线')
  }

  if (!Number.isInteger(config.timeout) || config.timeout <= 0) {
    throw new Error('短信接口超时必须是正整数')
  }
}

function normalizeSmsConfigForSave (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('短信配置格式错误')
  }

  const current = readSmsConfigFromDisk()
  const next = {}
  for (const field of SMS_CONFIG_FIELDS) {
    if (hasOwn(current, field)) next[field] = current[field]
  }

  if (hasOwn(input, 'enabled')) {
    next.enabled = !(input.enabled === false || input.enabled === 'false' || input.enabled === '0')
  }

  for (const field of ['provider', 'baseURL', 'endpoint', 'templateId', 'appid', 'type', 'appUUID']) {
    if (!hasOwn(input, field)) continue
    next[field] = typeof input[field] === 'string' ? input[field].trim() : ''
  }

  for (const field of SMS_SECRET_FIELDS) {
    if (!hasOwn(input, field)) continue
    const value = typeof input[field] === 'string' ? input[field].trim() : ''
    if (value && value !== SMS_SECRET_PLACEHOLDER) next[field] = value
  }

  if (hasOwn(input, 'timeout')) {
    const timeout = parseInt(input.timeout, 10)
    if (!Number.isInteger(timeout) || timeout <= 0) {
      throw new Error('短信接口超时必须是正整数')
    }
    next.timeout = timeout
  }

  const normalized = sendSMS.normalizeConfig(next)
  validateSmsConfigForSave(normalized)

  for (const field of SMS_SECRET_FIELDS) {
    if (!normalized[field]) delete normalized[field]
  }
  return normalized
}

function writeSmsConfigToDisk (config) {
  const tmp = `${SMS_CONFIG_FILE}.${process.pid}.tmp`
  fs.writeFileSync(tmp, JSON.stringify(config, null, 2) + os.EOL, {
    encoding: 'utf8',
    mode: 0o600
  })
  fs.renameSync(tmp, SMS_CONFIG_FILE)
}

function getSmsConfigStatus () {
  const config = getEffectiveSmsConfig()
  return {
    configured: sendSMS.hasRequiredConfig(config),
    missingFields: sendSMS.getMissingFields(config),
    config: {
      ...config,
      appkey: config.appkey ? SMS_SECRET_PLACEHOLDER : '',
      auth: config.auth ? SMS_SECRET_PLACEHOLDER : ''
    }
  }
}

async function retryRequest (host, port = 443, retries = MAX_RETRIES) {
  return retrySslRequest(host, port, {
    retries,
    timeout: REQUEST_TIMEOUT,
    onAttemptFailure: (err, attempt, totalRetries) => {
      const detail = err.detail ? ` (${err.detail})` : ''
      fastify.log.warn(`Attempt ${attempt}/${totalRetries} failed for ${formatTarget(host, port)} - ${err.message}${detail}`)
    }
  })
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
  const cacheKey = formatTarget(host, port)
  const now = Date.now()

  const entry = cache[cacheKey]
  if (entry) {
    const { timestamp, result, error } = entry
    const isError = !!error
    const expiration = isError ? CACHE_EXPIRATION_ERROR : CACHE_EXPIRATION_SUCCESS

    if (now - timestamp < expiration) {
      fastify.log.info(`Using cached ${isError ? 'error' : 'result'} for ${cacheKey}`)
      if (isError) {
        if (typeof error === 'string') {
          throw createCheckError(error, {
            code: 'CACHED_CHECK_FAILED',
            retryable: false
          })
        }

        throw createCheckError(error.message || '检测失败', {
          code: error.code || 'CACHED_CHECK_FAILED',
          detail: error.detail,
          retryable: false
        })
      }
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
    cache[cacheKey] = {
      timestamp: now,
      error: {
        message: err.message,
        code: err.code,
        detail: err.detail
      }
    }
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

fastify.get('/api/sms-config', { preHandler: requireAuth }, (req, reply) => {
  return { code: 1, result: getSmsConfigStatus() }
})

fastify.post('/api/sms-config', { preHandler: requireAuth }, (req, reply) => {
  const input = req.body && req.body.config
  let config
  try {
    config = normalizeSmsConfigForSave(input)
  } catch (err) {
    reply.code(400)
    return { code: -2, msg: err.message }
  }

  try {
    writeSmsConfigToDisk(config)
    return { code: 1, result: getSmsConfigStatus() }
  } catch (err) {
    reply.code(500)
    return { code: -1, msg: '写入短信配置异常' }
  }
})

fastify.get('/api/checkerSSLCertificate', { preHandler: requireAuth }, async (req, reply) => {
  let target
  try {
    target = normalizeTarget(req.query.host)
    if (req.query.port !== undefined && req.query.port !== '') {
      target.port = normalizePort(req.query.port)
    }
  } catch (err) {
    reply.code(400)
    return {
      code: -2,
      msg: err.message,
      error: {
        code: err.code,
        detail: err.detail
      }
    }
  }

  try {
    const result = await cachedCheckerSSLCertificate(target.host, target.port)
    return { code: 1, msg: 'ok', result, target }
  } catch (err) {
    return {
      code: -1,
      msg: err.message,
      error: {
        code: err.code,
        detail: err.detail
      }
    }
  }
})

fastify.post('/api/testSMS', { preHandler: requireAuth }, async (req, reply) => {
  const phones = req.body && req.body.phones
  if (!Array.isArray(phones) || phones.length === 0) {
    reply.code(400)
    return { code: -2, msg: '手机号不能为空' }
  }
  try {
    const result = await sendSMS(phones, { host: 'test', day: 0 }, { config: getEffectiveSmsConfig() })
    return { code: 1, result }
  } catch (err) {
    return { code: -1, msg: err.message }
  }
})

// ===== 定时巡检 =====
function parseConfigLines (raw) {
  const tasks = []
  raw.split(/\r?\n/).forEach((lineRaw, index) => {
    const line = stripInlineComment(lineRaw)
    if (!line) return

    const separatorIndex = line.indexOf('|')
    const targetText = separatorIndex === -1 ? line : line.slice(0, separatorIndex).trim()
    const phoneText = separatorIndex === -1 ? '' : stripPhoneComment(line.slice(separatorIndex + 1))

    let target
    try {
      target = normalizeTarget(targetText)
    } catch (err) {
      fastify.log.warn(`Invalid config line ${index + 1}: ${err.message} Raw: ${lineRaw}`)
      return
    }

    const phoneList = phoneText
      ? phoneText.split(',').map(p => p.trim()).filter(Boolean)
      : []
    tasks.push({ ...target, phoneList, line: index + 1 })
  })
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
  const smsConfig = getEffectiveSmsConfig()
  await Promise.allSettled(entries.map(async ({ host, port, phoneList }) => {
    const target = formatTarget(host, port)
    try {
      const { days } = await cachedCheckerSSLCertificate(host, port)
      if (days < WARN_DAYS) {
        fastify.log.warn(`SSL certificate for ${target} expires in ${days} days`)
        if (phoneList.length === 0) {
          fastify.log.warn(`No phone numbers configured for ${target}; skip SMS alert`)
          return
        }

        try {
          const smsResult = await sendSMS(phoneList, {
            host: host.replace(/\./g, '-').substring(0, 15),
            day: days
          }, { config: smsConfig })
          fastify.log.info(`SMS sent for ${target}: ${JSON.stringify(smsResult)}`)
        } catch (smsErr) {
          fastify.log.error(`Failed to send SMS for ${target}: ${smsErr.message}`)
        }
      }
    } catch (err) {
      fastify.log.error(`Failed to check SSL for ${target} - ${err.message}`)
    }
  }))
}

let scheduledCheckRunning = false

async function runScheduledCheckSafely () {
  if (scheduledCheckRunning) {
    fastify.log.warn('Previous scheduled SSL check is still running, skipping this run')
    return
  }

  scheduledCheckRunning = true
  try {
    await runScheduledCheck()
  } catch (err) {
    fastify.log.error(`Scheduled SSL check failed unexpectedly: ${err.message}`)
  } finally {
    scheduledCheckRunning = false
  }
}

let scheduledJob = null

function startScheduler () {
  if (scheduledJob) return scheduledJob

  try {
    scheduledJob = schedule.scheduleJob(CHECK_CRON, runScheduledCheckSafely)
  } catch (err) {
    failFast(`非法 CHECK_CRON: ${CHECK_CRON} (${err.message})`)
  }

  if (!scheduledJob) {
    failFast(`非法 CHECK_CRON: ${CHECK_CRON}`)
  }

  return scheduledJob
}

// ===== 启动与优雅退出 =====
const start = async () => {
  try {
    startScheduler()
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

if (require.main === module) {
  start()
}

module.exports = {
  normalizePort,
  normalizeTarget,
  parseConfigLines,
  runScheduledCheck,
  runScheduledCheckSafely,
  startScheduler
}
