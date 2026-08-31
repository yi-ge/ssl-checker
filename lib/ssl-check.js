'use strict'

const tls = require('tls')
const net = require('net')
const { domainToASCII } = require('url')

const DAY_MS = 24 * 60 * 60 * 1000

function createCheckError (message, options = {}) {
  const error = new Error(message)
  error.code = options.code || 'CHECK_FAILED'
  error.detail = options.detail
  error.retryable = options.retryable !== false
  return error
}

function normalizePort (value, fallback = 443) {
  if (value === undefined || value === null || value === '') return fallback

  const raw = String(value).trim()
  if (!/^\d+$/.test(raw)) {
    throw createCheckError(`端口格式不正确：${raw}。请输入 1-65535 之间的整数。`, {
      code: 'INVALID_PORT',
      retryable: false
    })
  }

  const port = Number(raw)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw createCheckError(`端口超出范围：${raw}。请输入 1-65535 之间的整数。`, {
      code: 'INVALID_PORT',
      retryable: false
    })
  }
  return port
}

function normalizeHost (value) {
  const raw = String(value || '').trim().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  if (!raw) {
    throw createCheckError('目标地址不能为空。请输入域名或 IP，例如 example.com 或 example.com:443。', {
      code: 'INVALID_HOST',
      retryable: false
    })
  }

  if (net.isIP(raw)) return raw

  const asciiHost = domainToASCII(raw).toLowerCase()
  if (!asciiHost || asciiHost.length > 253) {
    throw createCheckError(`域名格式不正确：${raw}。`, {
      code: 'INVALID_HOST',
      retryable: false
    })
  }

  const labels = asciiHost.split('.')
  const isValidDomain = labels.every(label => (
    label.length > 0 &&
    label.length <= 63 &&
    /^[a-z0-9-]+$/.test(label) &&
    !label.startsWith('-') &&
    !label.endsWith('-')
  ))

  if (!isValidDomain) {
    throw createCheckError(`域名格式不正确：${raw}。请检查是否包含空格、路径或非法字符。`, {
      code: 'INVALID_HOST',
      retryable: false
    })
  }

  return asciiHost
}

function normalizeTarget (value, fallbackPort = 443) {
  const raw = String(value || '').trim()
  if (!raw) {
    throw createCheckError('目标地址不能为空。请输入域名、域名:端口或 HTTPS URL。', {
      code: 'INVALID_TARGET',
      retryable: false
    })
  }

  const bracketMatch = raw.match(/^\[([^\]]+)](?::(.+))?$/)
  if (bracketMatch) {
    return {
      host: normalizeHost(bracketMatch[1]),
      port: normalizePort(bracketMatch[2], fallbackPort)
    }
  }

  if (net.isIP(raw)) {
    return {
      host: normalizeHost(raw),
      port: fallbackPort
    }
  }

  const hasProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
  const hasPathLikePart = /[/?#]/.test(raw)
  if (hasProtocol || hasPathLikePart) {
    let parsed
    try {
      parsed = new URL(hasProtocol ? raw : `https://${raw}`)
    } catch (err) {
      throw createCheckError(`目标地址格式不正确：${raw}。请输入域名、域名:端口或 HTTPS URL。`, {
        code: 'INVALID_TARGET',
        retryable: false,
        detail: err.message
      })
    }

    if (parsed.protocol && parsed.protocol !== 'https:') {
      throw createCheckError(`暂不支持 ${parsed.protocol} 地址。SSL 检测目标应为 HTTPS/TLS 服务。`, {
        code: 'UNSUPPORTED_PROTOCOL',
        retryable: false
      })
    }

    return {
      host: normalizeHost(parsed.hostname),
      port: normalizePort(parsed.port, fallbackPort)
    }
  }

  const colonCount = (raw.match(/:/g) || []).length
  if (colonCount > 1) {
    return {
      host: normalizeHost(raw),
      port: fallbackPort
    }
  }

  if (colonCount === 1) {
    const [host, port] = raw.split(':')
    return {
      host: normalizeHost(host),
      port: normalizePort(port, fallbackPort)
    }
  }

  return {
    host: normalizeHost(raw),
    port: fallbackPort
  }
}

function formatTarget (host, port) {
  const displayHost = net.isIP(host) === 6 ? `[${host}]` : host
  return `${displayHost}:${port}`
}

function getTLSServerName (host) {
  return net.isIP(host) ? undefined : host
}

function normalizeCheckError (err, host, port) {
  if (err && err.code && err.retryable !== undefined) return err

  const detail = err && err.message ? err.message : String(err || 'unknown error')
  const code = err && err.code
  const lowerDetail = detail.toLowerCase()
  const target = formatTarget(host, port)

  if (code === 'ENOTFOUND') {
    return createCheckError(`域名解析失败：${host}。请检查域名是否拼写正确，以及 DNS 记录是否存在。`, {
      code: 'DNS_NOT_FOUND',
      retryable: false,
      detail
    })
  }

  if (code === 'EAI_AGAIN') {
    return createCheckError(`DNS 查询暂时失败：${host}。请稍后重试，或检查服务器 DNS 网络。`, {
      code: 'DNS_TEMPORARY_FAILURE',
      detail
    })
  }

  if (code === 'ECONNREFUSED') {
    return createCheckError(`无法连接 ${target}：目标端口拒绝连接。请确认 HTTPS/TLS 服务正在监听该端口。`, {
      code: 'CONNECTION_REFUSED',
      retryable: false,
      detail
    })
  }

  if (code === 'ETIMEDOUT' || code === 'TIMEOUT') {
    return createCheckError(`连接 ${target} 超时。请确认目标网络可达，或调大 REQUEST_TIMEOUT。`, {
      code: 'CHECK_TIMEOUT',
      detail
    })
  }

  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return createCheckError(`无法访问 ${target}：目标网络不可达。`, {
      code: 'NETWORK_UNREACHABLE',
      detail
    })
  }

  if (code === 'ECONNRESET') {
    return createCheckError(`连接 ${target} 被目标服务器重置。请确认该端口提供 HTTPS/TLS 服务。`, {
      code: 'CONNECTION_RESET',
      detail
    })
  }

  if (
    code === 'EPROTO' ||
    code === 'ERR_SSL_WRONG_VERSION_NUMBER' ||
    lowerDetail.includes('wrong version number') ||
    lowerDetail.includes('unknown protocol') ||
    lowerDetail.includes('packet length too long')
  ) {
    return createCheckError(`目标 ${target} 未返回有效的 TLS 证书。请确认端口不是普通 HTTP、SSH 或其他非 HTTPS 服务。`, {
      code: 'NON_TLS_SERVICE',
      retryable: false,
      detail
    })
  }

  return createCheckError(`检测 ${target} 失败：${detail}`, {
    code: code || 'CHECK_FAILED',
    detail
  })
}

function parseCertificateDate (value, label) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    throw createCheckError(`证书${label}时间无法解析：${value}`, {
      code: 'INVALID_CERT_DATE',
      retryable: false
    })
  }
  return date
}

async function checkerSSLCertificate (host, port = 443, options = {}) {
  const timeout = Number.isInteger(options.timeout) && options.timeout > 0
    ? options.timeout
    : 5000
  const connectHost = options.connectHost || host
  const servername = Object.prototype.hasOwnProperty.call(options, 'servername')
    ? options.servername
    : getTLSServerName(host)

  return new Promise((resolve, reject) => {
    let settled = false
    let socket
    const finish = (fn, arg) => {
      if (settled) return
      settled = true
      fn(arg)
    }

    try {
      socket = tls.connect({
        host: connectHost,
        port,
        servername,
        rejectUnauthorized: options.rejectUnauthorized === true,
        timeout
      }, () => {
        try {
          const certificateInfo = socket.getPeerCertificate()
          if (!certificateInfo || Object.keys(certificateInfo).length === 0) {
            throw createCheckError(`无法获取 ${formatTarget(host, port)} 的证书信息。目标可能未提供 TLS 证书。`, {
              code: 'NO_CERTIFICATE',
              retryable: false
            })
          }

          if (!certificateInfo.valid_from || !certificateInfo.valid_to) {
            throw createCheckError('证书信息不完整：缺少起效时间或到期时间。', {
              code: 'INCOMPLETE_CERTIFICATE',
              retryable: false
            })
          }

          parseCertificateDate(certificateInfo.valid_from, '起效')
          const validTo = parseCertificateDate(certificateInfo.valid_to, '到期')
          const days = Math.floor((validTo.getTime() - Date.now()) / DAY_MS)

          finish(resolve, {
            valid_from: certificateInfo.valid_from,
            valid_to: certificateInfo.valid_to,
            days,
            expired: validTo.getTime() < Date.now(),
            issuer: certificateInfo.issuer,
            subject: certificateInfo.subject,
            fingerprint256: certificateInfo.fingerprint256,
            chain_authorized: socket.authorized === true,
            authorization_error: socket.authorizationError || null
          })
        } catch (err) {
          finish(reject, normalizeCheckError(err, host, port))
        } finally {
          socket.end()
        }
      })
    } catch (err) {
      return finish(reject, normalizeCheckError(err, host, port))
    }

    socket.setTimeout(timeout, () => {
      const err = createCheckError(`连接 ${formatTarget(host, port)} 超时。请确认目标网络可达，或调大 REQUEST_TIMEOUT。`, {
        code: 'CHECK_TIMEOUT',
        detail: `socket timeout after ${timeout}ms`
      })
      socket.destroy()
      finish(reject, err)
    })

    socket.once('error', err => {
      finish(reject, normalizeCheckError(err, host, port))
    })
  })
}

async function retryRequest (host, port = 443, options = {}) {
  let lastErr
  let attemptsUsed = 0
  const retries = Number.isInteger(options.retries) && options.retries > 0
    ? options.retries
    : 1

  for (let attempt = 1; attempt <= retries; attempt++) {
    attemptsUsed = attempt
    try {
      return await checkerSSLCertificate(host, port, options)
    } catch (err) {
      lastErr = normalizeCheckError(err, host, port)
      if (typeof options.onAttemptFailure === 'function') {
        options.onAttemptFailure(lastErr, attempt, retries)
      }
      if (lastErr.retryable === false) break
    }
  }

  if (!lastErr) {
    throw createCheckError(`检测 ${formatTarget(host, port)} 失败：未知错误`, {
      code: 'CHECK_FAILED',
      retryable: false
    })
  }

  if (attemptsUsed > 1 && lastErr.retryable !== false) {
    throw createCheckError(`连续检测 ${attemptsUsed} 次均失败：${lastErr.message}`, {
      code: lastErr.code,
      detail: lastErr.detail,
      retryable: false
    })
  }

  throw lastErr
}

module.exports = {
  checkerSSLCertificate,
  createCheckError,
  formatTarget,
  getTLSServerName,
  normalizeCheckError,
  normalizeHost,
  normalizePort,
  normalizeTarget,
  retryRequest
}
