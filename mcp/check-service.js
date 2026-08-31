'use strict'

const dns = require('dns').promises
const net = require('net')
const ipaddr = require('ipaddr.js')
const {
  getTLSServerName,
  normalizeHost,
  normalizePort,
  retryRequest
} = require('../lib/ssl-check')

const DEFAULT_ALLOWED_PORTS = [443]
const MAX_DNS_RESULTS = 16

function createPolicyError (message, code) {
  const error = new Error(message)
  error.code = code
  error.retryable = false
  return error
}

function parseIntegerOption (name, raw, fallback, min, max) {
  if (raw === undefined || raw === null || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw createPolicyError(`${name} 必须是 ${min}-${max} 之间的整数`, 'INVALID_MCP_CONFIGURATION')
  }
  return value
}

function parseAllowedPorts (raw) {
  if (raw === undefined || raw === null || raw === '') return DEFAULT_ALLOWED_PORTS
  const ports = String(raw)
    .split(',')
    .map(value => value.trim())
    .filter(Boolean)
    .map(value => normalizePort(value))

  if (ports.length === 0) {
    throw createPolicyError('SSL_MCP_ALLOWED_PORTS 至少需要包含一个端口', 'INVALID_MCP_CONFIGURATION')
  }
  return [...new Set(ports)]
}

function parseAllowedHosts (raw) {
  if (raw === undefined || raw === null || raw === '') return []

  return [...new Set(String(raw)
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean)
    .map(pattern => {
      if (pattern === '*') return pattern
      if (pattern.startsWith('*.')) {
        return `*.${normalizeHost(pattern.slice(2))}`
      }
      return normalizeHost(pattern)
    }))]
}

function matchesAllowedHost (host, patterns) {
  return patterns.some(pattern => {
    if (pattern === '*') return true
    if (!pattern.startsWith('*.')) return host === pattern
    const suffix = pattern.slice(1)
    return host.endsWith(suffix) && host.length > suffix.length
  })
}

function getPublicAddress (address) {
  let parsed
  try {
    parsed = ipaddr.parse(address)
  } catch (_) {
    throw createPolicyError('DNS 返回了无法识别的 IP 地址', 'INVALID_DNS_RESPONSE')
  }

  if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
    parsed = parsed.toIPv4Address()
  }

  if (parsed.range() !== 'unicast') {
    throw createPolicyError('目标解析到非公网地址，已拒绝连接', 'BLOCKED_TARGET')
  }

  return parsed.toString()
}

async function resolvePublicAddresses (host, lookup = dns.lookup) {
  if (net.isIP(host)) return [getPublicAddress(host)]

  let records
  try {
    records = await lookup(host, { all: true, verbatim: true })
  } catch (_) {
    throw createPolicyError('目标域名解析失败', 'DNS_LOOKUP_FAILED')
  }

  if (!Array.isArray(records) || records.length === 0) {
    throw createPolicyError('目标域名没有可用的 DNS 地址', 'DNS_LOOKUP_FAILED')
  }

  if (records.length > MAX_DNS_RESULTS) {
    throw createPolicyError('目标域名返回了过多 DNS 地址', 'DNS_RESPONSE_TOO_LARGE')
  }

  const addresses = records.map(record => getPublicAddress(record.address))
  return [...new Set(addresses)].sort((left, right) => {
    return net.isIP(left) - net.isIP(right)
  })
}

function boundedText (value, maxLength = 512) {
  if (value === undefined || value === null) return null
  return String(value).slice(0, maxLength)
}

function summarizeDistinguishedName (value) {
  if (!value || typeof value !== 'object') return null
  const summary = Object.entries(value)
    .slice(0, 16)
    .map(([key, part]) => `${key}=${Array.isArray(part) ? part.join('/') : part}`)
    .join(', ')
  return boundedText(summary, 1024)
}

function formatResult (host, port, resolvedAddress, result) {
  return {
    target: host,
    port,
    resolvedAddress,
    validFrom: boundedText(result.valid_from),
    validTo: boundedText(result.valid_to),
    daysRemaining: result.days,
    expired: result.expired === true,
    chainVerified: result.chain_authorized === true,
    authorizationError: boundedText(result.authorization_error),
    issuer: summarizeDistinguishedName(result.issuer),
    subject: summarizeDistinguishedName(result.subject),
    fingerprint256: boundedText(result.fingerprint256)
  }
}

function createMcpCheckService (options = {}) {
  const allowedHosts = options.allowedHosts || parseAllowedHosts(process.env.SSL_MCP_ALLOWED_HOSTS)
  const allowedPorts = new Set(options.allowedPorts || parseAllowedPorts(process.env.SSL_MCP_ALLOWED_PORTS))
  const timeout = parseIntegerOption(
    'SSL_MCP_TIMEOUT_MS',
    options.timeout ?? process.env.SSL_MCP_TIMEOUT_MS,
    5000,
    250,
    30000
  )
  const retries = parseIntegerOption(
    'SSL_MCP_MAX_RETRIES',
    options.retries ?? process.env.SSL_MCP_MAX_RETRIES,
    2,
    1,
    3
  )
  const maxConcurrent = parseIntegerOption(
    'SSL_MCP_MAX_CONCURRENCY',
    options.maxConcurrent ?? process.env.SSL_MCP_MAX_CONCURRENCY,
    4,
    1,
    16
  )
  const maxRequestsPerMinute = parseIntegerOption(
    'SSL_MCP_MAX_REQUESTS_PER_MINUTE',
    options.maxRequestsPerMinute ?? process.env.SSL_MCP_MAX_REQUESTS_PER_MINUTE,
    30,
    1,
    300
  )
  const lookup = options.lookup || dns.lookup
  const checkCertificate = options.checkCertificate || retryRequest
  const now = options.now || Date.now
  let activeChecks = 0
  let requestTimestamps = []

  function consumeRateLimit () {
    const cutoff = now() - 60 * 1000
    requestTimestamps = requestTimestamps.filter(timestamp => timestamp > cutoff)
    if (requestTimestamps.length >= maxRequestsPerMinute) {
      throw createPolicyError('MCP 证书检测调用过于频繁，请稍后重试', 'RATE_LIMITED')
    }
    requestTimestamps.push(now())
  }

  async function check (input) {
    consumeRateLimit()

    if (allowedHosts.length === 0) {
      throw createPolicyError(
        'MCP 未配置允许访问的域名。请设置 SSL_MCP_ALLOWED_HOSTS',
        'MCP_HOST_ALLOWLIST_REQUIRED'
      )
    }

    const host = normalizeHost(input.host)
    const port = normalizePort(input.port)

    if (!matchesAllowedHost(host, allowedHosts)) {
      throw createPolicyError('目标不在 MCP 域名允许列表中', 'HOST_NOT_ALLOWED')
    }
    if (!allowedPorts.has(port)) {
      throw createPolicyError('目标端口不在 MCP 端口允许列表中', 'PORT_NOT_ALLOWED')
    }
    if (activeChecks >= maxConcurrent) {
      throw createPolicyError('MCP 证书检测并发数已达上限', 'CONCURRENCY_LIMITED')
    }

    activeChecks += 1
    try {
      const addresses = await resolvePublicAddresses(host, lookup)
      const resolvedAddress = addresses[0]
      const result = await checkCertificate(host, port, {
        connectHost: resolvedAddress,
        servername: getTLSServerName(host),
        timeout,
        retries,
        rejectUnauthorized: false
      })
      return formatResult(host, port, resolvedAddress, result)
    } finally {
      activeChecks -= 1
    }
  }

  return {
    check,
    policy: {
      allowedHosts: [...allowedHosts],
      allowedPorts: [...allowedPorts],
      maxConcurrent,
      maxRequestsPerMinute,
      retries,
      timeout
    }
  }
}

module.exports = {
  createMcpCheckService,
  getPublicAddress,
  matchesAllowedHost,
  parseAllowedHosts,
  parseAllowedPorts,
  resolvePublicAddresses
}
