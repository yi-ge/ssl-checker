'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')
const {
  createMcpCheckService,
  matchesAllowedHost,
  parseAllowedHosts,
  resolvePublicAddresses
} = require('../mcp/check-service')

const certificateFixture = {
  valid_from: 'Jan  1 00:00:00 2026 GMT',
  valid_to: 'Jan  1 00:00:00 2027 GMT',
  days: 120,
  expired: false,
  issuer: { CN: 'Example Test CA' },
  subject: { CN: 'example.com' },
  fingerprint256: 'AA:BB',
  chain_authorized: true,
  authorization_error: null
}

function publicLookup (host, options) {
  assert.equal(host, 'example.com')
  assert.deepEqual(options, { all: true, verbatim: true })
  return Promise.resolve([{ address: '93.184.216.34', family: 4 }])
}

test('host allowlist supports exact hosts and explicit subdomain wildcards', () => {
  const patterns = parseAllowedHosts('example.com,*.example.org')
  assert.equal(matchesAllowedHost('example.com', patterns), true)
  assert.equal(matchesAllowedHost('api.example.org', patterns), true)
  assert.equal(matchesAllowedHost('example.org', patterns), false)
  assert.equal(matchesAllowedHost('example.com.evil.test', patterns), false)
})

test('public resolver rejects direct private and reserved IP addresses', async () => {
  await assert.rejects(resolvePublicAddresses('127.0.0.1'), error => error.code === 'BLOCKED_TARGET')
  await assert.rejects(resolvePublicAddresses('169.254.169.254'), error => error.code === 'BLOCKED_TARGET')
  await assert.rejects(resolvePublicAddresses('10.0.0.1'), error => error.code === 'BLOCKED_TARGET')
  await assert.rejects(resolvePublicAddresses('::1'), error => error.code === 'BLOCKED_TARGET')
  await assert.rejects(resolvePublicAddresses('2001:db8::1'), error => error.code === 'BLOCKED_TARGET')
})

test('public resolver rejects a DNS response containing any private address', async () => {
  const lookup = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '127.0.0.1', family: 4 }
  ]

  await assert.rejects(
    resolvePublicAddresses('example.com', lookup),
    error => error.code === 'BLOCKED_TARGET'
  )
})

test('MCP check pins the TLS connection to the validated DNS address', async () => {
  let received
  const service = createMcpCheckService({
    allowedHosts: ['example.com'],
    allowedPorts: [443],
    lookup: publicLookup,
    checkCertificate: async (host, port, options) => {
      received = { host, port, options }
      return certificateFixture
    }
  })

  const result = await service.check({ host: 'example.com', port: 443 })
  assert.equal(received.host, 'example.com')
  assert.equal(received.port, 443)
  assert.equal(received.options.connectHost, '93.184.216.34')
  assert.equal(received.options.servername, 'example.com')
  assert.equal(received.options.rejectUnauthorized, false)
  assert.equal(result.resolvedAddress, '93.184.216.34')
  assert.equal(result.chainVerified, true)
})

test('MCP check fails closed without a host allowlist', async () => {
  const service = createMcpCheckService({
    allowedHosts: [],
    checkCertificate: async () => certificateFixture
  })
  await assert.rejects(
    service.check({ host: 'example.com' }),
    error => error.code === 'MCP_HOST_ALLOWLIST_REQUIRED'
  )
})

test('MCP check rejects non-allowlisted hosts and ports before connecting', async () => {
  let calls = 0
  const service = createMcpCheckService({
    allowedHosts: ['example.com'],
    allowedPorts: [443],
    lookup: publicLookup,
    checkCertificate: async () => {
      calls += 1
      return certificateFixture
    }
  })

  await assert.rejects(
    service.check({ host: 'other.example', port: 443 }),
    error => error.code === 'HOST_NOT_ALLOWED'
  )
  await assert.rejects(
    service.check({ host: 'example.com', port: 8443 }),
    error => error.code === 'PORT_NOT_ALLOWED'
  )
  assert.equal(calls, 0)
})

test('MCP check enforces concurrency and per-minute rate limits', async () => {
  let releaseFirst
  const firstCheck = new Promise(resolve => { releaseFirst = resolve })
  let calls = 0
  const service = createMcpCheckService({
    allowedHosts: ['example.com'],
    allowedPorts: [443],
    lookup: publicLookup,
    maxConcurrent: 1,
    maxRequestsPerMinute: 2,
    checkCertificate: async () => {
      calls += 1
      if (calls === 1) await firstCheck
      return certificateFixture
    }
  })

  const running = service.check({ host: 'example.com' })
  await new Promise(resolve => setImmediate(resolve))
  await assert.rejects(
    service.check({ host: 'example.com' }),
    error => error.code === 'CONCURRENCY_LIMITED'
  )
  await assert.rejects(
    service.check({ host: 'example.com' }),
    error => error.code === 'RATE_LIMITED'
  )
  releaseFirst()
  await running
})
