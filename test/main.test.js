process.env.AUTH_USERNAME = process.env.AUTH_USERNAME || 'admin'
process.env.AUTH_PASSWORD = process.env.AUTH_PASSWORD || 'secret'

const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const path = require('node:path')
const test = require('node:test')

const {
  normalizePort,
  normalizeTarget,
  parseConfigLines
} = require('../main')

test('parseConfigLines keeps valid entries and allows missing phones', () => {
  const tasks = parseConfigLines(`
www.example.com|13800138000, 13800138001
api.example.com:8443|13900139000
status.example.com
bad.example.com:abc|13600136000
`)

  assert.deepEqual(tasks, [
    {
      host: 'www.example.com',
      port: 443,
      phoneList: ['13800138000', '13800138001'],
      line: 2
    },
    {
      host: 'api.example.com',
      port: 8443,
      phoneList: ['13900139000'],
      line: 3
    },
    {
      host: 'status.example.com',
      port: 443,
      phoneList: [],
      line: 4
    }
  ])
})

test('normalizePort rejects partial and out-of-range ports', () => {
  assert.equal(normalizePort('443'), 443)
  assert.throws(() => normalizePort('443abc'), /端口格式不正确/)
  assert.throws(() => normalizePort('65536'), /端口超出范围/)
})

test('normalizeTarget accepts URLs and host:port targets', () => {
  assert.deepEqual(normalizeTarget('https://www.example.com:8443/path'), {
    host: 'www.example.com',
    port: 8443
  })
  assert.deepEqual(normalizeTarget('api.example.com:443'), {
    host: 'api.example.com',
    port: 443
  })
})

test('scheduler startup fails fast for invalid cron', () => {
  const result = spawnSync(process.execPath, [
    '-e',
    [
      "process.env.AUTH_USERNAME='admin'",
      "process.env.AUTH_PASSWORD='secret'",
      "process.env.CHECK_CRON='not-a-cron'",
      "require('./main').startScheduler()"
    ].join(';')
  ], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8'
  })

  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /非法 CHECK_CRON/)
})
