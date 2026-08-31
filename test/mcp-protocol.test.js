'use strict'

const assert = require('node:assert/strict')
const path = require('node:path')
const test = require('node:test')
const { Client } = require('@modelcontextprotocol/sdk/client/index.js')
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js')

test('STDIO MCP supports initialize, tools/list, and a policy-blocked tools/call', { timeout: 15000 }, async () => {
  const root = path.join(__dirname, '..')
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(root, 'mcp/server.js')],
    cwd: root,
    env: {
      SSL_MCP_ALLOWED_HOSTS: '*',
      SSL_MCP_ALLOWED_PORTS: '443'
    },
    stderr: 'pipe'
  })
  const client = new Client({ name: 'ssl-checker-test', version: '1.0.0' })

  try {
    await client.connect(transport)
    const listed = await client.listTools()
    assert.equal(listed.tools.length, 1)
    assert.equal(listed.tools[0].name, 'check_ssl_certificate')
    assert.equal(listed.tools[0].annotations.readOnlyHint, true)

    const result = await client.callTool({
      name: 'check_ssl_certificate',
      arguments: { host: '127.0.0.1', port: 443 }
    })
    assert.equal(result.isError, true)
    assert.match(result.content[0].text, /BLOCKED_TARGET/)
  } finally {
    await client.close()
  }
})
