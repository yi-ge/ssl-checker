const fs = require('fs')
const path = require('path')
const https = require('https')
const fastify = require('fastify')({ logger: true })
const sendSMS = require('./sendSMS')

const schedule = require('node-schedule')

async function checkerSSLCertificate (host, port = 443) {
  return new Promise((resolve, reject) => {
    if (!port || isNaN(parseFloat(port)) || !isFinite(port)) {
      reject(new Error('Invalid host or port'))
    }

    const req = https.request({
      host,
      port,
      method: 'GET',
      rejectUnauthorized: false,
      agent: new https.Agent({
        maxCachedSessions: 0,
        timeout: 1000
      }),
      timeout: 1000,
    }, function (res) {
      const certificateInfo = res.socket.getPeerCertificate()

      function dhm (t) {
        const cd = 24 * 60 * 60 * 1000
        const ch = 60 * 60 * 1000
        let d = Math.floor(t / cd)
        let h = Math.floor((t - d * cd) / ch)
        let m = Math.round((t - d * cd - h * ch) / 60000)

        const pad = n => n < 10 ? '0' + n : n

        if (m === 60) {
          h++
          m = 0
        }

        if (h === 24) {
          d++
          h = 0
        }

        return [d, pad(h), pad(m)]
      }

      const expires = new Date(certificateInfo.valid_to)
      const days = dhm(expires - new Date())[0]

      resolve({
        valid_from: certificateInfo.valid_from,
        valid_to: certificateInfo.valid_to,
        days
      })
    })

    req.on('timeout', () => {
      req.destroy();
    });

    req.on('error', err => {
      console.log(err)
      reject(err)
    })
    req.end()
  })
}

fastify.register(require('@fastify/basic-auth'), {
  validate: (username, password, req, reply, done) => {
    if (username === 'admin' && password === 'admin') done() // TODO: 在这里修改用户名和密码
    else done(new Error('Winter is coming'))
  }, authenticate: { realm: 'Westeros' }
})

fastify.after(() => {
  fastify.addHook('onRequest', fastify.basicAuth)

  fastify.get('/', (req, reply) => {
    reply.type('text/html')
    return fs.readFileSync(path.join(__dirname, 'index.html'))
  })

  fastify.get('/api/config', (req, reply) => {
    return {
      code: 1,
      result: fs.readFileSync(path.join(__dirname, 'config.txt'), 'utf8')
    }
  })

  fastify.post('/api/config', (req, reply) => {
    const { data } = req.body
    if (!data) return { code: -2, msg: '内容为空' }
    try {
      fs.writeFileSync(path.join(__dirname, 'config.txt'), data, 'utf8')
      return { code: 1 }
    } catch (err) {
      return { code: -1, msg: '写入文件异常' }
    }
  })

  fastify.get('/api/checkerSSLCertificate', async (req, reply) => {
    try {
      const result = await checkerSSLCertificate(req.query.host, req.query.port)
      return {
        code: 1,
        msg: 'ok',
        result
      }
    } catch (err) {
      return { code: -1, msg: err.toString() }
    }
  })
})

schedule.scheduleJob('0 0 * * *', function () { // 循环任务。 这里修改cron风格的表达式
  const lines = fs.readFileSync(path.join(__dirname, 'config.txt'), 'utf8').split('\n')
  lines.forEach(async line => {
    if (line.trim().includes('//')) {
      line = line.split('//')[0]
    }
    if (line.trim()) {
      const [hostStr, phones] = line.split('|')
      if (hostStr.trim() && phones) {
        const phoneList = phones && phones.split ? phones.split(',') : []
        const [host, port] = hostStr.split(':')
        try {
          const { valid_from, valid_to, days } = await checkerSSLCertificate(host, port)
          // console.log(host, valid_from, valid_to, days)
          if (days < 3) {
            console.log(await sendSMS(phoneList, {
              host: host.replace(/\./g, '-').substring(0, 15),
              day: days
            }))
          }
        } catch (err) {
          console.error(err)
        }
      }
    }
  })
})

const start = async () => {
  try {
    await fastify.listen({
      port: 9000,
      host: '0.0.0.0'
    })
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()
