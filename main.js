const fs = require('fs')
const path = require('path')
const https = require('https')
const qs = require('qs')
const axios = require('axios')
const fastify = require('fastify')({ logger: true })

const schedule = require('node-schedule')

const sendSMS = async (phones, params) => { // TODO: 替换此内容为你的短信发送提供商内容即可
  const templateId = ''
  const appid = ''
  const appkey = ''
  const list = []

  phones.forEach(phone => {
    list.push({
      to: phone,
      vars: params
    })
  })

  const body = qs.stringify({
    appid,
    project: templateId,
    multi: JSON.stringify(list),
    signature: appkey
  })

  const {
    data
  } = await axios({
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    },
    method: 'POST',
    url: 'xxx',
    data: body,
  })

  if (data !== undefined) {
    for (const n in data) {
      if (data[n].status === 'success') data[n].code = 1
      if (data[n].to) data[n].mobile = data[n].to
      if (data[n].sms_credits) delete data[n].sms_credits
    }

    // 参数         必选 类型   描述
    // code         是 number 错误码，1表示成功（计费依据），非1表示失败
    // msg          否 string 错误消息，status 非1时的具体错误信息
    // fee          是 number 短信计费的条数，计费规则请参考具体运营商
    // mobile       是 string 手机号码
    // nationCode   否 string 国家（或地区）码
    // send_id      否 string 本次发送标识 ID，标识一次短信下发记录

    return {
      code: 1,
      result: data
    }
  } else {
    return {
      code: -1
    } // 收到未知错误
  }
}

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
        maxCachedSessions: 0
      }),
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

    req.on('error', err => reject(err))
    req.end()
  })
}

fastify.register(require('fastify-basic-auth'), {
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
    const res = await checkerSSLCertificate(req.query.host, req.query.port).catch(err => {
      reply.send({ code: -1, msg: err.message })
    })
    return res
  })
})

schedule.scheduleJob('0 0 1 * *', function () { // 循环任务。 这里修改cron风格的表达式
  const lines = fs.readFileSync(path.join(__dirname, 'config.txt'), 'utf8').split('\n')
  lines.forEach(async line => {
    if (line) {
      const [hostStr, phones] = line.split('|')
      if (phones) {
        const phoneList = phones.split(',')
        const [host, port] = hostStr.split(':')
        const { valid_from, valid_to, days } = await checkerSSLCertificate(host, port)
        console.log(host, valid_from, valid_to, days)
        if (days < 3) {
          console.log(await sendSMS(phoneList, {
            host: host.substring(0, 15),
            day: days
          }))
        }
      }
    }
  })
})

const start = async () => {
  try {
    await fastify.listen(9000, '0.0.0.0')
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()
