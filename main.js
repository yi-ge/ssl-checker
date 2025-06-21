const fs = require('fs')
const path = require('path')
const https = require('https')
const fastify = require('fastify')({ logger: true })
const sendSMS = require('./sendSMS')

const schedule = require('node-schedule')

const USERNAME = process.env.USERNAME || 'admin' // TODO: 修改用户名和密码
const PASSWORD = process.env.PASSWORD || 'admin'
const CACHE_FILE = 'ssl_cache.json'
const CACHE_EXPIRATION_SUCCESS = 5 * 60 * 1000 // 5 minutes for successful checks
const CACHE_EXPIRATION_ERROR = 1 * 60 * 1000 // 1 minute for errors

async function checkerSSLCertificate (host, port = 443) {
  return new Promise((resolve, reject) => {
    if (!port || isNaN(parseFloat(port)) || !isFinite(port)) {
      return reject(new Error('Invalid host or port'))
    }

    const req = https.request({
      host,
      port,
      method: 'GET',
      rejectUnauthorized: false,
      agent: new https.Agent({
        maxCachedSessions: 0,
        timeout: 5000
      }),
      timeout: 5000,
    }, function (res) {
      const certificateInfo = res.socket.getPeerCertificate()

      if (!certificateInfo || !certificateInfo.valid_from || !certificateInfo.valid_to) {
        return reject(new Error('No certificate information available'))
      }

      const expires = new Date(certificateInfo.valid_to)
      const now = new Date()
      const timeDiff = expires - now

      if (isNaN(timeDiff)) {
        return reject(new Error('Invalid certificate date'))
      }

      const days = Math.floor(timeDiff / (24 * 60 * 60 * 1000))

      resolve({
        valid_from: certificateInfo.valid_from,
        valid_to: certificateInfo.valid_to,
        days
      })
    })

    req.on('timeout', () => {
      req.destroy()
      reject(new Error('Request timed out'))
    })

    req.on('error', err => {
      console.log(err)
      reject(err)
    })
    req.end()
  })
}

async function retryRequest (host, port = 443, retries = 5) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const result = await checkerSSLCertificate(host, port);
      return result;
    } catch (err) {
      console.error(`Attempt ${attempt} failed for ${host}:${port} - ${err.message}`);
      if (attempt === retries) {
        throw new Error(`Failed after ${retries} attempts: ${err.message}`);
      }
    }
  }
}

function readCache () {
  try {
    const cache = fs.readFileSync(CACHE_FILE, 'utf8');
    return JSON.parse(cache);
  } catch (err) {
    return {};
  }
}

function writeCache (cache) {
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache), 'utf8');
  } catch (err) {
    console.error('Failed to write cache:', err.message);
  }
}

async function cachedCheckerSSLCertificate (host, port = 443) {
  const cache = readCache();
  const cacheKey = `${host}:${port}`;
  const now = Date.now();

  if (cache[cacheKey]) {
    const { timestamp, result, error } = cache[cacheKey];
    const isError = !!error;
    const expiration = isError ? CACHE_EXPIRATION_ERROR : CACHE_EXPIRATION_SUCCESS;

    if (now - timestamp < expiration) {
      console.log(`Using cached ${isError ? 'error' : 'result'} for ${host}:${port}`);
      if (isError) {
        throw new Error(error);
      } else {
        return result;
      }
    } else {
      // Cache expired, remove entry
      delete cache[cacheKey];
    }
  }

  try {
    const result = await retryRequest(host, port);
    cache[cacheKey] = { timestamp: now, result };
    writeCache(cache);
    return result;
  } catch (err) {
    cache[cacheKey] = { timestamp: now, error: err.message };
    writeCache(cache);
    throw err;
  }
}

fastify.register(require('@fastify/basic-auth'), {
  validate: (username, password, req, reply, done) => {
    if (username === USERNAME && password === PASSWORD) done()
    else done(new Error('Unauthorized'))
  }, authenticate: { realm: 'Westeros' }
})

fastify.after(() => {
  fastify.addHook('onRequest', fastify.basicAuth)

  fastify.get('/', (req, reply) => {
    reply.type('text/html')
    return fs.readFileSync(path.join(__dirname, 'index.html'))
  })

  fastify.get('/api/config', (req, reply) => {
    try {
      const configData = fs.readFileSync(path.join(__dirname, 'config.txt'), 'utf8');
      return {
        code: 1,
        result: configData
      }
    } catch (err) {
      return { code: -1, msg: 'Failed to read config' }
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
      const host = req.query.host
      const port = req.query.port || 443

      if (!host) {
        return { code: -2, msg: 'Host is required' }
      }

      const result = await cachedCheckerSSLCertificate(host, port)
      return {
        code: 1,
        msg: 'ok',
        result
      }
    } catch (err) {
      return { code: -1, msg: err.message }
    }
  })

  // 发送测试短信，用于验证短信接口配置是否可用
  fastify.route({
    method: ['POST', 'GET'],
    url: '/api/testSMS',
    handler: async (req, reply) => {
      try {
        const phonesRaw = (req.body && req.body.phones) || req.query.phones
        if (!phonesRaw) {
          return { code: -2, msg: '手机号不能为空' }
        }

        const phoneList = Array.isArray(phonesRaw)
          ? phonesRaw
          : phonesRaw.split(',').map(p => p.trim()).filter(p => p)

        if (phoneList.length === 0) {
          return { code: -2, msg: '手机号不能为空' }
        }

        const result = await sendSMS(phoneList, { host: 'test', day: 0 })
        return { code: 1, result }
      } catch (err) {
        return { code: -1, msg: err.message }
      }
    }
  })
})

schedule.scheduleJob('0 0 * * *', async function () {
  try {
    const lines = fs.readFileSync(path.join(__dirname, 'config.txt'), 'utf8').split('\n')
    const tasks = []

    for (const line of lines) {
      let trimmedLine = line.trim()
      if (trimmedLine.includes('//')) {
        trimmedLine = trimmedLine.split('//')[0]
      }

      if (trimmedLine) {
        const [hostStr, phones] = trimmedLine.split('|')
        if (hostStr && phones) {
          const phoneList = phones.split(',').map(phone => phone.trim()).filter(phone => phone)
          const [host, port] = hostStr.split(':')

          tasks.push((async () => {
            try {
              const { valid_from, valid_to, days } = await cachedCheckerSSLCertificate(host.trim(), port ? parseInt(port) : 443)
              if (days < 3) {
                console.log(`SSL certificate for ${host} expires in ${days} days`)
                console.log(await sendSMS(phoneList, {
                  host: host.replace(/\./g, '-').substring(0, 15),
                  day: days
                }))
              }
            } catch (err) {
              console.error(`Failed to check SSL for ${host}:${port || 443} - ${err.message}`)
            }
          })())
        } else {
          console.error(`Invalid line in config.txt: ${line}`)
        }
      }
    }

    await Promise.allSettled(tasks)
  } catch (err) {
    console.error('Failed to read config.txt:', err.message)
  }
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
