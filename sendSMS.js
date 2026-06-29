const axios = require('axios')

const DEFAULT_ENDPOINT = '/sendSMS'
const DEFAULT_PROVIDER = 'submail'
const DEFAULT_TIMEOUT = 10000
const REQUIRED_FIELDS = ['baseURL', 'templateId', 'appid', 'appkey', 'auth']

function trimString (value, fallback = '') {
  if (value === undefined || value === null) return fallback
  return String(value).trim()
}

function normalizeTimeout (value) {
  if (value === undefined || value === null || value === '') return DEFAULT_TIMEOUT
  const timeout = parseInt(value, 10)
  return Number.isInteger(timeout) && timeout > 0 ? timeout : DEFAULT_TIMEOUT
}

function normalizeEnabled (value) {
  if (value === false || value === 'false' || value === '0') return false
  return true
}

function getEnvConfig () {
  const provider = trimString(process.env.SMS_PROVIDER || process.env.SMS_TYPE, DEFAULT_PROVIDER) || DEFAULT_PROVIDER
  return {
    enabled: normalizeEnabled(process.env.SMS_ENABLED),
    provider,
    baseURL: trimString(process.env.SMS_BASE_URL),
    endpoint: trimString(process.env.SMS_ENDPOINT, DEFAULT_ENDPOINT) || DEFAULT_ENDPOINT,
    templateId: trimString(process.env.SMS_TEMPLATE_ID),
    appid: trimString(process.env.SMS_APPID),
    appkey: trimString(process.env.SMS_APPKEY),
    type: trimString(process.env.SMS_TYPE, provider) || provider,
    auth: trimString(process.env.SMS_AUTH),
    appUUID: trimString(process.env.SMS_APP_UUID, 'test') || 'test',
    timeout: normalizeTimeout(process.env.SMS_TIMEOUT)
  }
}

function normalizeConfig (input = {}) {
  const provider = trimString(input.provider, DEFAULT_PROVIDER) || DEFAULT_PROVIDER
  return {
    enabled: normalizeEnabled(input.enabled),
    provider,
    baseURL: trimString(input.baseURL),
    endpoint: trimString(input.endpoint, DEFAULT_ENDPOINT) || DEFAULT_ENDPOINT,
    templateId: trimString(input.templateId),
    appid: trimString(input.appid),
    appkey: trimString(input.appkey),
    type: trimString(input.type, provider) || provider,
    auth: trimString(input.auth),
    appUUID: trimString(input.appUUID, 'test') || 'test',
    timeout: normalizeTimeout(input.timeout)
  }
}

function getMissingFields (config) {
  if (config.enabled === false) return []
  return REQUIRED_FIELDS.filter(field => !trimString(config[field]))
}

function hasRequiredConfig (config) {
  return config.enabled !== false && getMissingFields(config).length === 0
}

function validateSmsConfig (config) {
  if (config.enabled === false) return

  let parsedURL
  try {
    parsedURL = new URL(config.baseURL)
  } catch (err) {
    throw new Error('短信服务 Base URL 必须是有效的 HTTP/HTTPS 地址')
  }

  if (!['http:', 'https:'].includes(parsedURL.protocol)) {
    throw new Error('短信服务 Base URL 仅支持 HTTP/HTTPS')
  }

  if (!config.endpoint.startsWith('/')) {
    throw new Error('短信服务接口路径必须以 / 开头')
  }
}

const sendSMS = async (phones, params, options = {}) => {
  const config = normalizeConfig(options.config || getEnvConfig())
  if (config.enabled === false) {
    throw new Error('短信服务已禁用')
  }

  const missingFields = getMissingFields(config)
  if (missingFields.length > 0) {
    throw new Error(`短信服务未配置完整，缺少：${missingFields.join(', ')}`)
  }

  validateSmsConfig(config)

  if (!Array.isArray(phones) || phones.length === 0) {
    throw new Error('手机号不能为空')
  }

  const sendSMSBody = {
    auth: config.auth,
    type: config.type,
    config: {
      appUUID: config.appUUID,
      appid: config.appid,
      appkey: config.appkey
    },
    props: {
      type: 'mass',
      phones,
      templateId: config.templateId,
      params
    }
  }

  try {
    const axiosInstance = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout
    })
    const { data } = await axiosInstance.post(config.endpoint, sendSMSBody)
    return data
  } catch (err) {
    // 归一化错误信息，避免泄露完整请求体
    const detail = err.response
      ? `HTTP ${err.response.status}`
      : err.message
    throw new Error(`短信发送失败: ${detail}`)
  }
}

sendSMS.getEnvConfig = getEnvConfig
sendSMS.normalizeConfig = normalizeConfig
sendSMS.getMissingFields = getMissingFields
sendSMS.hasRequiredConfig = hasRequiredConfig
sendSMS.validateSmsConfig = validateSmsConfig

module.exports = sendSMS
