const axios = require('axios')

// 短信服务配置全部来自环境变量，无硬编码凭证
const baseURL = process.env.SMS_BASE_URL
const templateId = process.env.SMS_TEMPLATE_ID
const appid = process.env.SMS_APPID
const appkey = process.env.SMS_APPKEY
const type = process.env.SMS_TYPE || 'submail'
const auth = process.env.SMS_AUTH
const timeout = parseInt(process.env.SMS_TIMEOUT, 10) || 10000

// 是否已完成短信配置
const smsConfigured = Boolean(baseURL && templateId && appid && appkey && auth)

if (!smsConfigured) {
  console.warn(
    '[WARN] 短信服务未配置（缺少 SMS_BASE_URL / SMS_TEMPLATE_ID / SMS_APPID / SMS_APPKEY / SMS_AUTH）。\n' +
    '       SSL 证书检测仍可正常工作，但到期时无法发送短信告警。'
  )
}

const axiosInstance = smsConfigured
  ? axios.create({ baseURL, timeout })
  : null

const sendSMS = async (phones, params) => {
  if (!smsConfigured) {
    throw new Error('短信服务未配置，无法发送短信')
  }
  if (!Array.isArray(phones) || phones.length === 0) {
    throw new Error('手机号不能为空')
  }

  const sendSMSBody = {
    auth,
    type,
    config: {
      appUUID: 'test',
      appid,
      appkey
    },
    props: {
      type: 'mass',
      phones,
      templateId,
      params
    }
  }

  try {
    const { data } = await axiosInstance.post('/sendSMS', sendSMSBody)
    return data
  } catch (err) {
    // 归一化错误信息，避免泄露完整请求体
    const detail = err.response
      ? `HTTP ${err.response.status}`
      : err.message
    throw new Error(`短信发送失败: ${detail}`)
  }
}

module.exports = sendSMS
