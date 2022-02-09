const axios = require('axios');

const templateId = 'xxx'

const sendSMS = async (phones, params) => {
  const { data } = await axios.post('https://api.xxx.xxx/sendSMS', {
    auth: 'xxx',
    type: 'xxx',
    config: {
      appUUID: 'test',
      appid: 001,
      appkey: 'xxx',
      smsSign: 'xxx'
    },
    params: {
      phones,
      templateId,
      params
    }
  })

  return data
}

module.exports = sendSMS