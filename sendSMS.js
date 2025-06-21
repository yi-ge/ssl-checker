const axios = require('axios');

const axiosInstance = axios.create({
  baseURL: 'https://example.com'
})

const templateId = 'xxx'
const appid = 'xxx'
const appkey = 'xxx'
const type = 'xxx'
const auth = 'xxx'

const sendSMS = async (phones, params) => {
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

  const { data } = await axiosInstance.post('/sendSMS', sendSMSBody)

  return data
}

module.exports = sendSMS
