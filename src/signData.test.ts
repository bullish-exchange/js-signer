import { signData } from './signData'

describe('signData', () => {
  it('get Signature using Private key string', () => {
    const privateKeyString = 'PVT_R1_ENSnpAGb4NHNA2chipxHQMVnAZdEAfRzHmJFEuxFkWvCXC5CG'

    const payload = 'I am a test string'

    const signature = signData(payload, privateKeyString)
    expect(signature).toEqual([
      'SIG_R1_KFoWD7gqpudPLQvAjhZ2BLtbvZvhfkCRA1JmY1qZ9XpjPUW1WLnA5aAtkPB139w667bJUroJqZrBDWN2V65f5MDGhM7o1H',
    ])
  })
})
