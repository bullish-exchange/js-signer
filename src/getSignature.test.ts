import { getSignature } from './getSignature'

describe('getSignature', () => {
  it('get Signature using Private key string', async () => {
    const privateKeyString = 'PVT_R1_ENSnpAGb4NHNA2chipxHQMVnAZdEAfRzHmJFEuxFkWvCXC5CG'
    const publicKeyString = 'PUB_R1_8CHJquaQWe4Pkhp1fBR9deP5wkqfjuWdfhaKYDxGKCo7gQwU9C'

    const payload = {
      message: 'I am a test string',
    }

    const signature = await getSignature(payload, publicKeyString, privateKeyString)
    expect(signature).toBe(
      'SIG_R1_KCymCyJCtCmbhGtb2B5XTfWQgtCDpESZNf9tYAJvTwsb3xw43ySdCohp1Lwko5TfChCW5c5Toyftv6f99Hv7UNsLoDv1QG'
    )
  })
})
