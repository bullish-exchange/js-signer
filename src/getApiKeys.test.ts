import { getApiKeys } from './getApiKeys'

describe('getApiKeys', () => {
  it('generate public & private key', async () => {
    const result = await getApiKeys()

    expect(typeof result.privateKey).toBe('string')
    expect(typeof result.publicKey).toBe('string')
  })
})
