import { getHeaders } from './getHeaders'

describe('getHeaders', () => {
  it('get Headers', () => {
    const result = getHeaders('', '', '')
    expect(result['BX-NONCE']).toBe('')
    expect(result['BX-SIGNATURE']).toBe('')
    expect(result['BX-TIMESTAMP']).toBe('')
  })
})
