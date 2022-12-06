import { Signature } from './Signature'

import { ERROR_TEXT } from '../constant'

describe('Signature', () => {
  it('should throw error for wrong signature', () => {
    expect(() => Signature.fromString('hello')).toThrow(Error(ERROR_TEXT.UNRECOGNIZED_SIGNATURE_FORMAT))
  })

  it('should generate Signature', () => {
    const stringSignature =
      'SIG_R1_KFVMm45forRPwnSrdX9YG6ioUUbUuTnJLyfeRH9kvW7JNfd81jenf9Z2aZXwjnprvBYnfSKoYF7Gn6ZKBLiBcXFwN5Hy2H'
    expect(Signature.fromString(stringSignature)).toBeDefined()
  })
})
