import { ERROR_TEXT } from './../constant'
import {
  getTypeFromPrivateKeyString,
  getTypeFromPublicKeyString,
  isPrivateKeyValid,
  isPublicKeyValid,
} from './verify'

import { KeyType } from '../config'

describe('Verify', () => {
  describe('public key', () => {
    it('should not verify invalid key', () => {
      expect(isPublicKeyValid('invalid key')).toBeFalsy()
    })
    it('should verify valid key', () => {
      expect(isPublicKeyValid('PUB_R1_8CHJquaQWe4Pkhp1fBR9deP5wkqfjuWdfhaKYDxGKCo7gQwU9C')).toBeTruthy()
    })
    it('should return public key type', () => {
      expect(getTypeFromPublicKeyString('PUB_R1_8CHJquaQWe4Pkhp1fBR9deP5wkqfjuWdfhaKYDxGKCo7gQwU9C')).toBe(
        KeyType.r1
      )
    })
    it('should throw error for invalid public key', () => {
      expect(() => getTypeFromPublicKeyString('invalid key')).toThrow(Error(ERROR_TEXT.KEY_UNEXTRACTABLE))
    })
    it('should throw error for empty public key', () => {
      expect(() => getTypeFromPublicKeyString('')).toThrow(
        Error(ERROR_TEXT.EXPECTED_STRING_CONTAINING_PUBLIC_KEY)
      )
    })
  })

  describe('private key', () => {
    it('should not verify invalid key', () => {
      expect(isPrivateKeyValid('invalid key')).toBeFalsy()
    })
    it('should verify valid key', () => {
      expect(isPrivateKeyValid('PVT_R1_ENSnpAGb4NHNA2chipxHQMVnAZdEAfRzHmJFEuxFkWvCXC5CG')).toBeTruthy()
    })
    it('should return true for valid private key', () => {
      expect(getTypeFromPrivateKeyString('PVT_R1_ENSnpAGb4NHNA2chipxHQMVnAZdEAfRzHmJFEuxFkWvCXC5CG')).toBe(
        KeyType.r1
      )
    })
    it('should throw error for invalid private key', () => {
      expect(() => getTypeFromPrivateKeyString('invalid key')).toThrow(Error(ERROR_TEXT.KEY_UNEXTRACTABLE))
    })
    it('should throw error for empty private key', () => {
      expect(() => getTypeFromPrivateKeyString('')).toThrow(
        Error(ERROR_TEXT.EXPECTED_STRING_CONTAINING_PRIVATE_KEY)
      )
    })
  })
})
