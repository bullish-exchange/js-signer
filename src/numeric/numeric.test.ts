import {
  base64ToBinary,
  binaryToDecimal,
  decimalToBinary,
  isNegative,
  negate,
  privateKeyToString,
  signedBinaryToDecimal,
  signedDecimalToBinary,
} from './numeric'

import { Key } from '../config'
import { ERROR_TEXT } from '../constant'

describe('Numeric', () => {
  it('isNegative', () => {
    const result = isNegative(new Uint8Array())
    expect(result).toBe(false)
  })
  it('negate for empty data', () => {
    const result = negate(new Uint8Array())
    expect(result).toBe(undefined)
  })
  it('negate for 0', () => {
    const result = negate(new Uint8Array([0]))
    expect(result).toBe(undefined)
  })
  it('base64ToBinary for base64 data', () => {
    const result = base64ToBinary('YXBwbGU=')
    const expected = new Uint8Array([97, 112, 112, 108, 101])
    expect(result).toEqual(expected)
  })
  it('base64ToBinary for empty data', () => {
    const result = base64ToBinary('=')
    const expected = new Uint8Array([])
    expect(result).toEqual(expected)
  })
  it('base64ToBinary for incorrect base64 data', () => {
    expect(() => base64ToBinary('apple')).toThrow(Error(ERROR_TEXT.BASE_64_VALUE_NOT_PADDED_CORRECTLY))
  })

  it('decimalToBinary for size 1', () => {
    const value = decimalToBinary(1, '2')
    const expected = new Uint8Array([2])
    expect(value).toEqual(expected)
  })
  it('decimalToBinary for size 5', () => {
    const value = decimalToBinary(5, '2')
    const expected = new Uint8Array([2, 0, 0, 0, 0])
    expect(value).toEqual(expected)
  })
  it('decimalToBinary for wrong data should throw error', () => {
    expect(() => decimalToBinary(5, 'A')).toThrow(Error(ERROR_TEXT.INVALID_NUMBER))
  })
  it('signedDecimalToBinary for size 1', () => {
    const value = signedDecimalToBinary(1, '-2')
    const expected = new Uint8Array([254])
    expect(value).toEqual(expected)
  })

  it('signedDecimalToBinary for size 5', () => {
    const value = signedDecimalToBinary(5, '-2')
    const expected = new Uint8Array([254, 255, 255, 255, 255])
    expect(value).toEqual(expected)
  })
  it('signedDecimalToBinary for wrong data should throw error', () => {
    expect(() => signedDecimalToBinary(5, 'A')).toThrow(Error(ERROR_TEXT.INVALID_NUMBER))
  })

  it('binaryToDecimal for size 1', () => {
    const input = new Uint8Array([2])
    const value = binaryToDecimal(input, 1)
    expect(value).toEqual('2')
  })
  it('binaryToDecimal for size 5', () => {
    const input = new Uint8Array([2, 0, 0, 0, 0])
    const value = binaryToDecimal(input, 1)
    expect(value).toEqual('2')
  })
  it('signedBinaryToDecimal for size 1', () => {
    const input = new Uint8Array([254, 255, 255, 255, 255])
    const value = signedBinaryToDecimal(input, 1)
    expect(value).toEqual('-2')
  })

  it('privateKeyToString should throw error for invalid key', () => {
    expect(() => privateKeyToString('Wrong private key' as unknown as Key)).toThrow(
      Error(ERROR_TEXT.UNRECOGNIZED_PRIVATE_KEY_FORMAT)
    )
  })
})
