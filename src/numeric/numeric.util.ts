import { base58Chars, base64Chars } from '../constant'
import { Buffer, RIPEMD160 } from '../external'

const create_base58_map = (): number[] => {
  const base58M = Array(256).fill(-1) as number[]
  for (let i = 0; i < base58Chars.length; ++i) {
    base58M[base58Chars.charCodeAt(i)] = i
  }
  return base58M
}

export const base58Map = create_base58_map()

const create_base64_map = (): number[] => {
  const base64M = Array(256).fill(-1) as number[]
  for (let i = 0; i < base64Chars.length; ++i) {
    base64M[base64Chars.charCodeAt(i)] = i
  }
  base64M['='.charCodeAt(0)] = 0
  return base64M
}

export const base64Map = create_base64_map()

/**
 * Convert `bignum` to a base-58 number
 *
 * @param minDigits 0-pad result to this many digits
 */
export const binaryToBase58 = (bignum: Uint8Array): string => {
  const result = [] as number[]
  for (const byte of bignum) {
    let carry = byte
    for (let j = 0; j < result.length; ++j) {
      const x = (base58Map[result[j]] << 8) + carry
      result[j] = base58Chars.charCodeAt(x % 58)
      carry = (x / 58) | 0
    }
    while (carry) {
      result.push(base58Chars.charCodeAt(carry % 58))
      carry = (carry / 58) | 0
    }
  }
  for (const byte of bignum) {
    if (byte) {
      break
    } else {
      result.push('1'.charCodeAt(0))
    }
  }
  result.reverse()
  return String.fromCharCode(...result)
}

export const ripemd160FromBuffer = (d: Uint8Array) => new RIPEMD160().update(Buffer.from(d))
