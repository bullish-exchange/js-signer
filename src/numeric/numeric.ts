import { privateKeyDataSize, publicKeyDataSize, signatureDataSize } from './numeric.config'
import { base58Map, base64Map, binaryToBase58, ripemd160FromBuffer } from './numeric.util'

import {
  Key,
  KeyStringSuffix,
  KeyType,
  PubKeyStringPrefix,
  PvtKeyStringPrefix,
  SignatureStringPrefix,
} from '../config'
import { ERRORS } from '../constant'
import { sha256 } from '../external'

/** Is `bignum` a negative number? */
export const isNegative = (bignum: Uint8Array): boolean => (bignum[bignum.length - 1] & 0x80) !== 0

/** Negate `bignum` */
export const negate = (bignum: Uint8Array): void => {
  let carry = 1
  for (let i = 0; i < bignum.length; ++i) {
    const x = (~bignum[i] & 0xff) + carry
    bignum[i] = x
    carry = x >> 8
  }
}

/**
 * Convert an unsigned decimal number in `s` to a bignum
 *
 * @param size bignum size (bytes)
 */
export const decimalToBinary = (size: number, s: string): Uint8Array => {
  const result = new Uint8Array(size)
  for (let i = 0; i < s.length; ++i) {
    const srcDigit = s.charCodeAt(i)
    if (srcDigit < '0'.charCodeAt(0) || srcDigit > '9'.charCodeAt(0)) {
      throw ERRORS.INVALID_NUMBER
    }
    let carry = srcDigit - '0'.charCodeAt(0)
    for (let j = 0; j < size; ++j) {
      const x = result[j] * 10 + carry
      result[j] = x
      carry = x >> 8
    }
    if (carry) {
      throw ERRORS.NUMBER_OUT_OF_RANGE
    }
  }
  return result
}

/**
 * Convert a signed decimal number in `s` to a bignum
 *
 * @param size bignum size (bytes)
 */
export const signedDecimalToBinary = (size: number, s: string): Uint8Array => {
  const negative = s[0] === '-'
  if (negative) {
    s = s.substring(1)
  }
  const result = decimalToBinary(size, s)
  if (negative) {
    negate(result)
    if (!isNegative(result)) {
      throw ERRORS.NUMBER_OUT_OF_RANGE
    }
  } else if (isNegative(result)) {
    throw ERRORS.NUMBER_OUT_OF_RANGE
  }
  return result
}

/**
 * Convert `bignum` to an unsigned decimal number
 *
 * @param minDigits 0-pad result to this many digits
 */
export const binaryToDecimal = (bignum: Uint8Array, minDigits = 1): string => {
  const result = Array(minDigits).fill('0'.charCodeAt(0)) as number[]
  for (let i = bignum.length - 1; i >= 0; --i) {
    let carry = bignum[i]
    for (let j = 0; j < result.length; ++j) {
      const x = ((result[j] - '0'.charCodeAt(0)) << 8) + carry
      result[j] = '0'.charCodeAt(0) + (x % 10)
      carry = (x / 10) | 0
    }
    while (carry) {
      result.push('0'.charCodeAt(0) + (carry % 10))
      carry = (carry / 10) | 0
    }
  }
  result.reverse()
  return String.fromCharCode(...result)
}

/**
 * Convert `bignum` to a signed decimal number
 *
 * @param minDigits 0-pad result to this many digits
 */
export const signedBinaryToDecimal = (bignum: Uint8Array, minDigits = 1): string => {
  if (isNegative(bignum)) {
    const x = bignum.slice()
    negate(x)
    return '-' + binaryToDecimal(x, minDigits)
  }
  return binaryToDecimal(bignum, minDigits)
}

const base58ToBinaryVarSize = (s: string): Uint8Array => {
  const result = [] as number[]
  for (let i = 0; i < s.length; ++i) {
    let carry = base58Map[s.charCodeAt(i)]
    if (carry < 0) {
      throw ERRORS.INVALID_BASE_58_VALUE
    }
    for (let j = 0; j < result.length; ++j) {
      const x = result[j] * 58 + carry
      result[j] = x & 0xff
      carry = x >> 8
    }
    if (carry) {
      result.push(carry)
    }
  }
  for (const ch of s) {
    if (ch === '1') {
      result.push(0)
    } else {
      break
    }
  }
  result.reverse()
  return new Uint8Array(result)
}

/**
 * Convert an unsigned base-58 number in `s` to a bignum
 *
 * @param size bignum size (bytes)
 */
export const base58ToBinary = (size: number, s: string): Uint8Array => {
  if (!size) {
    return base58ToBinaryVarSize(s)
  }
  const result = new Uint8Array(size)
  for (let i = 0; i < s.length; ++i) {
    let carry = base58Map[s.charCodeAt(i)]
    if (carry < 0) {
      throw ERRORS.INVALID_BASE_58_VALUE
    }
    for (let j = 0; j < size; ++j) {
      const x = result[j] * 58 + carry
      result[j] = x
      carry = x >> 8
    }
    if (carry) {
      throw ERRORS.BASE_58_VALUE_OUT_OF_RANGE
    }
  }
  result.reverse()
  return result
}

/** Convert an unsigned base-64 number in `s` to a bignum */
export const base64ToBinary = (s: string): Uint8Array => {
  let len = s.length
  if ((len & 3) === 1 && s[len - 1] === '=') {
    len -= 1
  } // fc appends an extra '='
  if ((len & 3) !== 0) {
    throw ERRORS.BASE_64_VALUE_NOT_PADDED_CORRECTLY
  }
  const groups = len >> 2
  let bytes = groups * 3
  if (len > 0 && s[len - 1] === '=') {
    if (s[len - 2] === '=') {
      bytes -= 2
    } else {
      bytes -= 1
    }
  }
  const result = new Uint8Array(bytes)

  for (let group = 0; group < groups; ++group) {
    const digit0 = base64Map[s.charCodeAt(group * 4 + 0)]
    const digit1 = base64Map[s.charCodeAt(group * 4 + 1)]
    const digit2 = base64Map[s.charCodeAt(group * 4 + 2)]
    const digit3 = base64Map[s.charCodeAt(group * 4 + 3)]
    result[group * 3 + 0] = (digit0 << 2) | (digit1 >> 4)
    if (group * 3 + 1 < bytes) {
      result[group * 3 + 1] = ((digit1 & 15) << 4) | (digit2 >> 2)
    }
    if (group * 3 + 2 < bytes) {
      result[group * 3 + 2] = ((digit2 & 3) << 6) | digit3
    }
  }
  return result
}

/** Convert ArrayBuffer to string where characters in string are represented as bytes */
export const arrayToString = (data: ArrayBuffer) => String.fromCharCode(...new Uint8Array(data))

/** Convert string where characters in string are represented as bytes to an ArrayBuffer */
export const stringToArray = (str: string): ArrayBuffer => {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

const digestSuffixRipemd160 = (data: Uint8Array, suffix: string): ArrayBuffer => {
  const d = new Uint8Array(data.length + suffix.length)
  for (let i = 0; i < data.length; ++i) {
    d[i] = data[i]
  }
  for (let i = 0; i < suffix.length; ++i) {
    d[data.length + i] = suffix.charCodeAt(i)
  }
  return ripemd160FromBuffer(d).digest()
}

const stringToKey = (s: string, type: KeyType, size: number, suffix: string): Key => {
  const whole = base58ToBinary(size ? size + 4 : 0, s)
  const result: Key = {
    type,
    data: new Uint8Array(whole.buffer, 0, whole.length - 4),
  }
  const digest = new Uint8Array(digestSuffixRipemd160(result.data, suffix))
  if (
    digest[0] !== whole[whole.length - 4] ||
    digest[1] !== whole[whole.length - 3] ||
    digest[2] !== whole[whole.length - 2] ||
    digest[3] !== whole[whole.length - 1]
  ) {
    throw ERRORS.CHECKSUM_MISMATCH
  }
  return result
}

const keyToString = (key: Key, suffix: string, prefix: string): string => {
  const digest = new Uint8Array(digestSuffixRipemd160(key.data, suffix))
  const whole = new Uint8Array(key.data.length + 4)
  for (let i = 0; i < key.data.length; ++i) {
    whole[i] = key.data[i]
  }
  for (let i = 0; i < 4; ++i) {
    whole[i + key.data.length] = digest[i]
  }
  return prefix + binaryToBase58(whole)
}

/** Convert key in `s` to binary form */
export const stringToPublicKey = (s: string): Key => {
  if (typeof s !== 'string') {
    throw ERRORS.EXPECTED_STRING_CONTAINING_PUBLIC_KEY
  }
  if (s.substring(0, 3) === 'EOS') {
    const whole = base58ToBinary(publicKeyDataSize + 4, s.substring(3))
    const key = { type: KeyType.k1, data: new Uint8Array(publicKeyDataSize) }
    for (let i = 0; i < publicKeyDataSize; ++i) {
      key.data[i] = whole[i]
    }
    const digest = new Uint8Array(ripemd160FromBuffer(key.data).digest())
    if (
      digest[0] !== whole[publicKeyDataSize] ||
      digest[1] !== whole[34] ||
      digest[2] !== whole[35] ||
      digest[3] !== whole[36]
    ) {
      throw ERRORS.CHECKSUM_MISMATCH
    }
    return key
  } else if (s.substring(0, 7) === PubKeyStringPrefix.K1) {
    return stringToKey(s.substring(7), KeyType.k1, publicKeyDataSize, KeyStringSuffix.K1)
  } else if (s.substring(0, 7) === PubKeyStringPrefix.R1) {
    return stringToKey(s.substring(7), KeyType.r1, publicKeyDataSize, KeyStringSuffix.R1)
  } else if (s.substring(0, 7) === PubKeyStringPrefix.WA) {
    return stringToKey(s.substring(7), KeyType.wa, 0, KeyStringSuffix.WA)
  } else {
    throw ERRORS.UNRECOGNIZED_PUBLIC_KEY_FORMAT
  }
}

/** Convert public `key` to legacy string (base-58) form */
export const publicKeyToLegacyString = (key: Key): string => {
  if (key.type === KeyType.k1 && key.data.length === publicKeyDataSize) {
    return keyToString(key, '', 'EOS')
  } else if (key.type === KeyType.r1 || key.type === KeyType.wa) {
    throw ERRORS.KEY_FORMAT_NOT_SUPPORTED_IN_LEGACY_CONVERSION
  } else {
    throw ERRORS.UNRECOGNIZED_PUBLIC_KEY_FORMAT
  }
}

/** Convert `key` to string (base-58) form */
export const publicKeyToString = (key: Key): string => {
  if (key.type === KeyType.k1 && key.data.length === publicKeyDataSize) {
    return keyToString(key, 'K1', 'PUB_K1_')
  } else if (key.type === KeyType.r1 && key.data.length === publicKeyDataSize) {
    return keyToString(key, 'R1', 'PUB_R1_')
  } else if (key.type === KeyType.wa) {
    return keyToString(key, KeyStringSuffix.WA, PubKeyStringPrefix.WA)
  } else {
    throw ERRORS.UNRECOGNIZED_PUBLIC_KEY_FORMAT
  }
}

/** If a key is in the legacy format (`EOS` prefix), then convert it to the new format (`PUB_K1_`).
 * Leaves other formats untouched
 */
export const convertLegacyPublicKey = (s: string): string => {
  if (s.substring(0, 3) === 'EOS') {
    return publicKeyToString(stringToPublicKey(s))
  }
  return s
}

/** If a key is in the legacy format (`EOS` prefix), then convert it to the new format (`PUB_K1_`).
 * Leaves other formats untouched
 */
export const convertLegacyPublicKeys = (keys: string[]): string[] => {
  return keys.map(convertLegacyPublicKey)
}

/** Convert key in `s` to binary form */
export const stringToPrivateKey = (s: string): Key => {
  if (typeof s !== 'string') {
    throw ERRORS.EXPECTED_STRING_CONTAINING_PRIVATE_KEY
  }
  if (s.substring(0, 7) === PvtKeyStringPrefix.R1) {
    return stringToKey(s.substring(7), KeyType.r1, privateKeyDataSize, KeyStringSuffix.R1)
  } else if (s.substring(0, 7) === PvtKeyStringPrefix.K1) {
    return stringToKey(s.substring(7), KeyType.k1, privateKeyDataSize, KeyStringSuffix.K1)
  } else {
    // todo: Verify checksum: sha256(sha256(key.data)).
    //       Not critical since a bad key will fail to produce a
    //       valid signature anyway.
    const whole = base58ToBinary(privateKeyDataSize + 5, s)
    const key = { type: KeyType.k1, data: new Uint8Array(privateKeyDataSize) }
    if (whole[0] !== 0x80) {
      throw ERRORS.UNRECOGNIZED_PRIVATE_KEY_TYPE
    }
    for (let i = 0; i < privateKeyDataSize; ++i) {
      key.data[i] = whole[i + 1]
    }
    return key
  }
}

/** Convert private `key` to legacy string (base-58) form */
export const privateKeyToLegacyString = (key: Key): string => {
  if (key.type === KeyType.k1 && key.data.length === privateKeyDataSize) {
    const whole = [] as number[]
    whole.push(128)
    key.data.forEach(byte => whole.push(byte))
    const digest = new Uint8Array(sha256().update(sha256().update(whole).digest()).digest())

    const result = new Uint8Array(privateKeyDataSize + 5)
    for (let i = 0; i < whole.length; i++) {
      result[i] = whole[i]
    }
    for (let i = 0; i < 4; i++) {
      result[i + whole.length] = digest[i]
    }
    return binaryToBase58(result)
  } else if (key.type === KeyType.r1 || key.type === KeyType.wa) {
    throw ERRORS.KEY_FORMAT_NOT_SUPPORTED_IN_LEGACY_CONVERSION
  } else {
    throw ERRORS.UNRECOGNIZED_PUBLIC_KEY_FORMAT
  }
}

/** Convert `key` to string (base-58) form */
export const privateKeyToString = (key: Key): string => {
  if (key.type === KeyType.r1) {
    return keyToString(key, 'R1', 'PVT_R1_')
  } else if (key.type === KeyType.k1) {
    return keyToString(key, 'K1', 'PVT_K1_')
  } else {
    throw ERRORS.UNRECOGNIZED_PRIVATE_KEY_FORMAT
  }
}

/** Convert key in `s` to binary form */
export const stringToSignature = (s: string): Key => {
  if (typeof s !== 'string') {
    throw ERRORS.EXPECTED_STRING_CONTAINING_SIGNATURE
  }
  if (s.substring(0, 7) === SignatureStringPrefix.K1) {
    return stringToKey(s.substring(7), KeyType.k1, signatureDataSize, KeyStringSuffix.K1)
  } else if (s.substring(0, 7) === SignatureStringPrefix.R1) {
    return stringToKey(s.substring(7), KeyType.r1, signatureDataSize, KeyStringSuffix.R1)
  } else if (s.substring(0, 7) === SignatureStringPrefix.WA) {
    return stringToKey(s.substring(7), KeyType.wa, 0, KeyStringSuffix.WA)
  } else {
    throw ERRORS.UNRECOGNIZED_SIGNATURE_FORMAT
  }
}

/** Convert `signature` to string (base-58) form */
export const signatureToString = (signature: Key): string => {
  if (signature.type === KeyType.k1) {
    return keyToString(signature, 'K1', 'SIG_K1_')
  } else if (signature.type === KeyType.r1) {
    return keyToString(signature, 'R1', 'SIG_R1_')
  } else if (signature.type === KeyType.wa) {
    return keyToString(signature, KeyStringSuffix.WA, SignatureStringPrefix.WA)
  } else {
    throw ERRORS.UNRECOGNIZED_SIGNATURE_FORMAT
  }
}
