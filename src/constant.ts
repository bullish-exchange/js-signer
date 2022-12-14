export const ALGORITHM_NAME = 'ECDSA'
export const ALGORITHM_CURVE = 'P-256'
export const ALGORITHM_HASH = 'SHA-256'

export const ELLIPTIC_CURVE_K1 = 'secp256k1'
export const ELLIPTIC_CURVE = 'p256'

export const base58Chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export enum KEY_FORMAT {
  PKCS8 = 'pkcs8',
  RAW = 'raw',
  SPKI = 'spki',
}

export enum KEY_USAGE {
  SIGN = 'sign',
  VERIFY = 'verify',
}

export enum KEY_TYPE {
  PUBLIC = 'public',
  PRIVATE = 'private',
}

export enum ERROR_TEXT {
  BASE_58_VALUE_OUT_OF_RANGE = 'base-58 value is out of range',
  BASE_64_VALUE_NOT_PADDED_CORRECTLY = 'base-64 value is not padded correctly',
  CHECKSUM_MISMATCH = "checksum doesn't match",
  EXPECTED_STRING_CONTAINING_PRIVATE_KEY = 'expected string containing private key',
  EXPECTED_STRING_CONTAINING_PUBLIC_KEY = 'expected string containing public key',
  EXPECTED_STRING_CONTAINING_SIGNATURE = 'expected string containing signature',
  INVALID_BASE_58_VALUE = 'invalid base-58 value',
  INVALID_NUMBER = 'invalid number',
  INVALID_RECOVERY_FACTOR = 'Unable to find valid recovery factor',
  INSECURE_ENV = 'Key generation is completely INSECURE in production environments in the browser. If you are absolutely certain this does NOT describe your environment, set `secureEnv` in your options to `true`.  If this does describe your environment and you set `secureEnv` to `true`, YOU DO SO AT YOUR OWN RISK AND THE RISK OF YOUR USERS.',
  KEY_FORMAT_NOT_SUPPORTED_IN_LEGACY_CONVERSION = 'Key format not supported in legacy conversion',
  KEY_UNEXTRACTABLE = 'Crypto Key is not extractable',
  NUMBER_OUT_OF_RANGE = 'number is out of range',
  UNRECOGNIZED_PRIVATE_KEY_FORMAT = 'unrecognized private key format',
  UNRECOGNIZED_PRIVATE_KEY_TYPE = 'unrecognized private key type',
  UNRECOGNIZED_PUBLIC_KEY_FORMAT = 'unrecognized public key format',
  UNRECOGNIZED_SIGNATURE_FORMAT = 'unrecognized signature format',
}

export const ERRORS = {
  BASE_58_VALUE_OUT_OF_RANGE: new Error(ERROR_TEXT.BASE_58_VALUE_OUT_OF_RANGE),
  BASE_64_VALUE_NOT_PADDED_CORRECTLY: new Error(ERROR_TEXT.BASE_64_VALUE_NOT_PADDED_CORRECTLY),
  CHECKSUM_MISMATCH: new Error(ERROR_TEXT.CHECKSUM_MISMATCH),
  EXPECTED_STRING_CONTAINING_PRIVATE_KEY: new Error(ERROR_TEXT.EXPECTED_STRING_CONTAINING_PRIVATE_KEY),
  EXPECTED_STRING_CONTAINING_PUBLIC_KEY: new Error(ERROR_TEXT.EXPECTED_STRING_CONTAINING_PUBLIC_KEY),
  EXPECTED_STRING_CONTAINING_SIGNATURE: new Error(ERROR_TEXT.EXPECTED_STRING_CONTAINING_SIGNATURE),
  INVALID_BASE_58_VALUE: new Error(ERROR_TEXT.INVALID_BASE_58_VALUE),
  INVALID_NUMBER: new Error(ERROR_TEXT.INVALID_NUMBER),
  INVALID_RECOVERY_FACTOR: new Error(ERROR_TEXT.INVALID_RECOVERY_FACTOR),
  INSECURE_ENV: new Error(ERROR_TEXT.INSECURE_ENV),
  KEY_FORMAT_NOT_SUPPORTED_IN_LEGACY_CONVERSION: new Error(
    ERROR_TEXT.KEY_FORMAT_NOT_SUPPORTED_IN_LEGACY_CONVERSION
  ),
  KEY_UNEXTRACTABLE: new Error(ERROR_TEXT.KEY_UNEXTRACTABLE),
  NUMBER_OUT_OF_RANGE: new Error(ERROR_TEXT.NUMBER_OUT_OF_RANGE),
  UNRECOGNIZED_PRIVATE_KEY_FORMAT: new Error(ERROR_TEXT.UNRECOGNIZED_PRIVATE_KEY_FORMAT),
  UNRECOGNIZED_PRIVATE_KEY_TYPE: new Error(ERROR_TEXT.UNRECOGNIZED_PRIVATE_KEY_TYPE),
  UNRECOGNIZED_PUBLIC_KEY_FORMAT: new Error(ERROR_TEXT.UNRECOGNIZED_PUBLIC_KEY_FORMAT),
  UNRECOGNIZED_SIGNATURE_FORMAT: new Error(ERROR_TEXT.UNRECOGNIZED_SIGNATURE_FORMAT),
}
