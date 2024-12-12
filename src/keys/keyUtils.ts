import { ec as EC } from 'elliptic'

import { PrivateKey } from './PrivateKey'
import { PublicKey } from './PublicKey'

import { KeyType } from '../config'
import {
  ALGORITHM_CURVE,
  ALGORITHM_NAME,
  ELLIPTIC_CURVE,
  ELLIPTIC_CURVE_K1,
  ERRORS,
  KEY_USAGE,
} from '../constant'

const { subtle } = globalThis.crypto

const DEFAULT_ALGORITHM: EcKeyGenParams = {
  name: ALGORITHM_NAME,
  namedCurve: ALGORITHM_CURVE,
}

const DEFAULT_KEY_USAGE: ReadonlyArray<KeyUsage> = [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]

/**
 * @description generate private & public key pair
 * @param type r1 (default) or k1
 * @param options
 * @returns private & public keys
 */
export const generateKeyPair = (
  type: KeyType = KeyType.r1,
  options: { secureEnv?: boolean; ecOptions?: EC.GenKeyPairOptions } = {}
): { publicKey: PublicKey; privateKey: PrivateKey } => {
  if (!options.secureEnv) {
    throw ERRORS.INSECURE_ENV
  }

  const curve = KeyType.k1 ? ELLIPTIC_CURVE_K1 : ELLIPTIC_CURVE
  const ec = new EC(curve)
  const ellipticKeyPair = ec.genKeyPair(options.ecOptions)
  const publicKey = PublicKey.fromElliptic(ellipticKeyPair, type, ec)
  const privateKey = PrivateKey.fromElliptic(ellipticKeyPair, type, ec)
  return { publicKey, privateKey }
}

/** Construct a p256/secp256r1 CryptoKeyPair from Web Crypto
 * Note: While creating a key that is not extractable means that it would not be possible
 * to convert the private key to string, it is not necessary to have the key extractable
 * for the Web Crypto Signature Provider.  Additionally, creating a key that is extractable
 * introduces security concerns.  For this reason, this function only creates CryptoKeyPairs
 * where the private key is not extractable and the public key is extractable.
 */
export const generateWebCryptoKeyPair = async (
  extractable = false,
  keyUsage = DEFAULT_KEY_USAGE,
  algorithm = DEFAULT_ALGORITHM
): Promise<CryptoKeyPair> => await subtle.generateKey(algorithm, extractable, keyUsage)

/**
 * @description generate api keys
 * - api keys once generated should be added to your account
 * - once the api keys are added, it can be used to sign request
 * - backend will be able to verify request using the signature added to header
 * @returns
 */
export const generateWebCryptoStringKeyPair = async (extractable = true) => {
  const { privateKey, publicKey } = await generateWebCryptoKeyPair(extractable)
  const publicKeyString = (await PublicKey.fromWebCrypto(publicKey)).toString()
  const privateKeyString = (await PrivateKey.fromWebCrypto(privateKey)).toString()

  return {
    publicKey: publicKeyString,
    privateKey: privateKeyString,
  }
}
