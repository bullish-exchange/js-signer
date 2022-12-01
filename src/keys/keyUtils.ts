import { KeyType } from '../config'
import {
  ALGORITHM_CURVE,
  ALGORITHM_NAME,
  ELLIPTIC_CURVE,
  ELLIPTIC_CURVE_K1,
  ERRORS,
  KEY_USAGE,
} from '../constant'
import { crypto, EC } from '../external'
import { PrivateKey, PublicKey } from '../keys'

const DEFAULT_ALGORITHM: EcKeyGenParams = {
  name: ALGORITHM_NAME,
  namedCurve: ALGORITHM_CURVE,
}

const DEFAULT_KEY_USAGE: ReadonlyArray<KeyUsage> = [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]

export const generateKeyPair = (
  type: KeyType,
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
): Promise<CryptoKeyPair> => await crypto.subtle.generateKey(algorithm, extractable, keyUsage)
