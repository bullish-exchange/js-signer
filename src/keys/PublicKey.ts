import { Buffer } from 'buffer'

import { AbstractPublicKey } from './key.config'

import { Key, KeyType } from '../config'
import {
  ALGORITHM_CURVE,
  ALGORITHM_NAME,
  DER_HEX_PREFIX_PUBLIC,
  ELLIPTIC_CURVE,
  ELLIPTIC_CURVE_K1,
  ERRORS,
  KEY_FORMAT,
  KEY_USAGE,
} from '../constant'
import { crypto, EC } from '../external'
import {
  arrayToString,
  publicKeyToLegacyString,
  publicKeyToString,
  stringToArray,
  stringToPublicKey,
} from '../numeric'

/** Represents/stores a public key and provides easy conversion for use with `elliptic` lib */
export class PublicKey implements AbstractPublicKey {
  constructor(private key: Key, private ec: EC) {}

  /** Instantiate public key from an EOSIO-format public key */
  public static fromString(publicKeyStr: string, ec?: EC): PublicKey {
    const key = stringToPublicKey(publicKeyStr)
    if (!ec) {
      if (key.type === KeyType.k1) {
        ec = new EC(ELLIPTIC_CURVE_K1)
      } else {
        ec = new EC(ELLIPTIC_CURVE)
      }
    }
    return new PublicKey(key, ec)
  }

  /** Instantiate public key from an `elliptic`-format public key */
  public static fromElliptic(publicKey: EC.KeyPair, keyType: KeyType, ec?: EC): PublicKey {
    const x = publicKey.getPublic().getX().toArray('be', 32)
    const y = publicKey.getPublic().getY().toArray('be', 32)
    if (!ec) {
      if (keyType === KeyType.k1) {
        ec = new EC(ELLIPTIC_CURVE_K1)
      } else {
        ec = new EC(ELLIPTIC_CURVE)
      }
    }
    return new PublicKey(
      {
        type: keyType,
        data: new Uint8Array([y[31] & 1 ? 3 : 2].concat(x)),
      },
      ec
    )
  }

  /** Instantiate public key from a `CryptoKey`-format public key */
  public static async fromWebCrypto(publicKey: CryptoKey): Promise<PublicKey> {
    if (publicKey.extractable === false) {
      throw ERRORS.KEY_UNEXTRACTABLE
    }
    const ec = new EC(ELLIPTIC_CURVE)

    const extractedArrayBuffer = await crypto.subtle.exportKey(KEY_FORMAT.SPKI, publicKey)
    const extractedDecoded = arrayToString(extractedArrayBuffer)
    const derHex = Buffer.from(extractedDecoded, 'binary').toString('hex')
    const publicKeyHex = derHex.replace(DER_HEX_PREFIX_PUBLIC, '')
    const publicKeyEc = ec.keyFromPublic(publicKeyHex, 'hex')
    return PublicKey.fromElliptic(publicKeyEc, KeyType.r1, ec)
  }

  /** Export public key as EOSIO-format public key */
  public toString(): string {
    return publicKeyToString(this.key)
  }

  /** Export public key as Legacy EOSIO-format public key */
  public toLegacyString(): string {
    return publicKeyToLegacyString(this.key)
  }

  /** Export public key as `elliptic`-format public key */
  public toElliptic(): EC.KeyPair {
    return this.ec.keyPair({
      pub: Buffer.from(this.key.data),
    })
  }

  /** Export public key as `CryptoKey`-format public key */
  public async toWebCrypto(extractable = false): Promise<CryptoKey> {
    const publicKeyEc = this.toElliptic()
    const publicKeyHex = publicKeyEc.getPublic('hex')

    const derHex = `${DER_HEX_PREFIX_PUBLIC}${publicKeyHex}`
    const derBase64 = Buffer.from(derHex, 'hex').toString('binary')
    const spkiArrayBuffer = stringToArray(derBase64)
    return await crypto.subtle.importKey(
      KEY_FORMAT.SPKI,
      spkiArrayBuffer,
      {
        name: ALGORITHM_NAME,
        namedCurve: ALGORITHM_CURVE,
      },
      extractable,
      [KEY_USAGE.VERIFY]
    )
  }

  /** Get key type from key */
  public getType(): KeyType {
    return this.key.type
  }

  /** Validate a public key */
  public isValid(): boolean {
    try {
      const ellipticPublicKey = this.toElliptic()
      const validationObj = ellipticPublicKey.validate()
      return validationObj.result
    } catch {
      return false
    }
  }
}
