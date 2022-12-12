import { Buffer } from 'buffer'
import { BNInput, ec as EC } from 'elliptic'

import { AbstractPrivateKey, WebCryptoSignatureData } from './key.config'
import { PublicKey } from './PublicKey'
import { Signature } from './Signature'

import { BufferEncoding, Key, KeyType } from '../config'
import {
  ALGORITHM_CURVE,
  ALGORITHM_HASH,
  ALGORITHM_NAME,
  ELLIPTIC_CURVE,
  ELLIPTIC_CURVE_K1,
  ERRORS,
  KEY_FORMAT,
  KEY_USAGE,
} from '../constant'
import {
  arrayToString,
  privateKeyToLegacyString,
  privateKeyToString,
  stringToArray,
  stringToPrivateKey,
} from '../numeric'
import { subtle } from '../subtle'

const DER_HEX_PREFIX = '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420'
const DER_HEX_SEPERATOR = 'a144034200'

/** Represents/stores a private key and provides easy conversion for use with `elliptic` lib */
export class PrivateKey implements AbstractPrivateKey {
  constructor(private key: Key, private ec: EC) {}

  /** Instantiate private key from an `elliptic`-format private key */
  public static fromElliptic(privKey: EC.KeyPair, keyType: KeyType, ec?: EC): PrivateKey {
    if (!ec) {
      if (keyType === KeyType.k1) {
        ec = new EC(ELLIPTIC_CURVE_K1)
      } else {
        ec = new EC(ELLIPTIC_CURVE)
      }
    }
    return new PrivateKey(
      {
        type: keyType,
        data: privKey.getPrivate().toArrayLike(Buffer, 'be', 32),
      },
      ec
    )
  }

  /** Instantiate private key from a `CryptoKey`-format private key */
  public static async fromWebCrypto(privKey: CryptoKey): Promise<PrivateKey> {
    if (privKey.extractable === false) {
      throw ERRORS.KEY_UNEXTRACTABLE
    }
    const ec = new EC(ELLIPTIC_CURVE)

    const extractedArrayBuffer = await subtle.exportKey(KEY_FORMAT.PKCS8, privKey)
    const extractedDecoded = arrayToString(extractedArrayBuffer)
    const derHex = Buffer.from(extractedDecoded, 'binary').toString('hex')
    let privateKeyHex = derHex.replace(DER_HEX_PREFIX, '')
    privateKeyHex = privateKeyHex.substring(0, privateKeyHex.indexOf(DER_HEX_SEPERATOR))
    const privateKeyEc = ec.keyFromPrivate(privateKeyHex, 'hex')
    return PrivateKey.fromElliptic(privateKeyEc, KeyType.r1, ec)
  }

  /** Instantiate private key from an Bullish-format private key */
  public static fromString(keyString: string, ec?: EC): PrivateKey {
    const privateKey = stringToPrivateKey(keyString)
    if (!ec) {
      if (privateKey.type === KeyType.k1) {
        ec = new EC(ELLIPTIC_CURVE_K1)
      } else {
        ec = new EC(ELLIPTIC_CURVE)
      }
    }
    return new PrivateKey(privateKey, ec)
  }

  /** Export private key as `elliptic`-format private key */
  public toElliptic(): EC.KeyPair {
    return this.ec.keyFromPrivate(this.key.data)
  }

  /** Export private key as `CryptoKey`-format private key */
  public async toWebCrypto(extractable = false): Promise<CryptoKey> {
    const privateKeyEc = this.toElliptic()
    const privateKeyHex = privateKeyEc.getPrivate('hex')
    const publicKey = this.getPublicKey()
    const publicKeyEc = publicKey.toElliptic()
    const publicKeyHex = publicKeyEc.getPublic('hex')

    const derHex = `${DER_HEX_PREFIX}${privateKeyHex}${DER_HEX_SEPERATOR}${publicKeyHex}`
    const derBinary = Buffer.from(derHex, 'hex').toString('binary')
    const pkcs8ArrayBuffer = stringToArray(derBinary)
    return await subtle.importKey(
      KEY_FORMAT.PKCS8,
      pkcs8ArrayBuffer,
      {
        name: ALGORITHM_NAME,
        namedCurve: ALGORITHM_CURVE,
      },
      extractable,
      [KEY_USAGE.SIGN]
    )
  }

  public toLegacyString(): string {
    return privateKeyToLegacyString(this.key)
  }

  /** Export private key as Bullish-format private key */
  public toString(): string {
    return privateKeyToString(this.key)
  }

  /** Get key type from key */
  public getType(): KeyType {
    return this.key.type
  }

  /** Retrieve the public key from a private key */
  public getPublicKey(): PublicKey {
    const ellipticPrivateKey = this.toElliptic()
    return PublicKey.fromElliptic(ellipticPrivateKey, this.getType(), this.ec)
  }

  /** Sign a message or hashed message digest with private key */
  public sign(data: BNInput, shouldHash = true, encoding: BufferEncoding = 'utf8'): Signature {
    if (shouldHash) {
      if (typeof data === 'string') {
        data = Buffer.from(data, encoding)
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      data = this.ec.hash().update(data).digest()
    }
    let tries = 0
    let signature: Signature
    const isCanonical = (sigData: Uint8Array): boolean =>
      !(sigData[1] & 0x80) &&
      !(sigData[1] === 0 && !(sigData[2] & 0x80)) &&
      !(sigData[33] & 0x80) &&
      !(sigData[33] === 0 && !(sigData[34] & 0x80))
    const constructSignature = (options: EC.SignOptions): Signature => {
      const ellipticPrivateKey = this.toElliptic()
      const ellipticSignature = ellipticPrivateKey.sign(data, options)
      return Signature.fromElliptic(ellipticSignature, this.getType(), this.ec)
    }

    if (this.key.type === KeyType.k1) {
      do {
        signature = constructSignature({ canonical: true, pers: [++tries] })
      } while (!isCanonical(signature.toBinary()))
    } else {
      signature = constructSignature({ canonical: true })
    }
    return signature
  }

  /** Use Web Crypto to sign data (that matches types) with private CryptoKey */
  public async webCryptoSign(data: WebCryptoSignatureData): Promise<Signature> {
    const publicKey = this.getPublicKey()
    const privWebCrypto = await this.toWebCrypto()

    const algorithm: EcdsaParams = {
      name: ALGORITHM_NAME,
      hash: {
        name: ALGORITHM_HASH,
      },
    }

    const webCryptoSig = await subtle.sign(algorithm, privWebCrypto, data)

    return Signature.fromWebCrypto(data, webCryptoSig, publicKey)
  }

  /** Validate a private key */
  public isValid(): boolean {
    try {
      const ellipticPrivateKey = this.toElliptic()
      const validationObj = ellipticPrivateKey.validate()
      return validationObj.result
    } catch {
      return false
    }
  }
}
