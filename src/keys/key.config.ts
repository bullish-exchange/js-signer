import BN from 'bn.js'
import { BNInput, ec as EC } from 'elliptic'

import { BufferEncoding, KeyType } from '../config'

export type WebCryptoSignatureData =
  | Int8Array
  | Int16Array
  | Int32Array
  | Uint8Array
  | Uint16Array
  | Uint32Array
  | Uint8ClampedArray
  | Float32Array
  | Float64Array
  | DataView
  | ArrayBuffer

// Class definition for Public Key Class
export abstract class AbstractPublicKey {
  public static fromString: (publicKeyStr: string, ec?: EC) => AbstractPublicKey
  public static fromElliptic: (publicKey: EC.KeyPair, keyType: KeyType, ec?: EC) => AbstractPublicKey
  public static fromWebCrypto: (publicKey: CryptoKey) => Promise<AbstractPublicKey>
  public abstract toString: () => string
  public abstract toLegacyString: () => string
  public abstract isValid: () => boolean
  public abstract toElliptic: () => EC.KeyPair
  public abstract toWebCrypto: (extractable?: boolean) => Promise<CryptoKey>
  public abstract getType: () => KeyType
}

// Class definition for Private Key Class
export abstract class AbstractPrivateKey extends AbstractPublicKey {
  public abstract getPublicKey: () => AbstractPublicKey
  public abstract sign: (data: BNInput, shouldHash?: boolean, encoding?: BufferEncoding) => AbstractSignature
  public abstract webCryptoSign: (data: WebCryptoSignatureData) => Promise<AbstractSignature>
}

// Class definition for Signature Class
export abstract class AbstractSignature {
  public static fromString: (sig: string, ec?: EC) => AbstractSignature
  public static fromElliptic: (
    ellipticSig: EC.Signature | { r: BN; s: BN; recoveryParam: number | null },
    keyType: KeyType,
    ec?: EC
  ) => AbstractSignature
  public static fromWebCrypto: (publicKey: CryptoKey) => Promise<AbstractPublicKey>
  public abstract toElliptic: () => EC.SignatureOptions
  public abstract toString: () => string
  public abstract toBinary: () => Uint8Array
  public abstract getType: () => KeyType
  public abstract verify: (
    data: BNInput,
    publicKey: AbstractPublicKey,
    shouldHash: boolean,
    encoding: BufferEncoding
  ) => boolean
  public abstract webCryptoVerify: (
    data: WebCryptoSignatureData,
    webCryptoSig: ArrayBuffer,
    publicKey: AbstractPublicKey
  ) => Promise<boolean>
  public abstract recover: (data: BNInput, shouldHash: boolean, encoding: BufferEncoding) => AbstractPublicKey
}
