import BN from 'bn.js'
import { Buffer } from 'buffer'
import { BNInput, ec as EC } from 'elliptic'

import { AbstractPublicKey, AbstractSignature, WebCryptoSignatureData } from './key.config'
import { PublicKey } from './PublicKey'

import { BufferEncoding, Key, KeyType } from '../config'
import { ALGORITHM_HASH, ALGORITHM_NAME, ELLIPTIC_CURVE, ELLIPTIC_CURVE_K1, ERRORS } from '../constant'
import { signatureToString, stringToSignature } from '../numeric'
import { subtle } from '../subtle'

/** Represents/stores a Signature and provides easy conversion for use with `elliptic` lib */
export class Signature implements AbstractSignature {
  constructor(private signature: Key, private ec: EC) {}

  /** Instantiate Signature from an Bullish-format Signature */
  public static fromString(sig: string, ec?: EC): Signature {
    const signature = stringToSignature(sig)
    if (!ec) {
      if (signature.type === KeyType.k1) {
        ec = new EC(ELLIPTIC_CURVE_K1)
      } else {
        ec = new EC(ELLIPTIC_CURVE)
      }
    }
    return new Signature(signature, ec)
  }

  /** Instantiate Signature from an `elliptic`-format Signature */
  public static fromElliptic(
    ellipticSig: EC.Signature | { r: BN; s: BN; recoveryParam: number | null },
    keyType: KeyType,
    ec?: EC
  ): Signature {
    const r = ellipticSig.r.toArray('be', 32)
    const s = ellipticSig.s.toArray('be', 32)
    const recoveryParam = ellipticSig.recoveryParam ?? 0
    let bullishRecoveryParam = 0
    if (keyType === KeyType.k1 || keyType === KeyType.r1) {
      bullishRecoveryParam = recoveryParam + 27
      if (recoveryParam <= 3) {
        bullishRecoveryParam += 4
      }
    } else if (keyType === KeyType.wa) {
      bullishRecoveryParam = recoveryParam
    }
    const sigData = new Uint8Array([bullishRecoveryParam].concat(r, s))
    if (!ec) {
      if (keyType === KeyType.k1) {
        ec = new EC(ELLIPTIC_CURVE_K1)
      } else {
        ec = new EC(ELLIPTIC_CURVE)
      }
    }
    return new Signature(
      {
        type: keyType,
        data: sigData,
      },
      ec
    )
  }

  /** Instantiate Signature from a Web Crypto Signature */
  public static async fromWebCrypto(
    data: WebCryptoSignatureData,
    webCryptoSig: ArrayBuffer,
    publicKey: PublicKey
  ) {
    const ec = new EC(ELLIPTIC_CURVE)

    const hash = await subtle.digest(ALGORITHM_HASH, data)
    const r = new BN(new Uint8Array(webCryptoSig.slice(0, 32)), 32)
    let s = new BN(new Uint8Array(webCryptoSig.slice(32)), 32)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    const halforder = ec.curve.n.ushrn(1) as BN // shift right 1 bit -- division by two
    if (s.ucmp(halforder) === 1) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      s = ec.curve.n.sub(s) as BN
    }
    const recoveryParam = this.getRecoveryParam(Buffer.from(hash), { r, s }, publicKey.toString(), ec)
    return Signature.fromElliptic({ r, s, recoveryParam }, KeyType.r1, ec)
  }

  /** Replaced version of getRecoveryParam from `elliptic` library */
  private static getRecoveryParam = (
    digest: BNInput,
    signature: EC.SignatureOptions,
    publicKey: string,
    ec: EC
  ) => {
    let recoveredKey: string
    for (let i = 0; i < 4; i++) {
      try {
        const keyPair = ec.recoverPubKey(digest, signature, i) as string
        recoveredKey = PublicKey.fromElliptic(ec.keyFromPublic(keyPair), KeyType.r1, ec).toString()
      } catch (e) {
        continue
      }
      if (recoveredKey === publicKey) {
        return i
      }
    }
    throw ERRORS.INVALID_RECOVERY_FACTOR
  }

  /** Export Signature as `elliptic`-format Signature
   * NOTE: This isn't an actual elliptic-format Signature, as ec.Signature is not exported by the library.
   * That's also why the return type is `any`.  We're *actually* returning an object with the 3 params
   * not an ec.Signature.
   * Further NOTE: @types/elliptic shows ec.Signature as exported; it is *not*.  Hence the `any`.
   */
  public toElliptic(): EC.SignatureOptions {
    const lengthOfR = 32
    const lengthOfS = 32
    const r = new BN(this.signature.data.slice(1, lengthOfR + 1))
    const s = new BN(this.signature.data.slice(lengthOfR + 1, lengthOfR + lengthOfS + 1))

    let ellipticRecoveryBitField = 0
    if (this.signature.type === KeyType.k1 || this.signature.type === KeyType.r1) {
      ellipticRecoveryBitField = this.signature.data[0] - 27
      if (ellipticRecoveryBitField > 3) {
        ellipticRecoveryBitField -= 4
      }
    } else if (this.signature.type === KeyType.wa) {
      ellipticRecoveryBitField = this.signature.data[0]
    }
    const recoveryParam = ellipticRecoveryBitField & 3
    return { r, s, recoveryParam }
  }

  /** Export Signature as Bullish-format Signature */
  public toString(): string {
    return signatureToString(this.signature)
  }

  /** Export Signature in binary format */
  public toBinary(): Uint8Array {
    return this.signature.data
  }

  /** Get key type from signature */
  public getType(): KeyType {
    return this.signature.type
  }

  /** Verify a signature with a message or hashed message digest and public key */
  public verify(
    data: BNInput,
    publicKey: AbstractPublicKey,
    shouldHash = true,
    encoding: BufferEncoding = 'utf8'
  ): boolean {
    if (shouldHash) {
      if (typeof data === 'string') {
        data = Buffer.from(data, encoding)
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      data = this.ec.hash().update(data).digest()
    }
    const ellipticSignature = this.toElliptic()
    const ellipticPublicKey = publicKey.toElliptic()
    return this.ec.verify(data, ellipticSignature, ellipticPublicKey, encoding)
  }

  /** Verify a Web Crypto signature with data (that matches types) and public key */
  public async webCryptoVerify(
    data: WebCryptoSignatureData,
    webCryptoSig: ArrayBuffer,
    publicKey: AbstractPublicKey
  ): Promise<boolean> {
    const webCryptoPub = await publicKey.toWebCrypto()
    return await subtle.verify(
      {
        name: ALGORITHM_NAME,
        hash: {
          name: ALGORITHM_HASH,
        },
      },
      webCryptoPub,
      webCryptoSig,
      data
    )
  }

  /** Recover a public key from a message or hashed message digest and signature */
  public recover(data: BNInput, shouldHash = true, encoding: BufferEncoding = 'utf8'): PublicKey {
    if (shouldHash) {
      if (typeof data === 'string') {
        data = Buffer.from(data, encoding)
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      data = this.ec.hash().update(data).digest()
    }
    const ellipticSignature = this.toElliptic()
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const recoveredPublicKey = this.ec.recoverPubKey(
      data,
      ellipticSignature,
      ellipticSignature.recoveryParam as number,
      encoding
    ) as string
    const ellipticKPub = this.ec.keyFromPublic(recoveredPublicKey)
    return PublicKey.fromElliptic(ellipticKPub, this.getType(), this.ec)
  }
}
