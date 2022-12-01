import { generateKeyPair } from './keyUtils'

import { KeyType } from '../config'
import { ALGORITHM_CURVE, ALGORITHM_NAME, KEY_USAGE } from '../constant'
import { crypto, EC } from '../external'
import { PrivateKey, Signature } from '../keys'

describe('PrivateKey', () => {
  describe('secp256k1', () => {
    const ec = new EC('secp256k1')
    const data = 'some string'

    const { privateKey, publicKey } = generateKeyPair(KeyType.r1, { secureEnv: true })

    it('retrieves the public key from a private key', () => {
      const pubKey = privateKey.getPublicKey()
      expect(pubKey.toString()).toEqual(publicKey.toString())
    })

    it('ensures private key elliptic conversion functions are consistent', () => {
      const { privateKey } = generateKeyPair(KeyType.k1, { secureEnv: true })
      const ellipticPrivKey = privateKey.toElliptic()
      const eosPrivKey = PrivateKey.fromElliptic(ellipticPrivKey, KeyType.k1)
      expect(eosPrivKey.toString()).toEqual(privateKey.toString())
    })

    it('ensures signature elliptic conversion functions are consistent', () => {
      const { privateKey } = generateKeyPair(KeyType.k1, { secureEnv: true })
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      const digest = ec.hash().update(data).digest()
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const signature = privateKey.sign(digest)

      const ellipticSig = signature.toElliptic() as EC.Signature
      const eosSig = Signature.fromElliptic(ellipticSig, KeyType.k1)
      expect(eosSig.toString()).toEqual(signature.toString())
    })

    it('ensures private key string conversion functions are consistent', () => {
      const privateKeyStr = privateKey.toString()
      const eosPrivKey = PrivateKey.fromString(privateKeyStr)
      expect(eosPrivKey.toString()).toEqual(privateKey.toString())
    })

    it('ensures signature string conversion functions are consistent', () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      const digest = ec.hash().update(data).digest()
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const signature = privateKey.sign(digest)

      const sigStr = signature.toString()
      const eosSig = Signature.fromString(sigStr)
      expect(eosSig.toString()).toEqual(signature.toString())
    })

    it('ensures private key string and legacy string conversion functions are consistent', () => {
      const privateKeyStr = privateKey.toString()
      const eosPrivKey = PrivateKey.fromString(privateKeyStr)
      expect(eosPrivKey.toString()).toEqual(privateKey.toString())
    })

    it('ensures elliptic sign, recover, verify flow works', () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      const digest = ec.hash().update(data).digest()
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const signature = privateKey.sign(digest)
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const recoveredPub = signature.recover(digest)

      expect(recoveredPub.toString()).toEqual(publicKey.toString())
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const valid = signature.verify(digest, recoveredPub)
      expect(valid).toBeTruthy()
    })

    it('Ensure elliptic sign, recover, verify flow works with shouldHash', () => {
      const signature = privateKey.sign(data, true)
      const recoveredPub = signature.recover(data, true)

      expect(recoveredPub.toString()).toEqual(publicKey.toString())
      const valid = signature.verify(data, recoveredPub, true)
      expect(valid).toBeTruthy()
    })

    it('Ensure elliptic sign, recover, verify flow works with shouldHash and encoding', () => {
      const signature = privateKey.sign(data, true, 'utf8')
      const recoveredPub = signature.recover(data, true, 'utf8')

      expect(recoveredPub.toString()).toEqual(publicKey.toString())
      const valid = signature.verify(data, recoveredPub, true, 'utf8')
      expect(valid).toEqual(true)
    })
  })

  describe('p256 elliptic', () => {
    const ec = new EC('secp256k1')
    const data = 'some string'

    const { privateKey, publicKey } = generateKeyPair(KeyType.r1, { secureEnv: true })

    it('retrieves the public key from a private key', () => {
      const pubKey = privateKey.getPublicKey()
      expect(pubKey.toString()).toEqual(publicKey.toString())
    })

    it('ensures private key elliptic conversion functions are consistent', () => {
      const ellipticPrivKey = privateKey.toElliptic()
      const eosPrivKey = PrivateKey.fromElliptic(ellipticPrivKey, KeyType.r1)
      expect(eosPrivKey.toString()).toEqual(privateKey.toString())
    })

    it('ensures signature elliptic conversion functions are consistent', () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      const digest = ec.hash().update(data).digest()
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const signature = privateKey.sign(digest)

      const ellipticSig = signature.toElliptic() as EC.Signature
      const eosSig = Signature.fromElliptic(ellipticSig, KeyType.r1)
      expect(eosSig.toString()).toEqual(signature.toString())
    })

    it('ensures private key string conversion functions are consistent', () => {
      const privateKeyStr = privateKey.toString()
      const eosPrivKey = PrivateKey.fromString(privateKeyStr)
      expect(eosPrivKey.toString()).toEqual(privateKey.toString())
    })

    it('ensures signature string conversion functions are consistent', () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      const digest = ec.hash().update(data).digest()
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const signature = privateKey.sign(digest)

      const sigStr = signature.toString()
      const eosSig = Signature.fromString(sigStr)
      expect(eosSig.toString()).toEqual(signature.toString())
    })

    it('ensures private key string and legacy string conversion functions are consistent', () => {
      const privateKeyStr = privateKey.toString()
      const eosPrivKey = PrivateKey.fromString(privateKeyStr)
      expect(eosPrivKey.toString()).toEqual(privateKey.toString())
    })
    it('ensures elliptic sign, recover, verify flow works', () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
      const digest = ec.hash().update(data).digest()
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const signature = privateKey.sign(digest)
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const recoveredPub = signature.recover(digest)

      expect(recoveredPub.toString()).toEqual(publicKey.toString())
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const valid = signature.verify(digest, recoveredPub)
      expect(valid).toBeTruthy()
    })

    it('Ensure elliptic sign, recover, verify flow works with shouldHash', () => {
      const signature = privateKey.sign(data, true)
      const recoveredPub = signature.recover(data, true)

      expect(recoveredPub.toString()).toEqual(publicKey.toString())
      const valid = signature.verify(data, recoveredPub, true)
      expect(valid).toBeTruthy()
    })

    it('Ensure elliptic sign, recover, verify flow works with shouldHash and encoding', () => {
      const signature = privateKey.sign(data, true, 'utf8')
      const recoveredPub = signature.recover(data, true, 'utf8')

      expect(recoveredPub.toString()).toEqual(publicKey.toString())
      const valid = signature.verify(data, recoveredPub, true, 'utf8')
      expect(valid).toEqual(true)
    })
  })

  describe('p256 WebCrypto', () => {
    it('converts private extractable CryptoKey to PrivateKey', async () => {
      const { privateKey } = await crypto.subtle.generateKey(
        {
          name: ALGORITHM_NAME,
          namedCurve: ALGORITHM_CURVE,
        },
        true,
        [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]
      )
      const priv = await PrivateKey.fromWebCrypto(privateKey)
      expect(priv).toBeInstanceOf(PrivateKey)
    })
  })

  it('confirm a keyPair constructed from elliptic can be converted reciprocally', async () => {
    const ec = new EC('p256')
    const keyPairEc = ec.genKeyPair()
    const privateKey = PrivateKey.fromElliptic(keyPairEc, KeyType.r1, ec)

    const webCryptoPriv = await privateKey.toWebCrypto(true)

    const exportedPrivateKey = await PrivateKey.fromWebCrypto(webCryptoPriv)

    expect(exportedPrivateKey.toString()).toEqual(privateKey.toString())
  })
  it('confirm a keyPair constructed from Web Crypto can be converted reciprocally', async () => {
    const ec = new EC('p256')
    const { privateKey } = await crypto.subtle.generateKey(
      {
        name: ALGORITHM_NAME,
        namedCurve: ALGORITHM_CURVE,
      },
      true,
      [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]
    )

    const priv = await PrivateKey.fromWebCrypto(privateKey)

    const privEc = priv.toElliptic()

    const exportedPrivateKey = PrivateKey.fromElliptic(privEc, KeyType.r1, ec)

    expect(exportedPrivateKey.toString()).toEqual(priv.toString())
  })

  it('Ensure Web Crypt sign, recover, verify flow works', async () => {
    const { privateKey } = await crypto.subtle.generateKey(
      {
        name: ALGORITHM_NAME,
        namedCurve: ALGORITHM_CURVE,
      },
      true,
      [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]
    )
    const priv = await PrivateKey.fromWebCrypto(privateKey)

    const dataAsString = 'some string'
    const enc = new TextEncoder()
    const encoded = enc.encode(dataAsString)

    const sig = await priv.webCryptoSign(encoded)
    const recoveredPub = sig.recover(encoded, true)

    expect(recoveredPub.isValid()).toBeTruthy()
    const valid = sig.verify(encoded, recoveredPub, true)
    expect(valid).toEqual(true)
  })
})
