import { ec as EC } from 'elliptic'

import { generateKeyPair } from './keyUtils'
import { PrivateKey } from './PrivateKey'
import { PublicKey } from './PublicKey'

import { KeyType } from '../config'
import { ALGORITHM_CURVE, ALGORITHM_NAME, ELLIPTIC_CURVE, KEY_USAGE } from '../constant'

const { subtle } = globalThis.crypto

describe('Elliptic Curve Cryptography', () => {
  describe('secp256k1', () => {
    const { publicKey } = generateKeyPair(KeyType.r1, { secureEnv: true })

    it('ensures public key elliptic conversion functions are consistent', () => {
      const { publicKey } = generateKeyPair(KeyType.k1, { secureEnv: true })
      const ellipticPubKey = publicKey.toElliptic()
      const bullishPubKey = PublicKey.fromElliptic(ellipticPubKey, KeyType.k1)
      expect(bullishPubKey.toString()).toEqual(publicKey.toString())
    })

    it('ensures public key string conversion functions are consistent', () => {
      const publicKeyStr = publicKey.toString()
      const bullishPubKey = PublicKey.fromString(publicKeyStr)
      expect(bullishPubKey.toString()).toEqual(publicKey.toString())
    })

    it('ensures public key string and legacy string conversion functions are consistent', () => {
      const publicKeyStr = publicKey.toString()
      const bullishPubKey = PublicKey.fromString(publicKeyStr)
      expect(bullishPubKey.toString()).toEqual(publicKey.toString())
    })
  })

  describe('p256 elliptic', () => {
    const { publicKey } = generateKeyPair(KeyType.r1, { secureEnv: true })

    it('ensures public key elliptic conversion functions are consistent', () => {
      const ellipticPubKey = publicKey.toElliptic()
      const bullishPubKey = PublicKey.fromElliptic(ellipticPubKey, KeyType.r1)
      expect(bullishPubKey.toString()).toEqual(publicKey.toString())
    })

    it('ensures public key string conversion functions are consistent', () => {
      const publicKeyStr = publicKey.toString()
      const bullishPubKey = PublicKey.fromString(publicKeyStr)
      expect(bullishPubKey.toString()).toEqual(publicKey.toString())
    })

    it('ensures public key string and legacy string conversion functions are consistent', () => {
      const publicKeyStr = publicKey.toString()
      const bullishPubKey = PublicKey.fromString(publicKeyStr)
      expect(bullishPubKey.toString()).toEqual(publicKey.toString())
    })
  })

  describe('p256 WebCrypto', () => {
    it('confirm a keyPair constructed from elliptic can be converted reciprocally', async () => {
      const ec = new EC(ELLIPTIC_CURVE)
      const keyPairEc = ec.genKeyPair()
      const publicKey = PublicKey.fromElliptic(keyPairEc, KeyType.r1, ec)

      const webCryptoPub = await publicKey.toWebCrypto(true)

      const exportedPublicKey = await PublicKey.fromWebCrypto(webCryptoPub)

      expect(exportedPublicKey.toString()).toEqual(publicKey.toString())
      expect(publicKey.isValid()).toBeTruthy()
      expect(exportedPublicKey.isValid()).toBeTruthy()
    })

    it('confirm a keyPair constructed from Web Crypto can be converted reciprocally', async () => {
      const ec = new EC(ELLIPTIC_CURVE)
      const { publicKey } = await subtle.generateKey(
        {
          name: ALGORITHM_NAME,
          namedCurve: ALGORITHM_CURVE,
        },
        true,
        [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]
      )

      const pub = await PublicKey.fromWebCrypto(publicKey)

      const pubEc = pub.toElliptic()

      const exportedPublicKey = PublicKey.fromElliptic(pubEc, KeyType.r1, ec)

      expect(exportedPublicKey.toString()).toEqual(pub.toString())
      expect(pub.isValid()).toBeTruthy()
      expect(exportedPublicKey.isValid()).toBeTruthy()
    })

    it('Ensure Web Crypt sign, recover, verify flow works', async () => {
      const { privateKey, publicKey } = await subtle.generateKey(
        {
          name: ALGORITHM_NAME,
          namedCurve: ALGORITHM_CURVE,
        },
        true,
        [KEY_USAGE.SIGN, KEY_USAGE.VERIFY]
      )
      const priv = await PrivateKey.fromWebCrypto(privateKey)
      const pub = await PublicKey.fromWebCrypto(publicKey)

      const dataAsString = 'some string'
      const enc = new TextEncoder()
      const encoded = enc.encode(dataAsString)

      const sig = await priv.webCryptoSign(encoded)
      const recoveredPub = sig.recover(encoded, true)

      expect(recoveredPub.toString()).toEqual(pub.toString())
      expect(recoveredPub.isValid()).toBeTruthy()
      const valid = sig.verify(encoded, recoveredPub, true)
      expect(valid).toEqual(true)
    })
  })
})
