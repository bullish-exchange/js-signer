import { generateKeyPair, generateWebCryptoKeyPair, generateWebCryptoStringKeyPair } from './keyUtils'

import { KeyType } from '../config'
import { ALGORITHM_CURVE, ALGORITHM_NAME, ERROR_TEXT, KEY_TYPE, KEY_USAGE } from '../constant'
import { PrivateKey, PublicKey } from '../keys'

describe('generateWebCryptoKeyPair', () => {
  const name = ALGORITHM_NAME
  const namedCurve = ALGORITHM_CURVE
  const algorithm = { name, namedCurve }

  it('generate a private and public key pair', async () => {
    const { privateKey, publicKey } = await generateWebCryptoKeyPair(true)

    expect(privateKey.type).toEqual(KEY_TYPE.PRIVATE)
    expect(privateKey.extractable).toBeTruthy()
    expect(privateKey.algorithm).toEqual(algorithm)
    expect(privateKey.usages).toEqual([KEY_USAGE.SIGN])

    expect(publicKey.type).toEqual(KEY_TYPE.PUBLIC)
    expect(publicKey.extractable).toBeTruthy()
    expect(publicKey.algorithm).toEqual(algorithm)
    expect(publicKey.usages).toEqual([KEY_USAGE.VERIFY])
  })

  it('generate a private and public key pair non extractable', async () => {
    const { privateKey, publicKey } = await generateWebCryptoKeyPair()

    expect(privateKey.type).toEqual(KEY_TYPE.PRIVATE)
    expect(privateKey.extractable).toBeFalsy()
    expect(privateKey.algorithm).toEqual(algorithm)
    expect(privateKey.usages).toEqual([KEY_USAGE.SIGN])

    expect(publicKey.type).toEqual(KEY_TYPE.PUBLIC)
    expect(publicKey.extractable).toBeTruthy()
    expect(publicKey.algorithm).toEqual(algorithm)
    expect(publicKey.usages).toEqual([KEY_USAGE.VERIFY])
  })

  it('generate a private and public key pair with usages', async () => {
    const { privateKey, publicKey } = await generateWebCryptoKeyPair(true)
    expect(privateKey.usages.length).toEqual(1)
    expect(privateKey.usages[0]).toEqual(KEY_USAGE.SIGN)
    expect(publicKey.usages.length).toEqual(1)
    expect(publicKey.usages[0]).toEqual(KEY_USAGE.VERIFY)
  })

  it('generate a private and public key pair with no usages', async () => {
    const { privateKey, publicKey } = await generateWebCryptoKeyPair(false, [])
    expect(privateKey.usages.length).toEqual(0)
    expect(publicKey.usages.length).toEqual(0)
  })

  it('fails to convert private non-extractable CryptoKey to PrivateKey', async () => {
    const { privateKey } = await generateWebCryptoKeyPair()
    const convertPrivateKey = async (priv: CryptoKey) => {
      return await PrivateKey.fromWebCrypto(priv)
    }
    await expect(async () => convertPrivateKey(privateKey)).rejects.toThrow(
      Error(ERROR_TEXT.KEY_UNEXTRACTABLE)
    )
  })

  it('converts public extractable CryptoKey to PublicKey', async () => {
    const { publicKey } = await generateWebCryptoKeyPair(true)
    const pub = await PublicKey.fromWebCrypto(publicKey)
    expect(pub).toBeInstanceOf(PublicKey)
  })
})

describe('generateKeyPair', () => {
  it('throws error with no options.secureEnv variable for K1', () => {
    expect(() => generateKeyPair(KeyType.k1)).toThrow(Error(ERROR_TEXT.INSECURE_ENV))
  })

  it('generates a private and public key pair for K1', () => {
    const { privateKey: priv, publicKey: pub } = generateKeyPair(KeyType.k1, { secureEnv: true })
    const privateKey = priv
    const publicKey = pub

    expect(privateKey).toBeInstanceOf(PrivateKey)
    expect(privateKey.isValid()).toBeTruthy()
    expect(publicKey).toBeInstanceOf(PublicKey)
    expect(publicKey.isValid()).toBeTruthy()
  })

  it('generates a private and public key pair for R1', () => {
    const { privateKey: priv, publicKey: pub } = generateKeyPair(KeyType.r1, { secureEnv: true })
    const privateKey = priv
    const publicKey = pub
    expect(privateKey).toBeInstanceOf(PrivateKey)
    expect(privateKey.isValid()).toBeTruthy()
    expect(publicKey).toBeInstanceOf(PublicKey)
    expect(publicKey.isValid()).toBeTruthy()
  })

  it('throws error with no options.secureEnv variable for R1', () => {
    expect(() => generateKeyPair(KeyType.r1)).toThrow(Error(ERROR_TEXT.INSECURE_ENV))
  })

  it('fails to convert public non-extractable CryptoKey to PublicKey', async () => {
    const { publicKey: pub } = generateKeyPair(KeyType.r1, { secureEnv: true })
    const publicKey = await pub.toWebCrypto(false)
    expect(publicKey.extractable).toBeFalsy()
    const convertPublicKey = async (pubKey: CryptoKey) => PublicKey.fromWebCrypto(pubKey)
    await expect(async () => convertPublicKey(publicKey)).rejects.toThrow(Error(ERROR_TEXT.KEY_UNEXTRACTABLE))
  })

  it('generate public & private key', async () => {
    const result = await generateWebCryptoStringKeyPair()

    expect(typeof result.privateKey).toBe('string')
    expect(typeof result.publicKey).toBe('string')
  })
})
