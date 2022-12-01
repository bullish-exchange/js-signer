import { PrivateKey, PublicKey } from './keys'
import { generateWebCryptoKeyPair } from './keys/keyUtils'

/**
 * @description generate api keys
 * - api keys once generated should be added to your account
 * - once the api keys are added, it can be used to sign request
 * - backend will be able to verify request using the signature added to header
 * @returns
 */
export const getApiKeys = async (extractable = true) => {
  const { privateKey, publicKey } = await generateWebCryptoKeyPair(extractable)
  const publicKeyString = (await PublicKey.fromWebCrypto(publicKey)).toString()
  const privateKeyString = (await PrivateKey.fromWebCrypto(privateKey)).toString()

  return {
    publicKey: publicKeyString,
    privateKey: privateKeyString,
  }
}
