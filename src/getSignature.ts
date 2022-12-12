/**
 * This returns the signature on the assumption that nonce and timestamp were already generated.
 * This si required for authnz which expects nonce, timestamp as part of the payload to sign
 */

import { ALGORITHM_HASH, ALGORITHM_NAME } from './constant'
import { PrivateKey, PublicKey, Signature } from './keys'
import { subtle } from './subtle'

/**
 * @description generates signature for a given payload using the keys provided
 * - the private & public keys need to be added to the account using the web-platform
 * @param payload data for which signature has to be generated
 * @param publicKey public key in string format
 * @param privateKey private key either in string or crypto format
 * @returns signature for the payload
 */
export const getSignature = async <T = unknown>(
  payload: Record<string, T>,
  publicKey: string,
  privateKey: string | CryptoKey
) => {
  const enc = new TextEncoder()
  const message = JSON.stringify(payload)

  if (typeof privateKey !== 'string') {
    const messageBuffer = enc.encode(message)
    const webCryptoSig = await subtle.sign(
      { name: ALGORITHM_NAME, hash: ALGORITHM_HASH },
      privateKey,
      messageBuffer
    )
    const signature = await Signature.fromWebCrypto(
      messageBuffer,
      webCryptoSig,
      PublicKey.fromString(publicKey)
    )
    return signature.toString()
  }
  return PrivateKey.fromString(privateKey).sign(message, true).toString()
}
