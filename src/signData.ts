import { sha256 } from './external'
import { PrivateKey } from './keys'

export const signData = (data: string, privateKey: string) => {
  const key = PrivateKey.fromString(privateKey)
  const dataHash = sha256().update(data).digest('hex')
  const signedData = key.sign(dataHash, false)
  return [signedData.toString()]
}
