import { ERRORS } from './../constant'
import { PrivateKey } from './PrivateKey'
import { PublicKey } from './PublicKey'

import { KeyType } from '../config'

export const isPublicKeyValid = (publicKey: string): boolean => {
  try {
    if (publicKey) {
      return PublicKey.fromString(publicKey).isValid()
    }
    return false
  } catch (err: unknown) {
    return false
  }
}

export const isPrivateKeyValid = (privateKey: string): boolean => {
  try {
    if (privateKey) {
      return PrivateKey.fromString(privateKey).isValid()
    }
    return false
  } catch (err: unknown) {
    return false
  }
}

export const getTypeFromPublicKeyString = (publicKey: string): KeyType => {
  if (!publicKey) {
    throw ERRORS.EXPECTED_STRING_CONTAINING_PUBLIC_KEY
  }
  try {
    return PublicKey.fromString(publicKey).getType()
  } catch (err: unknown) {
    throw ERRORS.KEY_UNEXTRACTABLE
  }
}
export const getTypeFromPrivateKeyString = (privateKey: string): KeyType => {
  if (!privateKey) {
    throw ERRORS.EXPECTED_STRING_CONTAINING_PRIVATE_KEY
  }

  try {
    return PrivateKey.fromString(privateKey).getType()
  } catch (err: unknown) {
    throw ERRORS.KEY_UNEXTRACTABLE
  }
}
