import { webcrypto } from 'crypto'

const isBrowser = typeof window !== 'undefined'

export const subtle = isBrowser ? window.crypto.subtle : webcrypto.subtle
