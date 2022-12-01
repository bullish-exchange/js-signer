import BN from 'bn.js'
import { Buffer } from 'buffer'
import { webcrypto } from 'crypto'
import { BNInput, ec as EC } from 'elliptic'
import { sha256 } from 'hash.js'
import RIPEMD160 from 'ripemd160'

export const crypto = typeof window !== 'undefined' ? window.crypto : webcrypto

export { BN, BNInput, Buffer, EC, RIPEMD160, sha256 }
