/** Key types this library supports */
export enum KeyType {
  k1 = 0,
  r1 = 1,
  wa = 2,
}

/** Public key, private key, or signature in binary form */
export interface Key {
  type: KeyType
  data: Uint8Array
}

export enum PvtKeyStringPrefix {
  K1 = 'PVT_K1_',
  R1 = 'PVT_R1_',
}
export enum PubKeyStringPrefix {
  K1 = 'PUB_K1_',
  R1 = 'PUB_R1_',
  WA = 'PUB_WA_',
}
export enum SignatureStringPrefix {
  K1 = 'SIG_K1_',
  R1 = 'SIG_R1_',
  WA = 'SIG_WA_',
}
export enum KeyStringSuffix {
  K1 = 'K1',
  R1 = 'R1',
  WA = 'WA',
}

export type BufferEncoding =
  | 'ascii'
  | 'utf8'
  | 'utf-8'
  | 'utf16le'
  | 'ucs2'
  | 'ucs-2'
  | 'base64'
  | 'base64url'
  | 'latin1'
  | 'binary'
  | 'hex'
