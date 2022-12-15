const isBrowser = typeof window !== 'undefined'
// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-var-requires
export const subtle = isBrowser ? window.crypto.subtle : (require('crypto').webcrypto.subtle as SubtleCrypto)
