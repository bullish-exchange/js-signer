// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
export const subtle = window.crypto?.subtle || (require('crypto').subtle as SubtleCrypto)
