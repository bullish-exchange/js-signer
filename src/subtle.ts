// window exists in envs like react-native so we also check for the presense of `subtle`. We can alias the "crypto" module in react-native with react-native-quick-crypto.
export const subtle =
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
  (typeof window !== 'undefined' && window.crypto?.subtle) || (require('crypto').subtle as SubtleCrypto)
