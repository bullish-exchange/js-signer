/**
 * Just a function to pack it nicely so it is all centralized for the UI to use.
 */
export const getHeaders = (signature: string, timestamp: string, nonce: string) => {
  return {
    'BX-SIGNATURE': signature,
    'BX-TIMESTAMP': String(timestamp),
    'BX-NONCE': String(nonce),
  }
}
