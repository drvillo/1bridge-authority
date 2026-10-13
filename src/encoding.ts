const DEFAULT_MAX_BYTES = 1024 * 1024

export function encodeBase64Url(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Expected Uint8Array bytes')
  const snapshot = new Uint8Array(bytes)
  let binary = ''
  for (let index = 0; index < snapshot.length; index += 1) binary += String.fromCharCode(snapshot[index]!)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeBase64Url(encoded: string, maxBytes?: number): Uint8Array {
  const limit = arguments.length > 1 ? maxBytes : DEFAULT_MAX_BYTES
  if (typeof encoded !== 'string') throw new TypeError('Expected base64url string')
  if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 0) throw new TypeError('Expected nonnegative safe integer byte limit')
  if (encoded.length > Math.ceil(limit * 4 / 3)) throw new RangeError('Base64url exceeds decoded byte limit')
  if (encoded.length % 4 === 1 || /[^A-Za-z0-9_-]/.test(encoded)) throw new TypeError('Expected unpadded base64url alphabet')
  const binary = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'))
  if (binary.length > limit) throw new RangeError('Base64url exceeds decoded byte limit')
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  if (encodeBase64Url(bytes) !== encoded) throw new TypeError('Expected canonical base64url trailing bits')
  return bytes
}
