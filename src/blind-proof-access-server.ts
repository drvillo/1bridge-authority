import { constants, createPublicKey, privateEncrypt, publicDecrypt, type KeyObject } from 'node:crypto'
import { decodeBase64Url, encodeBase64Url } from './encoding.js'
import { os2ip } from './blind-rsa.js'

const MODULUS_BYTES = 512

export function signBlindedProofAccess(blindedMessage: string, privateKey: KeyObject): string {
  if (!privateKey || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'rsa') throw new TypeError('Expected dedicated generic RSA private key')
  const details = privateKey.asymmetricKeyDetails
  if (details?.modulusLength !== 4096 || details.publicExponent !== 65537n) throw new TypeError('Expected RSA-4096/65537 private key')
  const publicKey = createPublicKey(privateKey)
  const jwk = publicKey.export({ format: 'jwk' })
  if (typeof jwk.n !== 'string') throw new TypeError('Expected public RSA modulus')
  const modulus = os2ip(decodeBase64Url(jwk.n, MODULUS_BYTES))
  if (modulus.toString(2).length !== 4096) throw new TypeError('Expected 4096-bit modulus')
  const input = decodeBase64Url(blindedMessage, MODULUS_BYTES)
  if (input.length !== MODULUS_BYTES) throw new TypeError('Expected fixed-width blinded representative')
  const representative = os2ip(input)
  if (representative === 0n || representative >= modulus) throw new RangeError('Blinded representative out of range')
  const signature = privateEncrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, input)
  const recovered = publicDecrypt({ key: publicKey, padding: constants.RSA_NO_PADDING }, signature)
  if (signature.length !== MODULUS_BYTES || recovered.length !== MODULUS_BYTES || !recovered.equals(input)) throw new Error('RSA private operation self-check failed')
  return encodeBase64Url(signature)
}
