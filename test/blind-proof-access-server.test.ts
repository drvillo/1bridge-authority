import { createPrivateKey, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { importProofAccessPublicKey, blindProofAccess, finalizeProofAccess, verifyProofAccess } from '../src/index.js'
import vector from './fixtures/rfc9474-a1.json' with { type: 'json' }
import { modInverse } from '../src/blind-rsa.js'
import { signBlindedProofAccess } from '../src/blind-proof-access-server.js'

const b64 = (value: string) => Buffer.from(value, 'hex').toString('base64url')

function rfcPrivateKey() {
  const p = BigInt('0x' + vector.p)
  const q = BigInt('0x' + vector.q)
  const d = BigInt('0x' + vector.d)
  return createPrivateKey({ key: { kty: 'RSA', n: b64(vector.n), e: b64(vector.e), d: b64(vector.d), p: b64(vector.p), q: b64(vector.q), dp: b64((d % (p - 1n)).toString(16).padStart(512, '0')), dq: b64((d % (q - 1n)).toString(16).padStart(512, '0')), qi: b64(modInverse(q, p).toString(16).padStart(512, '0')) }, format: 'jwk' })
}

describe('Node blind proof-access signer', () => {
  it('matches the RFC 9474 Appendix A.1 blinded signature exactly', () => {
    expect(signBlindedProofAccess(b64(vector.blinded_msg), rfcPrivateKey())).toBe(b64(vector.blind_sig))
  })

  it('rejects malformed, zero and out-of-range representatives', () => {
    const key = rfcPrivateKey()
    for (const malformed of ['', '***', 'AA', b64('00'.repeat(512)), b64(vector.n), b64(vector.blinded_msg) + '=']) {
      expect(() => signBlindedProofAccess(malformed, key)).toThrow()
    }
  })

  it('rejects private keys outside the dedicated generic RSA profile', () => {
    const small = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 }).privateKey
    const pss = generateKeyPairSync('rsa-pss', { modulusLength: 4096, publicExponent: 65537 }).privateKey
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey
    for (const key of [small, pss, ec]) {
      expect(() => signBlindedProofAccess(b64(vector.blinded_msg), key)).toThrow()
    }
    const wrongExponent = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 3 }).privateKey
    expect(() => signBlindedProofAccess(b64(vector.blinded_msg), wrongExponent)).toThrow()
  })

  it('completes a request with a fresh generic RSA-4096 key', async () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 65537 })
    const spki = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    const publicKey = await importProofAccessPublicKey(spki)
    const request = await blindProofAccess(publicKey)
    const response = signBlindedProofAccess(request.blindedMessage, pair.privateKey)
    const token = await finalizeProofAccess(request.state, response)
    expect(await verifyProofAccess(token, publicKey)).toBe(true)
  })
})
