import { createPrivateKey, createPublicKey } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import vector from './fixtures/rfc9474-a1.json' with { type: 'json' }
import * as authority from '../src/index.js'
import { blindRsa, emsaPssEncode, i2osp, modInverse, os2ip } from '../src/blind-rsa.js'
import { signBlindedProofAccess } from '../src/blind-proof-access-server.js'

const hex = (value: string) => new Uint8Array(Buffer.from(value, 'hex'))
const b64 = (value: string) => Buffer.from(value, 'hex').toString('base64url')
const publicKeyObject = createPublicKey({ key: { kty: 'RSA', n: b64(vector.n), e: b64(vector.e) }, format: 'jwk' })
const publicSpki = publicKeyObject.export({ type: 'spki', format: 'der' }).toString('base64url')
const modulus = BigInt('0x' + vector.n)

async function importedKey() {
  return authority.importProofAccessPublicKey(publicSpki)
}

describe('RFC 9474 Appendix A.1 arithmetic', () => {
  it('matches preparation, PSS encoding and blinding byte for byte', async () => {
    expect(vector.msg_prefix + vector.msg).toBe(vector.prepared_msg)
    const encoded = await emsaPssEncode(hex(vector.prepared_msg), hex(vector.salt), 4095)
    expect(Buffer.from(encoded).toString('hex')).toBe(vector.encoded_msg)
    const r = modInverse(BigInt('0x' + vector.inv), modulus)
    const result = await blindRsa(modulus, 65537n, hex(vector.prepared_msg), hex(vector.salt), () => hex(r.toString(16).padStart(1024, '0')))
    expect(Buffer.from(result.blindedMessage).toString('hex')).toBe(vector.blinded_msg)
    expect(result.inverse.toString(16).padStart(1024, '0')).toBe(vector.inv)
    const signature = i2osp(os2ip(hex(vector.blind_sig)) * result.inverse % modulus, 512)
    expect(Buffer.from(signature).toString('hex')).toBe(vector.sig)
    const key = await importedKey()
    expect(await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 48 }, key, new Uint8Array(signature), new Uint8Array(hex(vector.prepared_msg)))).toBe(true)
  })

  it('rejects out-of-range samples and retries noninvertible factors', async () => {
    const samples = [new Uint8Array(512), hex(vector.n), hex((modulus + 1n).toString(16).padStart(1024, '0')), hex(vector.p.padStart(1024, '0')), hex('01'.padStart(1024, '0'))]
    let reads = 0
    const result = await blindRsa(modulus, 65537n, hex(vector.prepared_msg), hex(vector.salt), () => samples[reads++]!)
    expect(reads).toBe(5)
    expect(result.inverse).toBe(1n)
    expect(result.blindedMessage).toEqual(hex(vector.encoded_msg))
  })
})

describe('proof access browser API', () => {
  it('imports only the fixed verify-only public key profile', async () => {
    const key = await importedKey()
    expect(key.type).toBe('public')
    expect(key.usages).toEqual(['verify'])
    expect(key.algorithm).toMatchObject({ name: 'RSA-PSS', modulusLength: 4096, hash: { name: 'SHA-384' } })
    await expect(authority.importProofAccessPublicKey(publicSpki + '=')).rejects.toThrow()
    const small = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384' }, true, ['sign', 'verify'])
    await expect(authority.importProofAccessPublicKey(Buffer.from(await crypto.subtle.exportKey('spki', small.publicKey)).toString('base64url'))).rejects.toThrow()
    const wrongExponent = createPublicKey({ key: { kty: 'RSA', n: b64(vector.n), e: b64('03') }, format: 'jwk' })
    await expect(authority.importProofAccessPublicKey(wrongExponent.export({ type: 'spki', format: 'der' }).toString('base64url'))).rejects.toThrow()
    const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    await expect(authority.importProofAccessPublicKey(Buffer.from(await crypto.subtle.exportKey('spki', ec.publicKey)).toString('base64url'))).rejects.toThrow()
  })

  it('creates independent fixed-format requests and opaque one-use state', async () => {
    const key = await importedKey()
    const first = await authority.blindProofAccess(key)
    const second = await authority.blindProofAccess(key)
    expect(first.blindedMessage).not.toBe(second.blindedMessage)
    expect(Buffer.from(first.blindedMessage, 'base64url')).toHaveLength(512)
    expect(Object.isFrozen(first.state)).toBe(true)
    expect(Reflect.ownKeys(first.state)).toEqual([])
    expect(JSON.stringify(first.state)).toBe('{}')
    expect(authority.canonicalJson(first.state)).toBe('{}')
    const token = await authority.finalizeProofAccess(first.state, signBlindedProofAccess(first.blindedMessage, privateKey()))
    expect(Object.keys(token).sort()).toEqual(['preparedMessage', 'signature'])
    expect(Buffer.from(token.preparedMessage, 'base64url')).toHaveLength(98)
    const prepared = Buffer.from(token.preparedMessage, 'base64url')
    expect(prepared.subarray(32, 66).toString()).toBe('1bridge.authority/v1/proof-access\n')
    expect(prepared.subarray(0, 32)).not.toEqual(prepared.subarray(66, 98))
    expect(Buffer.from(token.signature, 'base64url')).toHaveLength(512)
    expect(await authority.verifyProofAccess(token, key)).toBe(true)
    await expect(authority.finalizeProofAccess(first.state, signBlindedProofAccess(first.blindedMessage, privateKey()))).rejects.toThrow()
    const other = await authority.finalizeProofAccess(second.state, signBlindedProofAccess(second.blindedMessage, privateKey()))
    expect(other.preparedMessage).not.toBe(token.preparedMessage)
  })

  it('consumes state on a malformed response and rejects forged state', async () => {
    const key = await importedKey()
    const request = await authority.blindProofAccess(key)
    await expect(authority.finalizeProofAccess(request.state, '')).rejects.toThrow()
    await expect(authority.finalizeProofAccess(request.state, signBlindedProofAccess(request.blindedMessage, privateKey()))).rejects.toThrow()
    await expect(authority.finalizeProofAccess(Object.freeze({}) as never, '')).rejects.toThrow()
    const outOfRange = await authority.blindProofAccess(key)
    await expect(authority.finalizeProofAccess(outOfRange.state, b64(vector.n))).rejects.toThrow()
    await expect(authority.finalizeProofAccess(outOfRange.state, signBlindedProofAccess(outOfRange.blindedMessage, privateKey()))).rejects.toThrow()
  })

  it('rejects foreign keys and altered or malformed tokens', async () => {
    const key = await importedKey()
    const foreign = await crypto.subtle.importKey('spki', Buffer.from(publicSpki, 'base64url'), { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify'])
    await expect(authority.blindProofAccess(foreign)).rejects.toThrow()
    const request = await authority.blindProofAccess(key)
    const token = await authority.finalizeProofAccess(request.state, signBlindedProofAccess(request.blindedMessage, privateKey()))
    expect(await authority.verifyProofAccess(token, foreign)).toBe(false)
    const changedPrepared = Buffer.from(token.preparedMessage, 'base64url')
    changedPrepared[0] = changedPrepared[0]! ^ 1
    expect(await authority.verifyProofAccess({ ...token, preparedMessage: changedPrepared.toString('base64url') }, key)).toBe(false)
    const changedSignature = Buffer.from(token.signature, 'base64url')
    changedSignature[0] = changedSignature[0]! ^ 1
    expect(await authority.verifyProofAccess({ ...token, signature: changedSignature.toString('base64url') }, key)).toBe(false)
    for (const malformed of [{ ...token, extra: true }, { signature: token.signature }, { ...token, signature: token.signature + '=' }, Object.defineProperty({ preparedMessage: token.preparedMessage }, 'signature', { enumerable: true, get: () => token.signature })]) {
      expect(await authority.verifyProofAccess(malformed as never, key)).toBe(false)
    }
  })

  it('derives a domain-separated stable nullifier from validated prepared bytes', async () => {
    const key = await importedKey()
    const first = await authority.blindProofAccess(key)
    const second = await authority.blindProofAccess(key)
    const a = await authority.finalizeProofAccess(first.state, signBlindedProofAccess(first.blindedMessage, privateKey()))
    const b = await authority.finalizeProofAccess(second.state, signBlindedProofAccess(second.blindedMessage, privateKey()))
    expect(await authority.proofAccessNullifier(a)).toMatch(/^[0-9a-f]{64}$/)
    expect(await authority.proofAccessNullifier(a)).toBe(await authority.proofAccessNullifier(a))
    expect(await authority.proofAccessNullifier(a)).not.toBe(await authority.proofAccessNullifier(b))
    await expect(authority.proofAccessNullifier({ ...a, extra: true } as never)).rejects.toThrow()
    const oracle = await crypto.subtle.digest('SHA-256', Buffer.concat([Buffer.from('1bridge.authority/v1/proof-access-nullifier\n'), Buffer.from(a.preparedMessage, 'base64url')]))
    expect(await authority.proofAccessNullifier(a)).toBe(Buffer.from(oracle).toString('hex'))
  })

  it('snapshots token fields before asynchronous verification and hashing', async () => {
    const key = await importedKey()
    const request = await authority.blindProofAccess(key)
    const token = await authority.finalizeProofAccess(request.state, signBlindedProofAccess(request.blindedMessage, privateKey()))
    const mutable = { ...token }
    const verification = authority.verifyProofAccess(mutable, key)
    const nullifier = authority.proofAccessNullifier(mutable)
    mutable.preparedMessage = 'changed'
    mutable.signature = 'changed'
    expect(await verification).toBe(true)
    expect(await nullifier).toBe(await authority.proofAccessNullifier(token))
  })
})

// The RFC key is test-only and never enters the package build.
function privateKey() {
  const p = BigInt('0x' + vector.p)
  const q = BigInt('0x' + vector.q)
  const d = BigInt('0x' + vector.d)
  return createPrivateKey({ key: { kty: 'RSA', n: b64(vector.n), e: b64(vector.e), d: b64(vector.d), p: b64(vector.p), q: b64(vector.q), dp: b64((d % (p - 1n)).toString(16).padStart(512, '0')), dq: b64((d % (q - 1n)).toString(16).padStart(512, '0')), qi: b64(modInverse(q, p).toString(16).padStart(512, '0')) }, format: 'jwk' })
}
