import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import * as authority from '../src/index.js'

const fixture = { b: 2, a: 'x' }
const nativeMessage = new TextEncoder().encode('1bridge.authority/v1\napproval\n{"a":"x","b":2}')
let pair: CryptoKeyPair
let other: CryptoKeyPair
let p384: CryptoKeyPair
let hmac: CryptoKey
let emptyPublic: CryptoKey
let nonextractable: CryptoKeyPair
let nativePublic: Uint8Array
let nativePrivate: Uint8Array

async function nativePair(curve = 'P-256', extractable = true): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, extractable, ['sign', 'verify'])
}

beforeAll(async () => {
  pair = await nativePair()
  other = await nativePair()
  p384 = await nativePair('P-384')
  nonextractable = await nativePair('P-256', false)
  hmac = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify'])
  nativePublic = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
  nativePrivate = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  emptyPublic = await crypto.subtle.importKey('spki', new Uint8Array(nativePublic), { name: 'ECDSA', namedCurve: 'P-256' }, true, [])
})

describe('native P-256 signing keys', () => {
  it('exports only the requested signature functions', () => {
    for (const name of ['generateSigningKey', 'exportSigningPublicKey', 'importSigningPublicKey', 'exportSigningPrivateKey', 'importSigningPrivateKey', 'signingKeyId', 'signRecord', 'verifyRecord']) {
      expect(authority).toHaveProperty(name)
    }
    expect(authority).not.toHaveProperty('sha256')
  })

  it('generates dedicated extractable native P-256 keys', async () => {
    const generated = await authority.generateSigningKey()
    expect(generated.publicKey).toBeInstanceOf(CryptoKey)
    expect(generated.privateKey).toBeInstanceOf(CryptoKey)
    expect(generated.publicKey.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256' })
    expect(generated.privateKey.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256' })
    expect(generated.publicKey.type).toBe('public')
    expect(generated.privateKey.type).toBe('private')
    expect(generated.publicKey.usages).toEqual(['verify'])
    expect(generated.privateKey.usages).toEqual(['sign'])
    expect(generated.publicKey.extractable).toBe(true)
    expect(generated.privateKey.extractable).toBe(true)
  })

  it('roundtrips native canonical SPKI and secret PKCS8 encodings', async () => {
    const publicEncoded = await authority.exportSigningPublicKey(pair.publicKey)
    const privateEncoded = await authority.exportSigningPrivateKey(pair.privateKey)
    expect(authority.decodeBase64Url(publicEncoded)).toEqual(nativePublic)
    expect(Buffer.from(authority.decodeBase64Url(privateEncoded)).equals(Buffer.from(nativePrivate))).toBe(true)
    const publicKey = await authority.importSigningPublicKey(publicEncoded)
    const privateKey = await authority.importSigningPrivateKey(privateEncoded)
    expect(publicKey.extractable).toBe(true)
    expect(privateKey.extractable).toBe(true)
    expect(await authority.exportSigningPublicKey(publicKey)).toBe(publicEncoded)
    expect(await authority.exportSigningPrivateKey(privateKey) === privateEncoded).toBe(true)
    const signature = await authority.signRecord('approval', fixture, privateKey)
    expect(await authority.verifyRecord('approval', fixture, signature, publicKey)).toBe(true)
  })

  it('fingerprints the public-key LF domain followed by decoded SPKI', async () => {
    const expected = createHash('sha256').update('1bridge.authority/v1/public-key\n', 'utf8').update(nativePublic).digest('hex')
    expect(await authority.signingKeyId(pair.publicKey)).toBe(expected)
    expect(await authority.signingKeyId(other.publicKey)).not.toBe(expected)
    expect(expected).not.toBe(createHash('sha256').update(nativePublic).digest('hex'))
  })

  it('rejects wrong export key algorithms, curves, types and usage', async () => {
    for (const key of [pair.privateKey, p384.publicKey, hmac, emptyPublic, null, undefined, {}, { type: 'public', algorithm: { name: 'ECDSA', namedCurve: 'P-256' }, usages: ['verify'] }]) {
      await expect(authority.exportSigningPublicKey(key as CryptoKey)).rejects.toThrow()
      await expect(authority.signingKeyId(key as CryptoKey)).rejects.toThrow()
    }
    for (const key of [pair.publicKey, p384.privateKey, hmac, nonextractable.privateKey, null, {}, { type: 'private', algorithm: { name: 'ECDSA', namedCurve: 'P-256' }, usages: ['sign'] }]) {
      await expect(authority.exportSigningPrivateKey(key as CryptoKey)).rejects.toThrow()
    }
  })

  it('rejects malformed, empty, wrong-format and oversized key inputs', async () => {
    const p384Public = authority.encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey('spki', p384.publicKey)))
    const p384Private = authority.encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey('pkcs8', p384.privateKey)))
    const publicEncoded = authority.encodeBase64Url(nativePublic)
    const privateEncoded = authority.encodeBase64Url(nativePrivate)
    for (const encoded of ['', 'A', 'AA', 'Zg==', publicEncoded + '=', authority.encodeBase64Url(new Uint8Array(1025)), p384Public, privateEncoded, null, undefined, 1, {}]) {
      await expect(authority.importSigningPublicKey(encoded as string)).rejects.toThrow()
    }
    for (const encoded of ['', 'A', 'AA', 'Zg==', privateEncoded + '=', authority.encodeBase64Url(new Uint8Array(1025)), p384Private, publicEncoded, null, undefined, 1, {}]) {
      await expect(authority.importSigningPrivateKey(encoded as string)).rejects.toThrow()
    }
  })

  it('rejects SPKI with appended trailing data', async () => {
    const appended = new Uint8Array(nativePublic.length + 1)
    appended.set(nativePublic)
    // Some native runtimes accept trailing DER bytes; the profile requires re-export equality regardless.
    await expect(authority.importSigningPublicKey(authority.encodeBase64Url(appended))).rejects.toThrow()
  })

  it('requires native canonical SPKI even when a compressed point imports successfully', async () => {
    const compressed = new Uint8Array(59)
    compressed.set(nativePublic.subarray(0, 26))
    compressed[1] = 0x39
    compressed[24] = 0x22
    compressed[26] = 0x02 | (nativePublic[90]! & 1)
    compressed.set(nativePublic.subarray(27, 59), 27)
    const nativeImported = await crypto.subtle.importKey('spki', compressed, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
    expect(new Uint8Array(await crypto.subtle.exportKey('spki', nativeImported))).toEqual(nativePublic)
    await expect(authority.importSigningPublicKey(authority.encodeBase64Url(compressed))).rejects.toThrow('canonical native SPKI')
  })

  it('prebounds key import before native work', async () => {
    const imported = vi.spyOn(crypto.subtle, 'importKey')
    try {
      await expect(authority.importSigningPublicKey('A'.repeat(1367))).rejects.toThrow()
      await expect(authority.importSigningPrivateKey('A'.repeat(1367))).rejects.toThrow()
      expect(imported).not.toHaveBeenCalled()
    } finally {
      imported.mockRestore()
    }
  })
})

describe('domain-bound canonical record signatures', () => {
  it('produces a 64-byte IEEE-P1363 signature accepted on literal native message bytes', async () => {
    const signature = await authority.signRecord('approval', fixture, pair.privateKey)
    const bytes = authority.decodeBase64Url(signature)
    expect(bytes).toHaveLength(64)
    expect(signature).toMatch(/^[A-Za-z0-9_-]{86}$/)
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, new Uint8Array(bytes), nativeMessage)).toBe(true)
    const publicKey = createPublicKey({ key: Buffer.from(nativePublic), format: 'der', type: 'spki' })
    expect(verify('sha256', nativeMessage, { key: publicKey, dsaEncoding: 'ieee-p1363' }, bytes)).toBe(true)
  })

  it('accepts an independently native-produced signature on literal message bytes', async () => {
    const bytes = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, nativeMessage))
    expect(await authority.verifyRecord('approval', fixture, authority.encodeBase64Url(bytes), pair.publicKey)).toBe(true)
  })

  it('accepts an independently Node-produced IEEE-P1363 signature', async () => {
    const privateKey = createPrivateKey({ key: Buffer.from(nativePrivate), format: 'der', type: 'pkcs8' })
    const signature = sign('sha256', nativeMessage, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    expect(await authority.verifyRecord('approval', fixture, authority.encodeBase64Url(signature), pair.publicKey)).toBe(true)
  })

  it('rejects the same signature for a different purpose', async () => {
    const signature = await authority.signRecord('approval', fixture, pair.privateKey)
    expect(await authority.verifyRecord('receipt', fixture, signature, pair.publicKey)).toBe(false)
  })

  it('rejects an altered canonical record, key or signature', async () => {
    const signature = await authority.signRecord('approval', fixture, pair.privateKey)
    expect(await authority.verifyRecord('approval', { b: 3, a: 'x' }, signature, pair.publicKey)).toBe(false)
    expect(await authority.verifyRecord('approval', fixture, signature, other.publicKey)).toBe(false)
    const altered = authority.decodeBase64Url(signature)
    altered[0] = altered[0]! ^ 1
    expect(await authority.verifyRecord('approval', fixture, authority.encodeBase64Url(altered), pair.publicKey)).toBe(false)
  })

  it('canonicalizes record property order consistently', async () => {
    const signature = await authority.signRecord('approval', { b: 2, a: 'x' }, pair.privateKey)
    expect(await authority.verifyRecord('approval', { a: 'x', b: 2 }, signature, pair.publicKey)).toBe(true)
  })

  it('rejects DER signatures despite valid native P-256 material', async () => {
    const privateKey = createPrivateKey({ key: Buffer.from(nativePrivate), format: 'der', type: 'pkcs8' })
    const signature = sign('sha256', nativeMessage, privateKey)
    expect(await authority.verifyRecord('approval', fixture, authority.encodeBase64Url(signature), pair.publicKey)).toBe(false)
  })

  it.each(['', 'Approval', '1approval', 'approval\n', 'approval\r', 'approval\nreceipt', 'a'.repeat(65), 'é', null, 1, undefined])('rejects malformed purpose %s', async (purpose) => {
    await expect(authority.signRecord(purpose as string, fixture, pair.privateKey)).rejects.toThrow()
    expect(await authority.verifyRecord(purpose as string, fixture, authority.encodeBase64Url(new Uint8Array(64)), pair.publicKey)).toBe(false)
  })

  it('accepts both purpose length boundaries and the exact ASCII alphabet', async () => {
    for (const purpose of ['a', 'a'.repeat(64), 'approval.v1_2-3']) {
      const signature = await authority.signRecord(purpose, fixture, pair.privateKey)
      expect(await authority.verifyRecord(purpose, fixture, signature, pair.publicKey)).toBe(true)
    }
  })

  it('rejects malformed signatures without throwing', async () => {
    for (const signature of ['', 'A', 'AA', 'A'.repeat(85), 'A'.repeat(87), 'A'.repeat(86) + '=', 'A'.repeat(85) + 'B', 'A'.repeat(100000), 'A'.repeat(85) + '\n', null, undefined, 1, {}, new Uint8Array(64)]) {
      expect(await authority.verifyRecord('approval', fixture, signature as string, pair.publicKey)).toBe(false)
    }
  })

  it('rejects malformed records and wrong key profiles without throwing from verification', async () => {
    const signature = await authority.signRecord('approval', fixture, pair.privateKey)
    for (const record of [undefined, NaN, -0, { x: undefined }, new Date(), [null, undefined]]) {
      await expect(authority.signRecord('approval', record, pair.privateKey)).rejects.toThrow()
      expect(await authority.verifyRecord('approval', record, signature, pair.publicKey)).toBe(false)
    }
    for (const key of [pair.privateKey, p384.publicKey, hmac, emptyPublic, null, undefined, {}, { type: 'public', algorithm: { name: 'ECDSA', namedCurve: 'P-256' }, usages: ['verify'] }]) {
      expect(await authority.verifyRecord('approval', fixture, signature, key as CryptoKey)).toBe(false)
    }
    for (const key of [pair.publicKey, p384.privateKey, hmac, null, undefined, {}]) {
      await expect(authority.signRecord('approval', fixture, key as CryptoKey)).rejects.toThrow()
    }
  })

  it('permits native signing with nonextractable private material', async () => {
    const signature = await authority.signRecord('approval', fixture, nonextractable.privateKey)
    expect(await authority.verifyRecord('approval', fixture, signature, nonextractable.publicKey)).toBe(true)
  })

  it('snapshots the caller record before the first signing await', async () => {
    const record = { b: 2, a: 'x' }
    const pending = authority.signRecord('approval', record, pair.privateKey)
    record.b = 3
    const signature = await pending
    expect(await authority.verifyRecord('approval', fixture, signature, pair.publicKey)).toBe(true)
    expect(await authority.verifyRecord('approval', record, signature, pair.publicKey)).toBe(false)
  })

  it('snapshots the caller record before the first verifying await', async () => {
    const signature = await authority.signRecord('approval', fixture, pair.privateKey)
    const record = { b: 2, a: 'x' }
    const pending = authority.verifyRecord('approval', record, signature, pair.publicKey)
    record.b = 3
    expect(await pending).toBe(true)
  })

  it('prebounds malformed signature input before native verification', async () => {
    const verified = vi.spyOn(crypto.subtle, 'verify')
    try {
      expect(await authority.verifyRecord('approval', fixture, 'A'.repeat(100000), pair.publicKey)).toBe(false)
      expect(verified).not.toHaveBeenCalled()
    } finally {
      verified.mockRestore()
    }
  })
})
