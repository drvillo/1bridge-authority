import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import * as library from '../src/index.js'

const api = library as unknown as Record<string, any>
const PUBLIC_KEY = 'v3.x25519.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA'
const KEY_ID = 'riFsLvUkejeCwTXvonmj5M3GEJQnD10r5YxiBLemEsk'
const VECTOR_HASH = '70fc6416d6c82ed81fa18f4ae499b25adfebee21bf6abca56596b42b3e56660c'
const claim = {
  version: 1, workspaceId: 'b'.repeat(64), membershipId: 'c'.repeat(64), membershipKeyRowId: 'd'.repeat(64),
  membershipKeyVersion: 7, keySuite: 'x25519', keyId: KEY_ID, publicKey: PUBLIC_KEY,
}

describe('recipient key claim v1', () => {
  it('matches the app wire helper envelope, fingerprint and independent domain-hash vector', async () => {
    expect(api).toHaveProperty('recipientKeyClaimHash')
    expect(await api.recipientKeyClaimHash(claim)).toBe(VECTOR_HASH)
    expect(await api.recipientKeyClaimHash(claim)).toBe(createHash('sha256')
      .update('1bridge.authority/v1/recipient-key\n').update(library.canonicalBytes(claim)).digest('hex'))
  })

  it('commits to the exact workspace, membership, row and row version', async () => {
    for (const changed of [
      { workspaceId: 'a'.repeat(64) }, { membershipId: 'a'.repeat(64) },
      { membershipKeyRowId: 'a'.repeat(64) }, { membershipKeyVersion: 8 },
    ]) expect(await api.recipientKeyClaimHash({ ...claim, ...changed })).not.toBe(VECTOR_HASH)
  })

  it('rejects invalid records, alternate wire encoding and mismatched fingerprints', async () => {
    const invalid = [
      (({ keyId: _removed, ...rest }) => rest)(claim),
      { ...claim, extra: 1 }, { ...claim, version: 2 }, { ...claim, workspaceId: 'B'.repeat(64) },
      { ...claim, membershipId: 'C'.repeat(64) }, { ...claim, membershipKeyRowId: 'D'.repeat(64) },
      { ...claim, membershipKeyVersion: 0 }, { ...claim, membershipKeyVersion: -0 },
      { ...claim, membershipKeyVersion: Number.MAX_SAFE_INTEGER + 1 },
      { ...claim, keySuite: 'v3.x25519' }, { ...claim, keyId: 'a'.repeat(43) },
      { ...claim, keyId: KEY_ID + '=' }, { ...claim, publicKey: PUBLIC_KEY + '=' },
      { ...claim, publicKey: PUBLIC_KEY.slice(0, -1) + 'B' },
      { ...claim, publicKey: 'v2.x25519.' + PUBLIC_KEY.slice(11) },
      { ...claim, publicKey: 'v3.x25519.' },
      { ...claim, publicKey: 'v3.x25519.' + 'A'.repeat(43) },
      { ...claim, publicKey: 'v3.x25519.' + 'A'.repeat(42) + '+' },
    ]
    for (const input of invalid) await expect(api.recipientKeyClaimHash(input)).rejects.toThrow()
    const accessor = { ...claim }
    let calls = 0
    Object.defineProperty(accessor, 'publicKey', { enumerable: true, get() { calls++; return PUBLIC_KEY } })
    await expect(api.recipientKeyClaimHash(accessor)).rejects.toThrow()
    expect(calls).toBe(0)
  })
})
