import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const audienceId = '01'.repeat(32)
const otherAudience = '02'.repeat(32)

function oracle(audience: string, canonical: string, salt: string): string {
  const value = Buffer.from(canonical, 'utf8')
  const length = Buffer.alloc(4)
  length.writeUInt32BE(value.length)
  return createHash('sha256')
    .update(Buffer.from([0x04]))
    .update(Buffer.from(audience, 'hex'))
    .update(Buffer.from(salt, 'base64url'))
    .update(length)
    .update(value)
    .digest('hex')
}

function freshOpening() {
  const handle = authority.createEvidenceSalt()
  return { handle, salt: authority.exportEvidenceSalt(handle) }
}

describe('evidence commitment', () => {
  it('rejects a predictable caller-supplied all-zero salt', async () => {
    const allZero = authority.encodeBase64Url(new Uint8Array(32))
    await expect(authority.commitEvidence(audienceId, false, allZero as never)).rejects.toThrow()
  })

  it('does not serialize the private salt in a public commitment result', async () => {
    const { handle, salt } = freshOpening()
    const commitment = await authority.commitEvidence(audienceId, false, handle)
    expect(commitment).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify({ commitment })).toBe(`{"commitment":"${commitment}"}`)
    expect(JSON.stringify({ commitment })).not.toContain(salt)
  })

  it('keeps the native salt out of the frozen opaque handle serialization', () => {
    const { handle, salt } = freshOpening()
    expect(Object.isFrozen(handle)).toBe(true)
    expect(Reflect.ownKeys(handle)).toEqual([])
    expect(JSON.stringify(handle)).toBe('{}')
    expect(authority.canonicalJson(handle)).toBe('{}')
    expect(salt).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(Buffer.from(salt, 'base64url')).toHaveLength(32)
  })

  it('exposes a type that plain objects cannot construct', () => {
    type IsOpaque = {} extends authority.EvidenceSalt ? false : true
    const opaque: IsOpaque = true
    expect(opaque).toBe(true)
  })

  it('uses the exact audience, salt, length and canonical value bytes', async () => {
    expect(authority).toHaveProperty('commitEvidence')
    const value = { b: 2, a: 'ñ' }
    const { handle, salt } = freshOpening()
    const commitment = await authority.commitEvidence(audienceId, value, handle)
    expect(commitment).toBe(oracle(audienceId, '{"a":"ñ","b":2}', salt))
  })

  it('generates a fresh canonical 32-byte salt for each commitment', async () => {
    const first = freshOpening()
    const second = freshOpening()
    const firstSalt = first.salt
    const secondSalt = second.salt
    for (const salt of [firstSalt, secondSalt]) {
      expect(salt).toMatch(/^[A-Za-z0-9_-]{43}$/)
      expect(Buffer.from(salt, 'base64url')).toHaveLength(32)
    }
    const firstCommitment = await authority.commitEvidence(audienceId, false, first.handle)
    const secondCommitment = await authority.commitEvidence(audienceId, false, second.handle)
    expect(firstCommitment).toBe(oracle(audienceId, 'false', firstSalt))
    expect(secondCommitment).toBe(oracle(audienceId, 'false', secondSalt))
    expect(firstSalt).not.toBe(secondSalt)
    expect(firstCommitment).not.toBe(secondCommitment)
  })

  it.each(['', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64), 7, null])('rejects malformed audience %s', async (badAudience) => {
    await expect(authority.commitEvidence(badAudience as string, 1, freshOpening().handle)).rejects.toThrow()
  })

  it.each([undefined, NaN, -0, 1.5, () => 1, { x: undefined }, 'x'.repeat(1024 * 1024)])('rejects unsupported value #%#', async (value) => {
    await expect(authority.commitEvidence(audienceId, value, freshOpening().handle)).rejects.toThrow()
  })

  it('rejects salt strings and forged handles', async () => {
    const { salt } = freshOpening()
    for (const malformed of [salt, '', null, 7, Object.freeze({}), Object.freeze({ salt })]) {
      await expect(authority.commitEvidence(audienceId, 1, malformed as never)).rejects.toThrow()
      expect(() => authority.exportEvidenceSalt(malformed as never)).toThrow()
    }
  })

  it('consumes the handle before its first asynchronous hash and permits one commitment', async () => {
    const { handle, salt } = freshOpening()
    const pending = authority.commitEvidence(audienceId, 1, handle)
    expect(() => authority.exportEvidenceSalt(handle)).toThrow()
    await expect(authority.commitEvidence(audienceId, 1, handle)).rejects.toThrow()
    expect(await pending).toBe(oracle(audienceId, '1', salt))
  })

  it('keeps a handle live when audience or value validation fails', async () => {
    const { handle, salt } = freshOpening()
    await expect(authority.commitEvidence('A'.repeat(64), 1, handle)).rejects.toThrow()
    expect(authority.exportEvidenceSalt(handle)).toBe(salt)
    await expect(authority.commitEvidence(audienceId, undefined, handle)).rejects.toThrow()
    expect(authority.exportEvidenceSalt(handle)).toBe(salt)
    expect(await authority.commitEvidence(audienceId, 1, handle)).toBe(oracle(audienceId, '1', salt))
  })

  it('snapshots a caller-owned value before the first asynchronous digest', async () => {
    const value = { answer: 1 }
    const { handle, salt } = freshOpening()
    const pending = authority.commitEvidence(audienceId, value, handle)
    value.answer = 2
    expect(await pending).toBe(oracle(audienceId, '{"answer":1}', salt))
  })

  it('verifies a selected opening and rejects a changed audience, value, salt or commitment', async () => {
    expect(authority).toHaveProperty('verifyEvidenceOpening')
    const value = { answer: 42 }
    const { handle, salt } = freshOpening()
    const commitment = await authority.commitEvidence(audienceId, value, handle)
    expect(await authority.verifyEvidenceOpening(audienceId, value, salt, commitment)).toBe(true)
    expect(await authority.verifyEvidenceOpening(otherAudience, value, salt, commitment)).toBe(false)
    expect(await authority.verifyEvidenceOpening(audienceId, { answer: 43 }, salt, commitment)).toBe(false)
    expect(await authority.verifyEvidenceOpening(audienceId, value, 'A'.repeat(43), commitment)).toBe(false)
    expect(await authority.verifyEvidenceOpening(audienceId, value, salt, '0'.repeat(64))).toBe(false)
  })

  it('returns false for malformed or noncanonical openings', async () => {
    const { handle, salt } = freshOpening()
    const commitment = await authority.commitEvidence(audienceId, 7, handle)
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    const lastIndex = alphabet.indexOf(salt.at(-1)!)
    const noncanonical = salt.slice(0, -1) + alphabet[lastIndex + 1]
    for (const malformed of ['', salt + '=', salt.slice(0, -1), salt + 'AA', salt + '*', noncanonical, null, 5]) {
      expect(await authority.verifyEvidenceOpening(audienceId, 7, malformed as string, commitment)).toBe(false)
    }
    for (const malformed of ['', 'A'.repeat(64), 'a'.repeat(63), null, 5]) {
      expect(await authority.verifyEvidenceOpening(audienceId, 7, salt, malformed as string)).toBe(false)
      expect(await authority.verifyEvidenceOpening(malformed as string, 7, salt, commitment)).toBe(false)
    }
  })

  it('returns false for values outside the canonical profile', async () => {
    const { handle, salt } = freshOpening()
    const commitment = await authority.commitEvidence(audienceId, null, handle)
    const cycle: unknown[] = []
    cycle.push(cycle)
    const getter = Object.defineProperty({}, 'x', { get: () => 1 })
    for (const invalid of [undefined, NaN, 1.5, cycle, getter, 'x'.repeat(1024 * 1024)]) {
      expect(await authority.verifyEvidenceOpening(audienceId, invalid, salt, commitment)).toBe(false)
    }
  })

  it('snapshots the opening value before the first asynchronous digest', async () => {
    const value = { answer: 1 }
    const { handle, salt } = freshOpening()
    const commitment = await authority.commitEvidence(audienceId, value, handle)
    const pending = authority.verifyEvidenceOpening(audienceId, value, salt, commitment)
    value.answer = 2
    expect(await pending).toBe(true)
  })
})
