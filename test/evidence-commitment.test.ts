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

describe('evidence commitment', () => {
  it('uses the exact audience, salt, length and canonical value bytes', async () => {
    expect(authority).toHaveProperty('commitEvidence')
    const value = { b: 2, a: 'ñ' }
    const { commitment, salt } = await authority.commitEvidence(audienceId, value)
    expect(commitment).toBe(oracle(audienceId, '{"a":"ñ","b":2}', salt))
  })

  it('generates a fresh canonical 32-byte salt for each commitment', async () => {
    const first = await authority.commitEvidence(audienceId, false)
    const second = await authority.commitEvidence(audienceId, false)
    for (const opening of [first, second]) {
      expect(opening.salt).toMatch(/^[A-Za-z0-9_-]{43}$/)
      expect(Buffer.from(opening.salt, 'base64url')).toHaveLength(32)
      expect(opening.commitment).toBe(oracle(audienceId, 'false', opening.salt))
    }
    expect(first.salt).not.toBe(second.salt)
    expect(first.commitment).not.toBe(second.commitment)
  })

  it.each(['', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64), 7, null])('rejects malformed audience %s', async (badAudience) => {
    await expect(authority.commitEvidence(badAudience as string, 1)).rejects.toThrow()
  })

  it.each([undefined, NaN, -0, 1.5, () => 1, { x: undefined }, 'x'.repeat(1024 * 1024)])('rejects unsupported value #%#', async (value) => {
    await expect(authority.commitEvidence(audienceId, value)).rejects.toThrow()
  })

  it('snapshots a caller-owned value before the first asynchronous digest', async () => {
    const value = { answer: 1 }
    const pending = authority.commitEvidence(audienceId, value)
    value.answer = 2
    const opening = await pending
    expect(opening.commitment).toBe(oracle(audienceId, '{"answer":1}', opening.salt))
  })

  it('verifies a selected opening and rejects a changed audience, value, salt or commitment', async () => {
    expect(authority).toHaveProperty('verifyEvidenceOpening')
    const value = { answer: 42 }
    const { commitment, salt } = await authority.commitEvidence(audienceId, value)
    expect(await authority.verifyEvidenceOpening(audienceId, value, salt, commitment)).toBe(true)
    expect(await authority.verifyEvidenceOpening(otherAudience, value, salt, commitment)).toBe(false)
    expect(await authority.verifyEvidenceOpening(audienceId, { answer: 43 }, salt, commitment)).toBe(false)
    expect(await authority.verifyEvidenceOpening(audienceId, value, 'A'.repeat(43), commitment)).toBe(false)
    expect(await authority.verifyEvidenceOpening(audienceId, value, salt, '0'.repeat(64))).toBe(false)
  })

  it('returns false for malformed or noncanonical openings', async () => {
    const { commitment, salt } = await authority.commitEvidence(audienceId, 7)
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
    const { commitment, salt } = await authority.commitEvidence(audienceId, null)
    const cycle: unknown[] = []
    cycle.push(cycle)
    const getter = Object.defineProperty({}, 'x', { get: () => 1 })
    for (const invalid of [undefined, NaN, 1.5, cycle, getter, 'x'.repeat(1024 * 1024)]) {
      expect(await authority.verifyEvidenceOpening(audienceId, invalid, salt, commitment)).toBe(false)
    }
  })

  it('snapshots the opening value before the first asynchronous digest', async () => {
    const value = { answer: 1 }
    const { commitment, salt } = await authority.commitEvidence(audienceId, value)
    const pending = authority.verifyEvidenceOpening(audienceId, value, salt, commitment)
    value.answer = 2
    expect(await pending).toBe(true)
  })
})
