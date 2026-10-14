import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { authorityId, authoritySubjectId } from '../src/index.js'

const UUID = '550e8400-e29b-41d4-a716-446655440000'
const KIND_VECTORS = {
  workspace: '9388d79f479cf64a08567eafc736f6811110e0238bd557e8cc24bce53cb82f2c',
  vault: '398a28f25c45fd8cdf8a7b52004ce06a3ac580e1d5c62c173d59c3b82293ac9c',
  membership: '1cda0b825cdef47e69bcca0a337807edbceb5fede4a821e1f92cfac5d13531ce',
  'membership-key-row': '8999536b6cedb907e94d2d9c29d2800e53711b398c7e63f6ace7484af12aaca0',
  operation: '8e0b1cef28645380989ecbfb5573fc7b5372ccaafd5c7ce4e5e2c9a0050513d1',
} as const
const SUBJECT = { workspaceId: 'a'.repeat(64), membershipId: 'b'.repeat(64), actorKeyId: 'c'.repeat(64) }
const SUBJECT_VECTOR = 'cf234a9907485fb3707c0b3a0992d71091eb03dda20771b18ce9ca4589791c44'

describe('authority UUID mapping v1', () => {
  it('matches independently computed vectors for every fixed app role', async () => {
    for (const [kind, vector] of Object.entries(KIND_VECTORS)) {
      expect(await authorityId(kind as keyof typeof KIND_VECTORS, UUID)).toBe(vector)
      expect(vector).toBe(createHash('sha256').update(`1bridge.authority/v1/id/${kind}\n${UUID}`).digest('hex'))
    }
    expect(new Set(Object.values(KIND_VECTORS)).size).toBe(5)
  })

  it('folds hexadecimal UUID case without changing the mapped identity', async () => {
    expect(await authorityId('workspace', '550E8400-E29B-41D4-A716-446655440000')).toBe(KIND_VECTORS.workspace)
  })

  it('rejects invalid UUID syntax and invented roles', async () => {
    for (const uuid of [
      '', ' 550e8400-e29b-41d4-a716-446655440000',
      '550e8400-e29b-41d4-a716-446655440000 ',
      '{550e8400-e29b-41d4-a716-446655440000}',
      'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
      '550e8400e29b41d4a716446655440000',
      '550e8400-e29b-41d4-a716-44665544000g',
      '550e8400_e29b_41d4_a716_446655440000',
      '550e8400-e29b-41d4-a716-446655440000\n',
    ]) await expect(authorityId('workspace', uuid)).rejects.toThrow()
    await expect(authorityId('device' as never, UUID)).rejects.toThrow()
    await expect(authorityId('Workspace' as never, UUID)).rejects.toThrow()
    await expect(authorityId('__proto__' as never, UUID)).rejects.toThrow()
    await expect(authorityId('workspace', 1 as never)).rejects.toThrow()
  })

  it('accepts UUID byte format without claiming version or variant validation', async () => {
    const zero = '00000000-0000-0000-0000-000000000000'
    expect(await authorityId('workspace', zero)).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('authority actor subject v1', () => {
  it('matches the independent canonical JSON vector', async () => {
    expect(await authoritySubjectId(SUBJECT)).toBe(SUBJECT_VECTOR)
    const canonical = JSON.stringify({ actorKeyId: SUBJECT.actorKeyId, membershipId: SUBJECT.membershipId, workspaceId: SUBJECT.workspaceId })
    expect(SUBJECT_VECTOR).toBe(createHash('sha256').update('1bridge.authority/v1/actor-subject\n' + canonical).digest('hex'))
  })

  it('changes for each workspace, membership, or actor signing key', async () => {
    for (const changed of [
      { workspaceId: 'd'.repeat(64) },
      { membershipId: 'd'.repeat(64) },
      { actorKeyId: 'd'.repeat(64) },
    ]) expect(await authoritySubjectId({ ...SUBJECT, ...changed })).not.toBe(SUBJECT_VECTOR)
  })

  it('rejects malformed hashes and non-exact records without invoking accessors', async () => {
    const invalid = [
      null, [],
      { ...SUBJECT, extra: 1 },
      { workspaceId: SUBJECT.workspaceId, membershipId: SUBJECT.membershipId },
      { ...SUBJECT, workspaceId: 'A'.repeat(64) },
      { ...SUBJECT, membershipId: 'b'.repeat(63) },
      { ...SUBJECT, actorKeyId: 'g'.repeat(64) },
      Object.assign(Object.create({ inherited: true }), SUBJECT),
      Object.assign({ ...SUBJECT }, { [Symbol('hidden')]: true }),
    ]
    for (const value of invalid) await expect(authoritySubjectId(value as never)).rejects.toThrow()
    const accessor = { ...SUBJECT }
    let calls = 0
    Object.defineProperty(accessor, 'actorKeyId', { enumerable: true, get() { calls++; return SUBJECT.actorKeyId } })
    await expect(authoritySubjectId(accessor)).rejects.toThrow()
    expect(calls).toBe(0)
    const nonEnumerable = { ...SUBJECT }
    Object.defineProperty(nonEnumerable, 'membershipId', { enumerable: false, value: SUBJECT.membershipId })
    await expect(authoritySubjectId(nonEnumerable)).rejects.toThrow()
  })
})
