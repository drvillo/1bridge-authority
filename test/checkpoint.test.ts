import { createHash } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'
import { EMPTY_ROOT, fixtureLeaves, oracleRoot } from './oracle.js'

const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

let pair: CryptoKeyPair
let other: CryptoKeyPair
let signerKeyId: string

beforeAll(async () => {
  pair = await authority.generateSigningKey()
  other = await authority.generateSigningKey()
  signerKeyId = await authority.signingKeyId(pair.publicKey)
})

function statement(overrides: Record<string, unknown> = {}) {
  return {
    version: 1 as const,
    feedId: HASH_A,
    size: 0,
    historyRoot: EMPTY_ROOT,
    authorityRoot: HASH_B,
    policyEpoch: 0,
    signerKeyId,
    previous: null,
    ...overrides,
  }
}

async function signedHead(size: number, previous: string | null, overrides: Record<string, unknown> = {}) {
  const leaves = fixtureLeaves(size)
  return authority.signCheckpoint(statement({ size, historyRoot: oracleRoot(leaves), previous, ...overrides }), pair)
}

describe('signed governance checkpoint', () => {
  it('exports the checkpoint contract', () => {
    for (const name of ['checkpointHash', 'signCheckpoint', 'verifyCheckpoint', 'verifyCheckpointExtension']) {
      expect(authority).toHaveProperty(name)
    }
  })

  it('uses the exact statement-ID domain and canonical bytes', async () => {
    const head = statement()
    const expected = createHash('sha256')
      .update('1bridge.authority/v1/checkpoint-id\n', 'utf8')
      .update(authority.canonicalBytes(head))
      .digest('hex')
    expect(await authority.checkpointHash(head)).toBe(expected)
    expect(expected).not.toBe(createHash('sha256').update(authority.canonicalBytes(head)).digest('hex'))
  })

  it('signs an initial head with the existing purpose and verifies only under its declared trusted key', async () => {
    const head = await signedHead(0, null)
    expect(Object.keys(head).sort()).toEqual(['signature', 'statement'])
    expect(head.statement).toEqual(statement())
    expect(authority.decodeBase64Url(head.signature)).toHaveLength(64)
    expect(await authority.verifyRecord('history.checkpoint', head.statement, head.signature, pair.publicKey)).toBe(true)
    expect(await authority.verifyRecord('checkpoint', head.statement, head.signature, pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpoint(head, pair.publicKey)).toBe(true)
    expect(await authority.verifyCheckpoint(head, other.publicKey)).toBe(false)
    expect(await authority.verifyCheckpoint({ ...head, statement: { ...head.statement, historyRoot: HASH_A } }, pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpoint({ ...head, statement: { ...head.statement, signerKeyId: HASH_A } }, pair.publicKey)).toBe(false)
  })

  it('rejects mismatched signing pairs and signer IDs', async () => {
    await expect(authority.signCheckpoint(statement(), { publicKey: pair.publicKey, privateKey: other.privateKey })).rejects.toThrow()
    await expect(authority.signCheckpoint(statement({ signerKeyId: HASH_A }), pair)).rejects.toThrow()
    let getterCalls = 0
    const accessor = { privateKey: pair.privateKey } as CryptoKeyPair
    Object.defineProperty(accessor, 'publicKey', { enumerable: true, get() { getterCalls += 1; return pair.publicKey } })
    await expect(authority.signCheckpoint(statement(), accessor)).rejects.toThrow('data fields')
    expect(getterCalls).toBe(0)
  })

  it('snapshots the statement before its first signing await', async () => {
    const input = statement()
    const pending = authority.signCheckpoint(input, pair)
    input.historyRoot = HASH_A
    const head = await pending
    expect(head.statement.historyRoot).toBe(EMPTY_ROOT)
    expect(await authority.verifyCheckpoint(head, pair.publicKey)).toBe(true)
  })

  it('snapshots the envelope before its first verification await', async () => {
    const head = await signedHead(0, null)
    const pending = authority.verifyCheckpoint(head, pair.publicKey)
    head.statement.historyRoot = HASH_A
    head.signature = 'bad'
    expect(await pending).toBe(true)
  })

  it('rejects malformed statement fields without invoking getters', async () => {
    const good = statement()
    const cases: unknown[] = [
      { ...good, extra: 1 },
      Object.fromEntries(Object.entries(good).filter(([name]) => name !== 'feedId')),
      Object.assign(Object.create(null), good, { extra: 1 }),
      { ...good, [Symbol('extra')]: 1 },
      { ...good, version: 2 },
      { ...good, feedId: HASH_A.toUpperCase() },
      { ...good, historyRoot: '0'.repeat(63) },
      { ...good, authorityRoot: 'g'.repeat(64) },
      { ...good, signerKeyId: '' },
      { ...good, size: 1 },
      { ...good, previous: HASH_A },
      { ...good, size: 1, historyRoot: HASH_A, previous: null },
      { ...good, size: 1, historyRoot: HASH_A, previous: 'bad' },
      { ...good, policyEpoch: -1 },
    ]
    for (const field of ['size', 'policyEpoch']) {
      for (const value of [-0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN, '1']) {
        cases.push({ ...good, [field]: value })
      }
    }
    let getterCalls = 0
    const accessor = { ...good }
    Object.defineProperty(accessor, 'feedId', { enumerable: true, get() { getterCalls += 1; return HASH_A } })
    cases.push(accessor)
    for (const malformed of cases) {
      await expect(authority.checkpointHash(malformed as typeof good)).rejects.toThrow()
      await expect(authority.signCheckpoint(malformed as typeof good, pair)).rejects.toThrow()
    }
    expect(getterCalls).toBe(0)
  })

  it('rejects malformed envelopes and signatures without invoking getters', async () => {
    const head = await signedHead(0, null)
    let getterCalls = 0
    const accessor = { ...head }
    Object.defineProperty(accessor, 'statement', { enumerable: true, get() { getterCalls += 1; return head.statement } })
    const malformed: unknown[] = [null, {}, { ...head, extra: 1 }, { ...head, [Symbol('extra')]: 1 }, accessor,
      { ...head, statement: { ...head.statement, extra: 1 } },
      ...['', 'A', 'A'.repeat(85), 'A'.repeat(87), head.signature + '=', 'A'.repeat(100000), null].map(signature => ({ ...head, signature }))]
    for (const input of malformed) expect(await authority.verifyCheckpoint(input as typeof head, pair.publicKey)).toBe(false)
    expect(getterCalls).toBe(0)
    expect(await authority.verifyCheckpoint(head, pair.privateKey)).toBe(false)
  })
})

describe('signed checkpoint extension', () => {
  it.each([[0, 1], [1, 2], [2, 3], [3, 7], [7, 8], [8, 13]])('verifies the RFC prefix %i to %i', async (oldSize, newSize) => {
    const oldHead = await signedHead(oldSize, oldSize === 0 ? null : HASH_A)
    const newHead = await signedHead(newSize, await authority.checkpointHash(oldHead.statement))
    const proof = await authority.consistencyProof(fixtureLeaves(newSize), oldSize)
    expect(await authority.verifyCheckpointExtension(oldHead, newHead, proof, pair.publicKey)).toBe(true)
  })

  it('rejects rollback, equal-size changes, scope changes, epoch rollback and wrong predecessor', async () => {
    const oldHead = await signedHead(1, HASH_A, { policyEpoch: 3 })
    const previous = await authority.checkpointHash(oldHead.statement)
    const good = await signedHead(2, previous, { policyEpoch: 4 })
    const proof = await authority.consistencyProof(fixtureLeaves(2), 1)
    expect(await authority.verifyCheckpointExtension(oldHead, good, proof, pair.publicKey)).toBe(true)
    for (const changed of [
      await signedHead(0, null, { policyEpoch: 4 }),
      await signedHead(1, HASH_A, { policyEpoch: 4 }),
      await signedHead(2, previous, { feedId: HASH_B, policyEpoch: 4 }),
      await signedHead(2, previous, { policyEpoch: 2 }),
      await signedHead(2, HASH_B, { policyEpoch: 4 }),
    ]) {
      expect(await authority.verifyCheckpointExtension(oldHead, changed, proof, pair.publicKey)).toBe(false)
    }
  })

  it('rejects tampered heads, rewritten prefixes and invalid consistency proof', async () => {
    const oldHead = await signedHead(2, HASH_A)
    const previous = await authority.checkpointHash(oldHead.statement)
    const good = await signedHead(3, previous)
    const proof = await authority.consistencyProof(fixtureLeaves(3), 2)
    expect(await authority.verifyCheckpointExtension(oldHead, good, proof, pair.publicKey)).toBe(true)
    const rewritten = await signedHead(3, previous, { historyRoot: oracleRoot(fixtureLeaves(3).reverse()) })
    expect(await authority.verifyCheckpointExtension(oldHead, rewritten, proof, pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpointExtension({ ...oldHead, signature: good.signature }, good, proof, pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpointExtension(oldHead, { ...good, signature: oldHead.signature }, proof, pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpointExtension(oldHead, good, [], pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpointExtension(oldHead, good, [HASH_A], pair.publicKey)).toBe(false)
    let getterCalls = 0
    const accessorProof = [...proof]
    Object.defineProperty(accessorProof, '0', { enumerable: true, get() { getterCalls += 1; return proof[0] } })
    expect(await authority.verifyCheckpointExtension(oldHead, good, accessorProof, pair.publicKey)).toBe(false)
    expect(getterCalls).toBe(0)
  })

  it('does not accept signer rotation under a new public key', async () => {
    const oldHead = await signedHead(1, HASH_A)
    const previous = await authority.checkpointHash(oldHead.statement)
    const rotated = await authority.signCheckpoint(statement({ size: 2, historyRoot: oracleRoot(fixtureLeaves(2)), previous, signerKeyId: await authority.signingKeyId(other.publicKey) }), other)
    const proof = await authority.consistencyProof(fixtureLeaves(2), 1)
    expect(await authority.verifyCheckpointExtension(oldHead, rotated, proof, pair.publicKey)).toBe(false)
    expect(await authority.verifyCheckpointExtension(oldHead, rotated, proof, other.publicKey)).toBe(false)
  })

  it('snapshots both heads and the proof before the first await', async () => {
    const oldHead = await signedHead(1, HASH_A)
    const newHead = await signedHead(2, await authority.checkpointHash(oldHead.statement))
    const proof = await authority.consistencyProof(fixtureLeaves(2), 1)
    const pending = authority.verifyCheckpointExtension(oldHead, newHead, proof, pair.publicKey)
    oldHead.signature = 'bad'
    newHead.statement.historyRoot = HASH_A
    proof[0] = HASH_B
    expect(await pending).toBe(true)
  })
})
