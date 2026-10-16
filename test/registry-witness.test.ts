import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

let publisher: CryptoKeyPair
let observer: CryptoKeyPair
let outsider: CryptoKeyPair

beforeAll(async () => {
  [publisher, observer, outsider] = await Promise.all([
    authority.generateSigningKey(), authority.generateSigningKey(), authority.generateSigningKey(),
  ])
})

async function signedHead(leaves: Uint8Array[], previous: string | null) {
  return authority.signRegistryCheckpoint({ version: 1, size: leaves.length,
    root: await authority.merkleRoot(leaves),
    signerKeyId: await authority.signingKeyId(publisher.publicKey), previous }, publisher)
}

describe('compact registry witness', () => {
  it('authenticates a jump over unpublished intermediate witness polls', async () => {
    const leaves = ['a', 'b', 'c'].map(value => new TextEncoder().encode(value))
    const genesis = await signedHead([], null)
    const first = await signedHead(leaves.slice(0, 1),
      await authority.registryCheckpointHash(genesis.statement))
    const second = await signedHead(leaves.slice(0, 2),
      await authority.registryCheckpointHash(first.statement))
    const third = await signedHead(leaves,
      await authority.registryCheckpointHash(second.statement))
    const proof = await authority.consistencyProof(leaves, 1)

    expect(await authority.verifyRegistryCheckpoint(first, publisher.publicKey)).toBe(true)
    expect(await authority.verifyRegistryCheckpoint(third, publisher.publicKey)).toBe(true)
    expect(await authority.verifyConsistency(1, 3, first.statement.root,
      third.statement.root, proof)).toBe(true)

    const report = await authority.signRegistryWitness(first, third, proof, [],
      '2026-10-16T08:00:00.000Z', observer, publisher.publicKey)
    expect(report.statement.registryCheckpointHash)
      .toBe(await authority.registryCheckpointHash(third.statement))
    expect(await authority.verifyRegistryWitness(report, first, proof,
      observer.publicKey, publisher.publicKey)).toBe(true)
    expect(await authority.verifyRegistryWitness(report, first, proof,
      outsider.publicKey, publisher.publicKey)).toBe(false)
    expect(await authority.verifyRegistryWitness(report, first, ['0'.repeat(64)],
      observer.publicKey, publisher.publicKey)).toBe(false)
    expect(await authority.verifyRegistryWitness(report, first, proof,
      observer.publicKey, outsider.publicKey)).toBe(false)
    expect(await authority.verifyRegistryWitness({ ...report, statement: {
      ...report.statement, registryCheckpointHash: 'f'.repeat(64),
    } }, first, proof, observer.publicKey, publisher.publicKey)).toBe(false)
  })

  it('rejects a same-size rewrite while allowing an exact refresh', async () => {
    const original = await signedHead([new TextEncoder().encode('x')],
      await authority.registryCheckpointHash((await signedHead([], null)).statement))
    const alternate = await signedHead([new TextEncoder().encode('y')], original.statement.previous)
    expect(await authority.verifyRegistryCheckpoint(original, publisher.publicKey)).toBe(true)
    await expect(authority.signRegistryWitness(original, alternate, [], [],
      '2026-10-16T08:00:00.000Z', observer, publisher.publicKey)).rejects.toThrow()
    const refresh = await authority.signRegistryWitness(original, original, [], [],
      '2026-10-16T08:00:00.000Z', observer, publisher.publicKey)
    expect(await authority.verifyRegistryWitness(refresh, original, [],
      observer.publicKey, publisher.publicKey)).toBe(true)
  })

  it('snapshots caller-owned heads before asynchronous signature checks', async () => {
    const genesis = await signedHead([], null)
    const target = await signedHead([new TextEncoder().encode('entry')],
      await authority.registryCheckpointHash(genesis.statement))
    const mutableTarget = authority.parseCanonical(authority.canonicalBytes(target)) as unknown as authority.SignedRegistryCheckpoint
    const pending = authority.signRegistryWitness(genesis, mutableTarget, [], [],
      '2026-10-16T08:00:00.000Z', observer, publisher.publicKey)
    mutableTarget.statement.root = 'f'.repeat(64)
    const report = await pending
    expect(report.statement.registryCheckpoint.statement.root).toBe(target.statement.root)
    expect(await authority.verifyRegistryWitness(report, genesis, [],
      observer.publicKey, publisher.publicKey)).toBe(true)

    const mutableReport = authority.parseCanonical(authority.canonicalBytes(report)) as unknown as authority.SignedRegistryWitness
    const checking = authority.verifyRegistryWitness(mutableReport, genesis, [],
      observer.publicKey, publisher.publicKey)
    mutableReport.statement.registryCheckpoint.statement.root = 'e'.repeat(64)
    expect(await checking).toBe(true)
  })

  it('refuses a publisher key reused as the independent observer key', async () => {
    const genesis = await signedHead([], null)
    const target = await signedHead([new TextEncoder().encode('entry')],
      await authority.registryCheckpointHash(genesis.statement))
    await expect(authority.signRegistryWitness(genesis, target, [], [],
      '2026-10-16T08:00:00.000Z', publisher, publisher.publicKey)).rejects.toThrow()
    const honest = await authority.signRegistryWitness(genesis, target, [], [],
      '2026-10-16T08:00:00.000Z', observer, publisher.publicKey)
    const statement = { ...honest.statement,
      observerKeyId: await authority.signingKeyId(publisher.publicKey) }
    const forged = { statement, signature: await authority.signRecord(
      'observer.registry-witness.v2', statement, publisher.privateKey) }
    expect(await authority.verifyRegistryWitness(forged, genesis, [],
      publisher.publicKey, publisher.publicKey)).toBe(false)
  })

  it('rejects malformed same-head consistency paths', async () => {
    const genesis = await signedHead([], null)
    const malformed = { length: 0 } as unknown as string[]
    await expect(authority.signRegistryWitness(genesis, genesis, malformed, [],
      '2026-10-16T08:00:00.000Z', observer, publisher.publicKey)).rejects.toThrow()
  })
})
