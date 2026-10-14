import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const vector = authority.parseCanonical(readFileSync(new URL('./fixtures/governance-v1.json', import.meta.url))) as {
  anchorPin: string; signedAnchor: string; leaves: string[]; checkpoints: string[]
}
const anchor = authority.parseCanonical(authority.decodeBase64Url(vector.signedAnchor)) as unknown as authority.SignedAuthorityAnchor
const leaves = vector.leaves.map(value => authority.decodeBase64Url(value))
const checkpoints = vector.checkpoints.map(value => authority.parseCanonical(authority.decodeBase64Url(value)) as unknown as authority.SignedCheckpoint)

let observer: CryptoKeyPair
let other: CryptoKeyPair
let snapshot: authority.GovernanceReplaySnapshot

beforeAll(async () => {
  observer = await authority.generateSigningKey()
  other = await authority.generateSigningKey()
  snapshot = await authority.replayGovernanceHistory(anchor, vector.anchorPin, leaves, checkpoints)
})

function scope(): authority.ObserverReportScope {
  return {
    anchorPin: vector.anchorPin,
    checkedAt: '2026-10-14T12:00:00.000Z',
    knownReceipts: { kind: 'none', count: 0, digest: null },
    unresolvedFindings: { count: 0, digest: null },
  }
}

describe('independently signed observer coverage', () => {
  it('derives canonical evidence-set and finding digests for reproducible scope checks', async () => {
    const hashes = ['a'.repeat(64), 'b'.repeat(64)]
    const expectedSet = createHash('sha256')
      .update('1bridge.authority/v1/observer-evidence-set\n')
      .update(JSON.stringify(hashes))
      .digest('hex')
    expect(await authority.observerEvidenceSetDigest(hashes)).toBe(expectedSet)
    const evidence = authority.canonicalBytes({ kind: 'observer.source_nonconformance', version: 1 })
    const expectedFinding = createHash('sha256')
      .update('1bridge.authority/v1/observer-finding-id\n')
      .update(evidence)
      .digest('hex')
    expect(await authority.observerFindingHash(evidence)).toBe(expectedFinding)
    await expect(authority.observerEvidenceSetDigest([])).rejects.toThrow()
    await expect(authority.observerEvidenceSetDigest([hashes[1]!, hashes[0]!])).rejects.toThrow()
    await expect(authority.observerEvidenceSetDigest([hashes[0]!, hashes[0]!])).rejects.toThrow()
    await expect(authority.observerFindingHash(new TextEncoder().encode('{"version":1,"kind":"x"}'))).rejects.toThrow()
  })

  it('commits the maximum combined receipt and source-finding set', async () => {
    const hashes = Array.from({ length: 20_000 }, (_, index) => index.toString(16).padStart(64, '0'))
    const expected = createHash('sha256')
      .update('1bridge.authority/v1/observer-evidence-set\n')
      .update(JSON.stringify(hashes))
      .digest('hex')
    expect(await authority.observerEvidenceSetDigest(hashes)).toBe(expected)
    await expect(authority.observerEvidenceSetDigest([...hashes, 'f'.repeat(64)])).rejects.toThrow()
  })

  it('binds a replayed exact checkpoint and admits explicitly source-only coverage', async () => {
    const signed = await authority.signObserverReport(snapshot, checkpoints.at(-1)!, scope(), observer)
    expect(signed.statement).toMatchObject({
      version: 1,
      coverageScope: 'verified_prefix',
      feedId: snapshot.feedId,
      anchorPin: vector.anchorPin,
      coveredCheckpointHash: snapshot.checkpointHash,
      coveredCheckpoint: checkpoints.at(-1),
      authorityRevision: snapshot.authorityRevision,
      authorityRevisionHash: snapshot.authorityRevisionHash,
      observerPolicyHash: snapshot.observerPolicyHash,
      knownReceipts: { kind: 'none', count: 0, digest: null },
    })
    expect(signed.statement.observerKeyId).toBe(await authority.signingKeyId(observer.publicKey))
    expect(await authority.verifyObserverReport(signed, observer.publicKey,
      { feedId: snapshot.feedId, anchorPin: vector.anchorPin })).toBe(true)
    expect(await authority.verifyObserverReport(signed, other.publicKey,
      { feedId: snapshot.feedId, anchorPin: vector.anchorPin })).toBe(false)
  })

  it('rejects altered scope, embedded head, wrong pin and wrong signature purpose', async () => {
    const signed = await authority.signObserverReport(snapshot, checkpoints.at(-1)!, scope(), observer)
    const expected = { feedId: snapshot.feedId, anchorPin: vector.anchorPin }
    for (const statement of [
      { ...signed.statement, coveredCheckpointHash: 'a'.repeat(64) },
      { ...signed.statement, authorityRevision: snapshot.authorityRevision + 1 },
      { ...signed.statement, checkedAt: '2026-10-15T12:00:00.000Z' },
      { ...signed.statement, coverageScope: 'all_events' },
      { ...signed.statement, extra: true },
      { ...signed.statement, knownReceipts: { kind: 'none', count: 1, digest: 'a'.repeat(64) } },
      { ...signed.statement, coveredCheckpoint: checkpoints[0] },
    ]) {
      expect(await authority.verifyObserverReport({ ...signed, statement } as authority.SignedObserverReport,
        observer.publicKey, expected)).toBe(false)
    }
    expect(await authority.verifyObserverReport(signed, observer.publicKey,
      { feedId: snapshot.feedId, anchorPin: 'a'.repeat(64) })).toBe(false)
    expect(await authority.verifyRecord('history.checkpoint', signed.statement,
      signed.signature, observer.publicKey)).toBe(false)
  })

  it('does not invoke accessors or allow mutable caller objects to change the signed meaning', async () => {
    const input = scope()
    const pending = authority.signObserverReport(snapshot, checkpoints.at(-1)!, input, observer)
    input.checkedAt = '2026-10-15T12:00:00.000Z'
    const signed = await pending
    expect(signed.statement.checkedAt).toBe('2026-10-14T12:00:00.000Z')
    let getterCalls = 0
    const accessor = { signature: signed.signature } as authority.SignedObserverReport
    Object.defineProperty(accessor, 'statement', { enumerable: true, get() {
      getterCalls += 1
      return signed.statement
    } })
    expect(await authority.verifyObserverReport(accessor, observer.publicKey,
      { feedId: snapshot.feedId, anchorPin: vector.anchorPin })).toBe(false)
    expect(getterCalls).toBe(0)
    const verification = authority.verifyObserverReport(signed, observer.publicKey,
      { feedId: snapshot.feedId, anchorPin: vector.anchorPin })
    signed.statement.checkedAt = '2026-10-15T12:00:00.000Z'
    expect(await verification).toBe(true)
  })

  it('rejects a head inconsistent with the supplied replay snapshot before signing', async () => {
    expect(snapshot.anchorPin).toBe(vector.anchorPin)
    await expect(authority.signObserverReport(snapshot, checkpoints.at(-1)!,
      { ...scope(), anchorPin: 'b'.repeat(64) }, observer)).rejects.toThrow()
    await expect(authority.signObserverReport(snapshot, checkpoints[0]!, scope(), observer)).rejects.toThrow()
    await expect(authority.signObserverReport({ ...snapshot, size: 6 }, checkpoints.at(-1)!, scope(), observer)).rejects.toThrow()
    await expect(authority.signObserverReport(snapshot, checkpoints.at(-1)!,
      { ...scope(), checkedAt: '2026-10-14' }, observer)).rejects.toThrow()
    await expect(authority.signObserverReport(snapshot, checkpoints.at(-1)!,
      { ...scope(), knownReceipts: { kind: 'none', count: 1, digest: null } }, observer)).rejects.toThrow()
    await expect(authority.signObserverReport(snapshot, checkpoints.at(-1)!, scope(),
      { publicKey: observer.publicKey, privateKey: other.privateKey })).rejects.toThrow()
  })

  it('binds the known archived-receipt and unresolved-finding summaries without claiming completeness', async () => {
    const enriched: authority.ObserverReportScope = { ...scope(),
      knownReceipts: { kind: 'known_archive', count: 2, digest: 'b'.repeat(64) },
      unresolvedFindings: { count: 1, digest: 'c'.repeat(64) } }
    const signed = await authority.signObserverReport(snapshot, checkpoints.at(-1)!,
      enriched, observer)
    expect(signed.statement.knownReceipts).toEqual(enriched.knownReceipts)
    expect(signed.statement.unresolvedFindings).toEqual(enriched.unresolvedFindings)
    expect(await authority.verifyObserverReport(signed, observer.publicKey,
      { feedId: snapshot.feedId, anchorPin: vector.anchorPin })).toBe(true)
  })
})
