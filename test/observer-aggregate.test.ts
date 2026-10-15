import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const api = authority as unknown as Record<string, any>
const FEEDS = ['a'.repeat(64), 'b'.repeat(64)]
const WORKSPACES = ['c'.repeat(64), 'd'.repeat(64)]
let publisher: CryptoKeyPair
let observer: CryptoKeyPair
let other: CryptoKeyPair
let customer: CryptoKeyPair[]
let recovery: CryptoKeyPair[]
let feedSigner: CryptoKeyPair[]

beforeAll(async () => {
  const pairs = await Promise.all(Array.from({ length: 9 }, () => authority.generateSigningKey()))
  publisher = pairs[0]!
  observer = pairs[1]!
  other = pairs[2]!
  customer = [pairs[3]!, pairs[4]!]
  recovery = [pairs[5]!, pairs[6]!]
  feedSigner = [pairs[7]!, pairs[8]!]
})

async function fixture() {
  const zero = await authority.signRegistryCheckpoint({ version: 1, size: 0,
    root: await authority.merkleRoot([]), signerKeyId: await authority.signingKeyId(publisher.publicKey),
    previous: null }, publisher)
  const anchors = await Promise.all(FEEDS.map(async (feedId, index) => {
    const statement = await authority.createAuthorityAnchor({ feedId, workspaceId: WORKSPACES[index]!,
      rootPublicKey: customer[index]!.publicKey, recoveryPublicKey: recovery[index]!.publicKey,
      checkpointPublicKey: feedSigner[index]!.publicKey })
    return { pin: await authority.anchorHash(statement),
      signed: await authority.signAuthorityAnchor(statement, customer[index]!, recovery[index]!) }
  }))
  const feedHead = await authority.signCheckpoint({ version: 1, feedId: FEEDS[0]!, size: 0,
    historyRoot: await authority.merkleRoot([]), authorityRoot: await authority.orderedMapRoot([]),
    policyEpoch: 0, signerKeyId: await authority.signingKeyId(feedSigner[0]!.publicKey),
    previous: null }, feedSigner[0]!)
  const leaves = [
    authority.registryEntryBytes({ version: 1, kind: 'feed_anchor', index: 0, feedId: FEEDS[0]!,
      anchorPin: anchors[0]!.pin, signedAnchor: anchors[0]!.signed }),
    authority.registryEntryBytes({ version: 1, kind: 'feed_head', index: 1, feedId: FEEDS[0]!,
      signedCheckpoint: feedHead }),
    authority.registryEntryBytes({ version: 1, kind: 'feed_anchor', index: 2, feedId: FEEDS[1]!,
      anchorPin: anchors[1]!.pin, signedAnchor: anchors[1]!.signed }),
  ]
  const head = await authority.signRegistryCheckpoint({ version: 1, size: leaves.length,
    root: await authority.merkleRoot(leaves), signerKeyId: await authority.signingKeyId(publisher.publicKey),
    previous: await authority.registryCheckpointHash(zero.statement) }, publisher)
  const session = await authority.createRegistryReplaySession(zero, publisher.publicKey)
  await session.appendRegistryEntries(leaves, head)
  await session.sealRegistryCheckpoint(head, await authority.consistencyProof(leaves, 0))
  const verified = await authority.replayGovernanceHistory(anchors[0]!.signed, anchors[0]!.pin, [], [feedHead])
  return { registry: session.snapshot(), head, verified }
}

describe('shared observer aggregate coverage', () => {
  it('signs one verified feed and one pending feed against an exact registry head', async () => {
    const { registry, head, verified } = await fixture()
    const report = await api.signAggregateReport(registry, head, [verified], [],
      '2026-10-14T12:00:00.000Z', observer)
    expect(report.statement).toMatchObject({ version: 1, coverageScope: 'shared_registry',
      registryCheckpointHash: registry.checkpointHash,
      verifiedFeeds: { count: 1 }, pendingFeeds: { count: 1 },
      unresolvedFindings: { count: 0, root: null } })
    expect(await api.verifyAggregateReport(report, observer.publicKey, publisher.publicKey,
      registry.checkpointHash)).toBe(true)
    expect(await api.verifyAggregateReport(report, other.publicKey, publisher.publicKey,
      registry.checkpointHash)).toBe(false)
    expect(await api.verifyAggregateReport({ ...report, statement: { ...report.statement,
      pendingFeeds: { count: 0, root: null } } }, observer.publicKey, publisher.publicKey,
      registry.checkpointHash)).toBe(false)
    const pending = await api.aggregateFeedStatusProof(registry, [verified], FEEDS[1])
    expect(pending.status).toEqual({ feedId: FEEDS[1], anchorPin: registry.feeds[1]!.anchorPin,
      checkpointHash: null, status: 'pending' })
    expect(await api.verifyAggregateFeedStatus(report, pending, observer.publicKey,
      publisher.publicKey, registry.checkpointHash, FEEDS[1], registry.feeds[1]!.anchorPin)).toBe(true)
    expect(await api.verifyAggregateFeedStatus(report, pending, observer.publicKey,
      publisher.publicKey, registry.checkpointHash, FEEDS[0], registry.feeds[0]!.anchorPin)).toBe(false)
    expect(await api.verifyAggregateFeedStatus(report, pending, observer.publicKey,
      publisher.publicKey, registry.checkpointHash, FEEDS[1], 'e'.repeat(64))).toBe(false)
    expect(await api.verifyAggregateFeedStatus(report, { ...pending,
      status: { ...pending.status, status: 'verified' } }, observer.publicKey,
      publisher.publicKey, registry.checkpointHash, FEEDS[1], registry.feeds[1]!.anchorPin)).toBe(false)
  })

  it('rejects a verified head not advertised by the registry and mismatched registry snapshot', async () => {
    const { registry, head, verified } = await fixture()
    await expect(api.signAggregateReport(registry, head, [{ ...verified,
      checkpointHash: 'e'.repeat(64) }], [], '2026-10-14T12:00:00.000Z', observer)).rejects.toThrow()
    await expect(api.signAggregateReport({ ...registry, size: registry.size - 1 }, head,
      [verified], [], '2026-10-14T12:00:00.000Z', observer)).rejects.toThrow()
    await expect(api.signAggregateReport(registry, head, [verified, verified], [],
      '2026-10-14T12:00:00.000Z', observer)).rejects.toThrow()
  })

  it('never reads accessors in caller-supplied feed and finding arrays', async () => {
    const { registry, head, verified } = await fixture()
    let reads = 0
    const unsafe = [verified]
    Object.defineProperty(unsafe, '0', { enumerable: true, get() { reads++; return verified } })
    await expect(api.signAggregateReport(registry, head, unsafe, [],
      '2026-10-14T12:00:00.000Z', observer)).rejects.toThrow()
    const finding = ['e'.repeat(64)]
    Object.defineProperty(finding, '0', { enumerable: true, get() { reads++; return 'e'.repeat(64) } })
    await expect(api.signAggregateReport(registry, head, [verified], finding,
      '2026-10-14T12:00:00.000Z', observer)).rejects.toThrow()
    expect(reads).toBe(0)
  })

  it('can still sign aggregate coverage after the 20,001st feed registration', async () => {
    const { head } = await fixture()
    const largeHead = await authority.signRegistryCheckpoint({ ...head.statement,
      size: 20_001, root: 'f'.repeat(64) }, publisher)
    const feeds = Array.from({ length: 20_001 }, (_, index) => ({
      feedId: index.toString(16).padStart(64, '0'), anchorPin: 'a'.repeat(64),
      advertisedCheckpointHash: null, advertisedSize: null }))
    const registry = { size: 20_001,
      checkpointHash: await authority.registryCheckpointHash(largeHead.statement), feeds }
    const report = await api.signAggregateReport(registry, largeHead, [], [],
      '2026-10-14T12:00:00.000Z', observer)
    expect(report.statement.pendingFeeds.count).toBe(20_001)
  }, 30_000)
})
