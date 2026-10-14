import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const api = authority as unknown as Record<string, any>
const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)
let publisher: CryptoKeyPair
let root: CryptoKeyPair
let recovery: CryptoKeyPair
let feedSigner: CryptoKeyPair

beforeAll(async () => {
  const pairs = await Promise.all(Array.from({ length: 4 }, () => authority.generateSigningKey()))
  publisher = pairs[0]!
  root = pairs[1]!
  recovery = pairs[2]!
  feedSigner = pairs[3]!
})

async function anchor(index = 0) {
  const statement = await authority.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey,
    checkpointPublicKey: feedSigner.publicKey })
  return { version: 1 as const, kind: 'feed_anchor' as const, index, feedId: FEED,
    anchorPin: await authority.anchorHash(statement),
    signedAnchor: await authority.signAuthorityAnchor(statement, root, recovery) }
}

async function head(index: number, size: number, previous: string | null) {
  const leaves = size === 0 ? [] : [authority.canonicalBytes({ event: 'x' })]
  const signedCheckpoint = await authority.signCheckpoint({ version: 1, feedId: FEED, size,
    historyRoot: await authority.merkleRoot(leaves), authorityRoot: await authority.orderedMapRoot([]),
    policyEpoch: 0, signerKeyId: await authority.signingKeyId(feedSigner.publicKey), previous }, feedSigner)
  return { version: 1 as const, kind: 'feed_head' as const, index, feedId: FEED, signedCheckpoint }
}

async function registryHead(leaves: Uint8Array[], previous: string | null) {
  return authority.signRegistryCheckpoint({ version: 1, size: leaves.length,
    root: await authority.merkleRoot(leaves), signerKeyId: await authority.signingKeyId(publisher.publicKey),
    previous }, publisher)
}

describe('shared registry replay', () => {
  it('catches up through contiguous pages and retains the latest advertised feed head', async () => {
    const zero = await registryHead([], null)
    const firstFeedHead = await head(1, 0, null)
    const first = [authority.registryEntryBytes(await anchor()),
      authority.registryEntryBytes(firstFeedHead)]
    const globalOne = await registryHead(first, await authority.registryCheckpointHash(zero.statement))
    const laterFeedHead = await head(2, 1,
      await authority.checkpointHash(firstFeedHead.signedCheckpoint.statement))
    const all = [...first, authority.registryEntryBytes(laterFeedHead)]
    const globalTwo = await registryHead(all, await authority.registryCheckpointHash(globalOne.statement))
    const session = await api.createRegistryReplaySession(zero, publisher.publicKey)
    await session.appendRegistryEntries(first.slice(0, 1), globalOne)
    await session.appendRegistryEntries(first.slice(1), globalOne)
    await session.sealRegistryCheckpoint(globalOne, await authority.consistencyProof(first, 0))
    expect(session.snapshot().size).toBe(2)
    await session.appendRegistryEntries(all.slice(2), globalTwo)
    await session.sealRegistryCheckpoint(globalTwo, await authority.consistencyProof(all, 2))
    expect(session.snapshot()).toMatchObject({ size: 3,
      checkpointHash: await authority.registryCheckpointHash(globalTwo.statement),
      feeds: [{ feedId: FEED, anchorPin: (await anchor()).anchorPin,
        advertisedCheckpointHash: await authority.checkpointHash(laterFeedHead.signedCheckpoint.statement),
        advertisedSize: 1 }] })
  })

  it('rejects a head before registration and duplicate registration', async () => {
    const zero = await registryHead([], null)
    const early = authority.registryEntryBytes(await head(0, 0, null))
    const first = await registryHead([early], await authority.registryCheckpointHash(zero.statement))
    const session = await api.createRegistryReplaySession(zero, publisher.publicKey)
    await expect(session.appendRegistryEntries([early], first)).rejects.toThrow()

    const registration = authority.registryEntryBytes(await anchor())
    const duplicate = authority.registryEntryBytes(await anchor(1))
    const duplicated = await registryHead([registration, duplicate],
      await authority.registryCheckpointHash(zero.statement))
    const other = await api.createRegistryReplaySession(zero, publisher.publicKey)
    await expect(other.appendRegistryEntries([registration, duplicate], duplicated)).rejects.toThrow()
  })

  it('rejects omitted indexes, forged enrollment and feed-size rollback', async () => {
    const zero = await registryHead([], null)
    const goodAnchor = await anchor()
    const registration = authority.registryEntryBytes(goodAnchor)
    const firstHead = await head(1, 1, 'c'.repeat(64))
    const laterHead = await head(2, 0, null)
    const all = [registration, authority.registryEntryBytes(firstHead), authority.registryEntryBytes(laterHead)]
    const target = await registryHead(all, await authority.registryCheckpointHash(zero.statement))
    const session = await api.createRegistryReplaySession(zero, publisher.publicKey)
    await expect(session.appendRegistryEntries(all.slice(1, 2), target)).rejects.toThrow()

    const forgedAnchor = authority.registryEntryBytes({ ...goodAnchor,
      anchorPin: 'd'.repeat(64) } as authority.RegistryEntry)
    const forgedTarget = await registryHead([forgedAnchor], await authority.registryCheckpointHash(zero.statement))
    const second = await api.createRegistryReplaySession(zero, publisher.publicKey)
    await expect(second.appendRegistryEntries([forgedAnchor], forgedTarget)).rejects.toThrow()

    const third = await api.createRegistryReplaySession(zero, publisher.publicKey)
    await expect(third.appendRegistryEntries(all, target)).rejects.toThrow()
  })
})
