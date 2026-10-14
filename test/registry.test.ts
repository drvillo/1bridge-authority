import { beforeAll, describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const registry = authority as unknown as Record<string, any>
const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)

let publisher: CryptoKeyPair
let root: CryptoKeyPair
let recovery: CryptoKeyPair
let checkpoint: CryptoKeyPair
let outsider: CryptoKeyPair

beforeAll(async () => {
  const pairs = await Promise.all(Array.from({ length: 5 }, () => authority.generateSigningKey()))
  publisher = pairs[0]!
  root = pairs[1]!
  recovery = pairs[2]!
  checkpoint = pairs[3]!
  outsider = pairs[4]!
})

async function registration() {
  const anchor = await authority.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey,
    checkpointPublicKey: checkpoint.publicKey })
  return { version: 1, kind: 'feed_anchor', index: 0, feedId: FEED,
    anchorPin: await authority.anchorHash(anchor),
    signedAnchor: await authority.signAuthorityAnchor(anchor, root, recovery) }
}

async function feedHead() {
  const statement = { version: 1 as const, feedId: FEED, size: 0,
    historyRoot: await authority.merkleRoot([]), authorityRoot: await authority.orderedMapRoot([]),
    policyEpoch: 0, signerKeyId: await authority.signingKeyId(checkpoint.publicKey), previous: null }
  return { version: 1, kind: 'feed_head', index: 1, feedId: FEED,
    signedCheckpoint: await authority.signCheckpoint(statement, checkpoint) }
}

async function signedRegistry(size: number, rootHash: string, previous: string | null) {
  return registry.signRegistryCheckpoint({ version: 1, size, root: rootHash,
    signerKeyId: await authority.signingKeyId(publisher.publicKey), previous }, publisher)
}

describe('shared feed registry', () => {
  it('publishes exact registration/head bytes under a signed append-only root', async () => {
    const anchor = await registration()
    const head = await feedHead()
    const leaves = [registry.registryEntryBytes(anchor), registry.registryEntryBytes(head)] as Uint8Array[]
    expect(leaves[0]).toEqual(authority.canonicalBytes(anchor))
    expect(leaves[1]).toEqual(authority.canonicalBytes(head))
    const empty = await signedRegistry(0, await authority.merkleRoot([]), null)
    const next = await signedRegistry(2, await authority.merkleRoot(leaves),
      await registry.registryCheckpointHash(empty.statement))
    expect(await registry.verifyRegistryCheckpoint(empty, publisher.publicKey)).toBe(true)
    expect(await registry.verifyRegistryExtension(empty, next,
      await authority.consistencyProof(leaves, 0), publisher.publicKey)).toBe(true)
    expect(await authority.verifyInclusion(leaves[0]!, 0, 2,
      await authority.inclusionProof(leaves, 0), next.statement.root)).toBe(true)
    expect(await authority.verifyRecord('history.checkpoint', next.statement,
      next.signature, publisher.publicKey)).toBe(false)
  })

  it('rejects a rewritten or rolled-back registry and an unpinned signer', async () => {
    const leaves = [registry.registryEntryBytes(await registration()),
      registry.registryEntryBytes(await feedHead())] as Uint8Array[]
    const empty = await signedRegistry(0, await authority.merkleRoot([]), null)
    const next = await signedRegistry(2, await authority.merkleRoot(leaves),
      await registry.registryCheckpointHash(empty.statement))
    const proof = await authority.consistencyProof(leaves, 0)
    expect(await registry.verifyRegistryCheckpoint(next, outsider.publicKey)).toBe(false)
    expect(await registry.verifyRegistryExtension(next, empty, [], publisher.publicKey)).toBe(false)
    expect(await registry.verifyRegistryExtension(empty, { ...next,
      statement: { ...next.statement, root: 'f'.repeat(64) } }, proof, publisher.publicKey)).toBe(false)
    expect(await registry.verifyRegistryExtension(empty, next, ['0'.repeat(64)], publisher.publicKey)).toBe(false)
  })

  it('refuses mismatched entry identity and ambiguous fields', async () => {
    const anchor = await registration()
    const head = await feedHead()
    expect(() => registry.registryEntryBytes({ ...anchor, feedId: 'c'.repeat(64) })).toThrow()
    expect(() => registry.registryEntryBytes({ ...head, index: -1 })).toThrow()
    expect(() => registry.registryEntryBytes({ ...head, extra: true })).toThrow()
    let reads = 0
    const accessor = { ...head }
    Object.defineProperty(accessor, 'feedId', { enumerable: true, get() { reads++; return FEED } })
    expect(() => registry.registryEntryBytes(accessor)).toThrow()
    expect(reads).toBe(0)
  })
})
