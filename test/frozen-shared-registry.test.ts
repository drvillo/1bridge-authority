import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'
import { oracleRoot } from './oracle.js'

const vector = JSON.parse(readFileSync(new URL('./fixtures/shared-registry-v1.json', import.meta.url), 'utf8'))

describe('frozen shared-registry cross-repository vector', () => {
  it('matches independent Merkle roots and replays an offline two-feed backlog', async () => {
    const publisher = await authority.importSigningPublicKey(vector.publisherPublicKey)
    const observer = await authority.importSigningPublicKey(vector.observerPublicKey)
    const entries: Uint8Array[] = vector.entries.map((encoded: string) => authority.decodeBase64Url(encoded))
    expect(vector.headOne.statement.root).toBe(oracleRoot(entries.slice(0, 3)))
    expect(vector.headTwo.statement.root).toBe(oracleRoot(entries))
    const replay = await authority.createRegistryReplaySession(vector.genesis, publisher)
    await replay.appendRegistryEntries(entries.slice(0, 2), vector.headOne)
    await replay.appendRegistryEntries(entries.slice(2, 3), vector.headOne)
    await replay.sealRegistryCheckpoint(vector.headOne, vector.proofOne)
    expect(replay.snapshot()).toEqual(vector.snapshotOne)
    expect(await authority.verifyAggregateReport(vector.aggregateOne, observer, publisher,
      vector.snapshotOne.checkpointHash)).toBe(true)
    expect(await authority.verifyAggregateFeedStatus(vector.aggregateOne, vector.pendingProof,
      observer, publisher, vector.snapshotOne.checkpointHash,
      vector.snapshotOne.feeds[1].feedId, vector.snapshotOne.feeds[1].anchorPin)).toBe(true)
    await replay.appendRegistryEntries(entries.slice(3), vector.headTwo)
    await replay.sealRegistryCheckpoint(vector.headTwo, vector.proofTwo)
    expect(replay.snapshot()).toEqual(vector.snapshotTwo)
  })

  it('rejects omitted and substituted registry entries from the frozen target', async () => {
    const publisher = await authority.importSigningPublicKey(vector.publisherPublicKey)
    const entries: Uint8Array[] = vector.entries.map((encoded: string) => authority.decodeBase64Url(encoded))
    const missing = await authority.createRegistryReplaySession(vector.genesis, publisher)
    await expect(missing.appendRegistryEntries(entries.slice(1, 3), vector.headOne)).rejects.toThrow()
    const replaced = await authority.createRegistryReplaySession(vector.genesis, publisher)
    const original = authority.parseCanonical(entries[1]!) as unknown as authority.RegistryEntry
    if (original.kind !== 'feed_head') throw new TypeError('Fixture head missing')
    const signature = original.signedCheckpoint.signature
    const changed = authority.registryEntryBytes({ ...original,
      signedCheckpoint: { ...original.signedCheckpoint,
        signature: (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1) } })
    await replaced.appendRegistryEntries([entries[0]!, changed, entries[2]!], vector.headOne)
    await expect(replaced.sealRegistryCheckpoint(vector.headOne, vector.proofOne)).rejects.toThrow()
  })
})
