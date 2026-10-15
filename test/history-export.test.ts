import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as authority from '../src/index.js'

interface Vector {
  anchorPin: string
  signedAnchor: string
  leaves: string[]
  checkpoints: string[]
  expected: {
    feedId: string
    size: number
    checkpointHash: string
    authorityRevision: number
  }
}

const vector = JSON.parse(readFileSync(new URL('./fixtures/governance-v1.json', import.meta.url), 'utf8')) as Vector

function artifact(checkpoints = vector.checkpoints, leaves = vector.leaves) {
  return { version: 1 as const, signedAnchor: vector.signedAnchor,
    leaves: [...leaves], checkpoints: [...checkpoints],
    advertisedCheckpointHash: vector.expected.checkpointHash }
}

function retained(index: number) {
  return { anchorPin: vector.anchorPin, signedCheckpoint: vector.checkpoints[index]! }
}

afterEach(() => vi.unstubAllGlobals())

describe('portable signed-history export', () => {
  it('verifies an app-shaped file against a separately retained checkpoint without a service connection', async () => {
    vi.stubGlobal('fetch', () => { throw new Error('Unexpected service request') })
    const result = await authority.verifyGovernanceHistoryExport(retained(3), artifact())
    expect(result).toMatchObject(vector.expected)
    expect(result.retainedCheckpointHash).toBe(await authority.checkpointHash(
      (authority.parseCanonical(authority.decodeBase64Url(vector.checkpoints[3]!)) as unknown as authority.SignedCheckpoint).statement,
    ))
    expect(result.signedCheckpoint).toBe(vector.checkpoints.at(-1))
  })

  it('rejects a changed leaf, advertised head and missing retained checkpoint', async () => {
    const changed = artifact()
    changed.leaves[0] = 'AA'
    await expect(authority.verifyGovernanceHistoryExport(retained(3), changed)).rejects.toThrow()
    await expect(authority.verifyGovernanceHistoryExport(retained(3), {
      ...artifact(), advertisedCheckpointHash: '0'.repeat(64),
    })).rejects.toThrow()
    await expect(authority.verifyGovernanceHistoryExport({
      anchorPin: vector.anchorPin, signedCheckpoint: 'AA',
    }, artifact())).rejects.toThrow()
  })

  it('rejects an older candidate than the retained checkpoint', async () => {
    const checkpoints = vector.checkpoints.slice(0, 4)
    const head = authority.parseCanonical(authority.decodeBase64Url(checkpoints.at(-1)!)) as unknown as authority.SignedCheckpoint
    const candidate = { ...artifact(checkpoints, vector.leaves.slice(0, head.statement.size)),
      advertisedCheckpointHash: await authority.checkpointHash(head.statement) }
    await expect(authority.verifyGovernanceHistoryExport(retained(5), candidate)).rejects.toThrow()
  })

  it('requires the exact retained signature, even for the same checkpoint statement', async () => {
    const original = authority.parseCanonical(authority.decodeBase64Url(vector.checkpoints[3]!)) as unknown as authority.SignedCheckpoint
    const unrelated = await authority.generateSigningKey()
    const alternate = { statement: original.statement,
      signature: await authority.signRecord('history.checkpoint', original.statement, unrelated.privateKey) }
    await expect(authority.verifyGovernanceHistoryExport({
      anchorPin: vector.anchorPin,
      signedCheckpoint: authority.encodeBase64Url(authority.canonicalBytes(alternate)),
    }, artifact())).rejects.toThrow(/retained checkpoint/i)
  })
})
