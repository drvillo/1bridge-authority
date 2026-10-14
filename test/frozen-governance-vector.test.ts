import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

interface GovernanceVector {
  version: 1
  profile: '1bridge.governance/v1'
  anchorPin: string
  signedAnchor: string
  leaves: string[]
  checkpoints: string[]
  expected: authority.GovernanceReplaySnapshot
}

const VECTOR_SHA256 = 'b648945a00e00ea998b8f6a070d620a4ecd2ce05882d66c17b65ca13767d18b5'
const VECTOR_URL = new URL('./fixtures/governance-v1.json', import.meta.url)

function vector(): GovernanceVector {
  return authority.parseCanonical(readFileSync(VECTOR_URL)) as unknown as GovernanceVector
}

function decode(value: GovernanceVector) {
  return {
    anchor: authority.parseCanonical(authority.decodeBase64Url(value.signedAnchor)) as unknown as authority.SignedAuthorityAnchor,
    leaves: value.leaves.map(item => authority.decodeBase64Url(item)),
    checkpoints: value.checkpoints.map(item => authority.parseCanonical(authority.decodeBase64Url(item)) as unknown as authority.SignedCheckpoint),
  }
}

describe('frozen cross-repository governance vector', () => {
  it('pins the exact public evidence bytes for other repositories', () => {
    expect(createHash('sha256').update(readFileSync(VECTOR_URL)).digest('hex')).toBe(VECTOR_SHA256)
  })

  it('replays the same exact public history from the independent anchor pin', async () => {
    const fixture = vector()
    const decoded = decode(fixture)
    expect(Object.keys(fixture).sort()).toEqual(['anchorPin', 'checkpoints', 'expected', 'leaves', 'profile', 'signedAnchor', 'version'])
    expect(fixture.version).toBe(1)
    expect(fixture.profile).toBe('1bridge.governance/v1')
    expect(decoded.leaves).toHaveLength(7)
    expect(decoded.checkpoints).toHaveLength(8)
    expect(fixture.expected.feedId).toBe('a'.repeat(64))
    expect(fixture.expected.policyEpoch).toBe(1)
    expect(fixture.expected.actorHeads).toHaveLength(2)
    await expect(authority.replayGovernanceHistory(decoded.anchor, fixture.anchorPin,
      decoded.leaves, decoded.checkpoints)).resolves.toEqual(fixture.expected)
  })

  it('rejects a different canonical leaf under the frozen signed history', async () => {
    const fixture = vector()
    const decoded = decode(fixture)
    decoded.leaves[6] = decoded.leaves[1]!
    await expect(authority.replayGovernanceHistory(decoded.anchor, fixture.anchorPin,
      decoded.leaves, decoded.checkpoints)).rejects.toThrow()
  })
})
