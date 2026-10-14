import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'

const vector = JSON.parse(readFileSync(new URL('./fixtures/recovery-custody-v1.json', import.meta.url), 'utf8'))

describe('frozen enterprise recovery-custody vector', () => {
  it('accepts a recovery-authorized reset and rejects the former routine root', async () => {
    const recovery = await authority.importSigningPublicKey(vector.signedAnchor.anchor.recoveryKeySpki)
    const oldRoot = await authority.importSigningPublicKey(vector.signedAnchor.anchor.rootKeySpki)
    expect(await authority.verifyRecord('authority.revision', vector.resetRevision.statement,
      vector.resetRevision.signature, recovery)).toBe(true)
    expect(await authority.verifyRecord('authority.revision', vector.oldRootRevision.statement,
      vector.oldRootRevision.signature, oldRoot)).toBe(true)
    const initial = await authority.verifyAuthorityAnchor(vector.signedAnchor, vector.anchorPin)
    const accepted = await authority.applyAuthorityRevision(initial, vector.resetRevision)
    expect(authority.authorityStateSnapshot(accepted)).toMatchObject(vector.expectedAfterReset)
    await expect(authority.applyAuthorityRevision(accepted, vector.oldRootRevision)).rejects.toThrow()
    const replayed = await authority.replayAuthorityRevisions(vector.signedAnchor,
      vector.anchorPin, [vector.resetRevision])
    expect(authority.authorityStateSnapshot(replayed)).toMatchObject(vector.expectedAfterReset)
  })
})
