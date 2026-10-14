import { createHash } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import * as library from '../src/index.js'

const api = library as unknown as Record<string, any>
const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)
const SUBJECT = 'c'.repeat(64)
const OPERATION = 'd'.repeat(64)
const COMMITMENT = 'e'.repeat(64)
const OBSERVED = 'f'.repeat(64)
const OTHER = '0'.repeat(64)
let root: CryptoKeyPair
let recovery: CryptoKeyPair
let provider: CryptoKeyPair
let actor: CryptoKeyPair
let secondActor: CryptoKeyPair
let state: library.AuthorityState

beforeAll(async () => {
  const pairs = await Promise.all(Array.from({ length: 5 }, () => library.generateSigningKey()))
  root = pairs[0]!; recovery = pairs[1]!; provider = pairs[2]!; actor = pairs[3]!; secondActor = pairs[4]!
  const anchor = await api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey, checkpointPublicKey: provider.publicKey })
  const signedAnchor = await api.signAuthorityAnchor(anchor, root, recovery)
  state = await api.verifyAuthorityAnchor(signedAnchor, await api.anchorHash(anchor))
  const binding = { subjectId: SUBJECT, keySpki: await library.exportSigningPublicKey(actor.publicKey),
    keyId: await library.signingKeyId(actor.publicKey), version: 1,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'], status: 'active' }
  const authorityRoot = await library.orderedMapRoot([{ key: await api.authorityMapKey(SUBJECT), valueHash: await api.authorityBindingHash(binding) }])
  const current = api.authorityStateSnapshot(state)
  const revision = await api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
    number: 1, previous: current.revisionHash, previousRoot: current.authorityRoot, expectedPolicyEpoch: 0,
    operation: { kind: 'bind', binding }, authorityRoot, policyEpoch: 0, signerKeyId: await library.signingKeyId(root.publicKey) }, root)
  state = await api.applyAuthorityRevision(state, revision)
})

function statement(overrides: Record<string, unknown> = {}) {
  const snapshot = api.authorityStateSnapshot(state)
  return { version: 1 as const, feedId: FEED, workspaceId: WORKSPACE, operationId: OPERATION,
    actorSubjectId: SUBJECT, actorKeyId: snapshot.bindings[0].keyId, actorVersion: 1,
    scope: { kind: 'workspace' as const, workspaceId: WORKSPACE }, actionClass: 'document.read',
    authorityRevision: snapshot.revision, authorityRevisionHash: snapshot.revisionHash,
    authorityRoot: snapshot.authorityRoot, policyEpoch: snapshot.policyEpoch,
    observerPolicyHash: snapshot.observerPolicyHash, intentCommitment: COMMITMENT,
    effectCommitment: COMMITMENT, observedCheckpointHash: OBSERVED,
    previousActionHash: null, previousReceipt: null, ...overrides }
}

describe('signed governance action', () => {
  it('exports the portable action contract', () => {
    for (const name of ['signGovernanceAction', 'verifyGovernanceAction', 'governanceActionHash', 'governanceCompletionLeaf']) {
      expect(api).toHaveProperty(name)
    }
  })

  it('signs a bound actor statement under a distinct purpose and derives a stable statement hash', async () => {
    const signed = await api.signGovernanceAction(statement(), actor)
    expect(await api.verifyGovernanceAction(signed, state)).toBe(true)
    expect(await library.verifyRecord('governance.action', signed.statement, signed.signature, actor.publicKey)).toBe(true)
    expect(await library.verifyRecord('authority.revision', signed.statement, signed.signature, actor.publicKey)).toBe(false)
    const expected = createHash('sha256').update('1bridge.authority/v1/action-id\n').update(library.canonicalBytes(signed.statement)).digest('hex')
    expect(await api.governanceActionHash(signed.statement)).toBe(expected)
    const resigned = await api.signGovernanceAction(statement(), actor)
    expect(await api.governanceActionHash(resigned.statement)).toBe(expected)
    expect(await api.governanceActionHash({ ...signed.statement, operationId: OTHER })).not.toBe(expected)
  })

  it('validates exact binding, authority position, class and scope', async () => {
    const valid = await api.signGovernanceAction(statement(), actor)
    const childVault = await api.signGovernanceAction(statement({ scope: { kind: 'vault', workspaceId: WORKSPACE, vaultId: OTHER } }), actor)
    expect(await api.verifyGovernanceAction(childVault, state)).toBe(true)
    for (const changed of [
      { actorSubjectId: OTHER }, { actorKeyId: OTHER }, { actorVersion: 2 },
      { actionClass: 'document.write' }, { scope: { kind: 'vault', workspaceId: OTHER, vaultId: OTHER } },
      { authorityRevision: 0 }, { authorityRevisionHash: OTHER }, { authorityRoot: OTHER },
      { policyEpoch: 1 }, { observerPolicyHash: OTHER }, { feedId: OTHER }, { workspaceId: OTHER },
    ]) {
      const altered = statement(changed)
      const signed = { statement: altered, signature: await library.signRecord('governance.action', altered, actor.privateKey) }
      expect(await api.verifyGovernanceAction(signed, state)).toBe(false)
    }
    expect(await api.verifyGovernanceAction({ ...valid, signature: await library.signRecord('governance.action', valid.statement, secondActor.privateKey) }, state)).toBe(false)
    await expect(api.signGovernanceAction(statement(), { publicKey: actor.publicKey, privateKey: secondActor.privateKey })).rejects.toThrow()
  })

  it('rejects malformed exact records without invoking accessors', async () => {
    const good = statement()
    const invalid = [
      { ...good, extra: 1 }, { ...good, version: 2 }, { ...good, operationId: 'ABC' },
      { ...good, actionClass: 'not_a.class' }, { ...good, scope: { ...good.scope, extra: 1 } },
      { ...good, actorVersion: 0 }, { ...good, actorVersion: -0 }, { ...good, policyEpoch: -1 },
      { ...good, previousActionHash: OTHER }, { ...good, previousReceipt: {} },
    ]
    let getterCalls = 0
    const accessor = { ...good }
    Object.defineProperty(accessor, 'operationId', { enumerable: true, get() { getterCalls++; return OPERATION } })
    invalid.push(accessor)
    for (const input of invalid) await expect(api.signGovernanceAction(input, actor)).rejects.toThrow()
    expect(getterCalls).toBe(0)
    expect(await api.verifyGovernanceAction({ statement: good, signature: 'bad' }, state)).toBe(false)
  })

  it('uses the embedded prior integrated receipt only as a locally matching predecessor claim', async () => {
    const earlier = await api.signGovernanceAction(statement(), actor)
    const leaf = api.governanceCompletionLeaf(earlier)
    const head = await library.signCheckpoint({ version: 1, feedId: FEED, size: 1,
      historyRoot: await library.merkleRoot([leaf]), authorityRoot: api.authorityStateSnapshot(state).authorityRoot,
      policyEpoch: 0, signerKeyId: await library.signingKeyId(provider.publicKey), previous: OBSERVED }, provider)
    const previousReceipt = { version: 1, status: 'integrated', feedId: FEED, operationId: OPERATION,
      actionHash: await api.governanceActionHash(earlier.statement), effectCommitment: COMMITMENT,
      leafIndex: 0, leafHash: await library.hashLeaf(leaf), checkpoint: head, inclusionProof: [] }
    const next = statement({ operationId: OTHER, previousActionHash: previousReceipt.actionHash, previousReceipt })
    const signed = await api.signGovernanceAction(next, actor)
    expect(await api.verifyGovernanceAction(signed, state)).toBe(true)
    await expect(api.signGovernanceAction(statement({ ...next, previousActionHash: COMMITMENT }), actor)).rejects.toThrow()
    await expect(api.signGovernanceAction(statement({ ...next, previousReceipt: { ...previousReceipt, feedId: OTHER } }), actor)).rejects.toThrow()
  })

  it('enforces a vault-only binding and rejects a later revoked actor at that historical state', async () => {
    const current = api.authorityStateSnapshot(state)
    const bound = { ...current.bindings[0], version: 2, scope: { kind: 'vault', workspaceId: WORKSPACE, vaultId: OTHER } }
    const authorityRoot = await library.orderedMapRoot([{ key: await api.authorityMapKey(SUBJECT), valueHash: await api.authorityBindingHash(bound) }])
    const update = await api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
      number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
      expectedPolicyEpoch: 0, operation: { kind: 'update', binding: bound }, authorityRoot,
      policyEpoch: 0, signerKeyId: await library.signingKeyId(root.publicKey) }, root)
    const vaultState = await api.applyAuthorityRevision(state, update)
    const vaultSnapshot = api.authorityStateSnapshot(vaultState)
    const base = statement({ actorVersion: 2, authorityRevision: vaultSnapshot.revision,
      authorityRevisionHash: vaultSnapshot.revisionHash, authorityRoot: vaultSnapshot.authorityRoot })
    const valid = await api.signGovernanceAction({ ...base, scope: { kind: 'vault', workspaceId: WORKSPACE, vaultId: OTHER } }, actor)
    const workspace = await api.signGovernanceAction(base, actor)
    const foreignVault = await api.signGovernanceAction({ ...base, scope: { kind: 'vault', workspaceId: WORKSPACE, vaultId: OPERATION } }, actor)
    expect(await api.verifyGovernanceAction(valid, vaultState)).toBe(true)
    expect(await api.verifyGovernanceAction(workspace, vaultState)).toBe(false)
    expect(await api.verifyGovernanceAction(foreignVault, vaultState)).toBe(false)
    const tombstone = { subjectId: SUBJECT, keyId: bound.keyId, version: 3, status: 'revoked' }
    const revokedRoot = await library.orderedMapRoot([{ key: await api.authorityMapKey(SUBJECT), valueHash: await api.authorityBindingHash(tombstone) }])
    const revoke = await api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
      number: vaultSnapshot.revision + 1, previous: vaultSnapshot.revisionHash, previousRoot: vaultSnapshot.authorityRoot,
      expectedPolicyEpoch: 0, operation: { kind: 'revoke', binding: tombstone }, authorityRoot: revokedRoot,
      policyEpoch: 0, signerKeyId: await library.signingKeyId(root.publicKey) }, root)
    const revoked = await api.applyAuthorityRevision(vaultState, revoke)
    expect(await api.verifyGovernanceAction(valid, revoked)).toBe(false)
    expect(await api.verifyGovernanceAction(valid, vaultState)).toBe(true)
  })

  it('encodes one exact completed leaf and rejects changed effect or extra wire fields', async () => {
    const signed = await api.signGovernanceAction(statement(), actor)
    const leaf = api.governanceCompletionLeaf(signed)
    expect(library.parseCanonical(leaf)).toEqual({ version: 1, kind: 'governance.completion', action: signed, effectCommitment: COMMITMENT })
    expect(leaf).toEqual(library.canonicalBytes(library.parseCanonical(leaf)))
    expect(await library.hashLeaf(leaf)).not.toBe(await library.hashLeaf(library.canonicalBytes({ ...library.parseCanonical(leaf) as object, effectCommitment: OTHER })))
    expect(() => api.governanceCompletionLeaf({ ...signed, extra: 1 })).toThrow()
    expect(() => api.governanceCompletionLeaf({ ...signed, statement: { ...signed.statement, extra: 1 } })).toThrow()
  })
})
