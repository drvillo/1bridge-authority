import { createHash } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import * as library from '../src/index.js'

const api = library as unknown as Record<string, any>
const FEED = 'a'.repeat(64)
const WORKSPACE = 'b'.repeat(64)
const SUBJECT = 'c'.repeat(64)
const OTHER_SUBJECT = 'd'.repeat(64)
const HASH = 'e'.repeat(64)
let root: CryptoKeyPair
let recovery: CryptoKeyPair
let provider: CryptoKeyPair
let actor: CryptoKeyPair
let actor2: CryptoKeyPair
let other: CryptoKeyPair

beforeAll(async () => {
  const pairs = await Promise.all(Array.from({ length: 6 }, () => library.generateSigningKey()))
  root = pairs[0]!; recovery = pairs[1]!; provider = pairs[2]!; actor = pairs[3]!; actor2 = pairs[4]!; other = pairs[5]!
})

async function anchor() {
  const statement = await api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey, checkpointPublicKey: provider.publicKey })
  return api.signAuthorityAnchor(statement, root, recovery)
}

async function initial() {
  const signed = await anchor()
  const pin = await api.anchorHash(signed.anchor)
  return { signed, pin, state: await api.verifyAuthorityAnchor(signed, pin) }
}

async function active(subjectId = SUBJECT, pair = actor, version = 1) {
  return { subjectId, keySpki: await library.exportSigningPublicKey(pair.publicKey),
    keyId: await library.signingKeyId(pair.publicKey), version,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'], recipientKeyCommitment: null, status: 'active' }
}

async function revision(state: any, operation: any, signer = root, overrides: Record<string, unknown> = {}) {
  const head = api.authorityStateSnapshot(state)
  const bindings = head.bindings.filter((entry: any) => entry.subjectId !== operation.binding?.subjectId)
  if (operation.binding) bindings.push(operation.binding)
  const entries = await Promise.all(bindings.map(async (binding: any) => ({
    key: await api.authorityMapKey(binding.subjectId), valueHash: await api.authorityBindingHash(binding),
  })))
  entries.sort((a, b) => a.key.localeCompare(b.key))
  const authorityRoot = operation.kind === 'reset' ? await library.orderedMapRoot([])
    : operation.binding ? await library.orderedMapRoot(entries) : head.authorityRoot
  const policyEpoch = head.policyEpoch + (operation.kind === 'policy' || operation.kind === 'reset' ? 1 : 0)
  const statement = { version: 1, feedId: FEED, workspaceId: WORKSPACE, number: head.revision + 1,
    previous: head.revisionHash, previousRoot: head.authorityRoot, expectedPolicyEpoch: head.policyEpoch,
    operation, authorityRoot, policyEpoch, signerKeyId: await library.signingKeyId(signer.publicKey), ...overrides }
  return api.signAuthorityRevision(statement, signer)
}

interface MixedFixtureCase {
  signedAnchor: library.SignedAuthorityAnchor
  pin: string
  oldHead: library.SignedCheckpoint
  newHead: library.SignedCheckpoint
  leaves: Uint8Array[]
  proof: string[]
}

async function replayFixturePrefix(fixture: MixedFixtureCase, size: number) {
  let state = await api.verifyAuthorityAnchor(fixture.signedAnchor, fixture.pin)
  for (const leaf of fixture.leaves.slice(0, size)) {
    const parsed = library.parseCanonical(leaf) as Record<string, any>
    if (parsed.version !== 1) throw new TypeError('Unknown fixture leaf version')
    if (parsed.kind === 'authority.revision' && Object.keys(parsed).sort().join(',') === 'kind,revision,version') {
      state = await api.applyAuthorityRevision(state, parsed.revision)
    } else if (parsed.kind === 'action.placeholder' && Object.keys(parsed).sort().join(',') === 'kind,version') {
      // This fixed opaque leaf exercises ordering and RFC history only; no action semantics are claimed.
      if (new TextDecoder().decode(leaf) !== library.canonicalJson({ kind: 'action.placeholder', version: 1 })) {
        throw new TypeError('Unexpected fixture placeholder')
      }
    } else {
      throw new TypeError('Unknown fixture leaf')
    }
  }
  return state
}

async function verifyMixedFixtureExtension(fixture: MixedFixtureCase): Promise<boolean> {
  try {
    const oldSize = fixture.oldHead.statement.size
    const newSize = fixture.newHead.statement.size
    if (oldSize >= newSize || newSize !== fixture.leaves.length) return false
    const oldState = api.authorityStateSnapshot(await replayFixturePrefix(fixture, oldSize))
    const newState = api.authorityStateSnapshot(await replayFixturePrefix(fixture, newSize))
    const oldRoot = await library.merkleRoot(fixture.leaves.slice(0, oldSize))
    const newRoot = await library.merkleRoot(fixture.leaves)
    const oldHead = fixture.oldHead.statement
    const newHead = fixture.newHead.statement
    if (oldHead.feedId !== oldState.feedId || newHead.feedId !== newState.feedId
      || oldHead.historyRoot !== oldRoot || newHead.historyRoot !== newRoot
      || oldHead.authorityRoot !== oldState.authorityRoot || newHead.authorityRoot !== newState.authorityRoot
      || oldHead.policyEpoch !== oldState.policyEpoch || newHead.policyEpoch !== newState.policyEpoch
      || oldHead.signerKeyId !== oldState.checkpointKeyId || newHead.signerKeyId !== newState.checkpointKeyId
      || newHead.previous !== await library.checkpointHash(oldHead)) return false
    const oldKey = await library.importSigningPublicKey(oldState.checkpointKeySpki)
    const newKey = await library.importSigningPublicKey(newState.checkpointKeySpki)
    return await library.verifyCheckpoint(fixture.oldHead, oldKey)
      && await library.verifyCheckpoint(fixture.newHead, newKey)
      && await library.verifyConsistency(oldSize, newSize, oldRoot, newRoot, fixture.proof)
  } catch {
    return false
  }
}

describe('customer authority lifecycle', () => {
  it('exports the pin-first authority contract', () => {
    for (const name of ['createAuthorityAnchor', 'signAuthorityAnchor', 'anchorHash', 'verifyAuthorityAnchor',
      'authorityStateSnapshot', 'authorityMapKey', 'authorityBindingHash', 'observerPolicyHash',
      'authorityRevisionHash', 'signAuthorityRevision', 'applyAuthorityRevision',
      'replayAuthorityRevisions', 'authorityRevisionLeaf']) expect(api).toHaveProperty(name)
  })

  it('requires an independent pin and both possession proofs', async () => {
    const { signed, pin, state } = await initial()
    const snapshot = api.authorityStateSnapshot(state)
    expect(snapshot.revision).toBe(0)
    expect(snapshot.revisionHash).toBe(pin)
    expect(snapshot.authorityRoot).toBe(await library.orderedMapRoot([]))
    const expected = createHash('sha256').update('1bridge.authority/v1/anchor-id\n').update(library.canonicalBytes(signed.anchor)).digest('hex')
    expect(pin).toBe(expected)
    await expect(api.verifyAuthorityAnchor(signed, HASH)).rejects.toThrow()
    await expect(api.verifyAuthorityAnchor(signed)).rejects.toThrow()
    await expect(api.verifyAuthorityAnchor({ ...signed, recoverySignature: signed.rootSignature }, pin)).rejects.toThrow()
    await expect(api.verifyAuthorityAnchor({ ...signed, anchor: { ...signed.anchor, feedId: HASH } }, pin)).rejects.toThrow()
    await expect(api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
      rootPublicKey: root.publicKey, recoveryPublicKey: root.publicKey, checkpointPublicKey: provider.publicKey })).rejects.toThrow()
  })

  it('binds, updates, revokes, and regrants with exact roots and retained tombstones', async () => {
    let { state } = await initial()
    const first = await revision(state, { kind: 'bind', binding: await active() })
    state = await api.applyAuthorityRevision(state, first)
    expect(api.authorityStateSnapshot(state).revision).toBe(1)
    expect(api.authorityStateSnapshot(state).bindings).toEqual([await active()])
    expect(api.authorityStateSnapshot(state).authorityRoot).toBe(first.statement.authorityRoot)
    const independentKey = createHash('sha256').update('1bridge.authority/v1/subject\n').update(Buffer.from(SUBJECT, 'hex')).digest('hex')
    const independentValue = createHash('sha256').update('1bridge.authority/v1/binding\n').update(library.canonicalBytes(await active())).digest('hex')
    expect(first.statement.authorityRoot).toBe(await library.orderedMapRoot([{ key: independentKey, valueHash: independentValue }]))
    expect(await api.authorityRevisionHash(first.statement)).toBe(api.authorityStateSnapshot(state).revisionHash)
    expect(library.parseCanonical(api.authorityRevisionLeaf(first))).toEqual({ version: 1, kind: 'authority.revision', revision: first })
    const updateBinding = { ...await active(SUBJECT, actor, 2), actionClasses: ['document.read', 'document.write'] }
    state = await api.applyAuthorityRevision(state, await revision(state, { kind: 'update', binding: updateBinding }))
    const tombstone = { subjectId: SUBJECT, keyId: await library.signingKeyId(actor.publicKey), version: 3, status: 'revoked' }
    state = await api.applyAuthorityRevision(state, await revision(state, { kind: 'revoke', binding: tombstone }))
    expect(api.authorityStateSnapshot(state).bindings).toEqual([tombstone])
    state = await api.applyAuthorityRevision(state, await revision(state, { kind: 'regrant', binding: await active(SUBJECT, actor2, 4) }))
    expect(api.authorityStateSnapshot(state).bindings).toEqual([await active(SUBJECT, actor2, 4)])
    expect(await api.authorityMapKey(SUBJECT)).not.toBe(await api.authorityMapKey(OTHER_SUBJECT))
  })

  it('constructs a root-signed binding from verified state and refuses stale reuse', async () => {
    const { state } = await initial()
    const binding = await active()
    const signed = await api.signAuthorityBindingRevision(state, binding, root)
    expect(signed.statement.operation).toEqual({ kind: 'bind', binding })
    expect(signed.statement.previous).toBe(api.authorityStateSnapshot(state).revisionHash)
    const next = await api.applyAuthorityRevision(state, signed)
    expect(api.authorityStateSnapshot(next).bindings).toEqual([binding])
    await expect(api.applyAuthorityRevision(next, signed)).rejects.toThrow()
    await expect(api.signAuthorityBindingRevision(state, binding, other)).rejects.toThrow()
    await expect(api.signAuthorityBindingRevision(next, binding, root)).rejects.toThrow()
  })

  it('constructs signed binding updates and tombstones from the current authority map', async () => {
    const { state } = await initial()
    const first = await api.signAuthorityBindingRevision(state, await active(), root)
    const bound = await api.applyAuthorityRevision(state, first)
    const updated = { ...await active(SUBJECT, actor, 2), actionClasses: ['document.read', 'document.write'] }
    const signedUpdate = await api.signAuthorityBindingOperation(bound,
      { kind: 'update', binding: updated }, root)
    expect(signedUpdate.statement.operation).toEqual({ kind: 'update', binding: updated })
    const changed = await api.applyAuthorityRevision(bound, signedUpdate)
    expect(api.authorityStateSnapshot(changed).bindings).toEqual([updated])
    const tombstone = { subjectId: SUBJECT, keyId: updated.keyId, version: 3, status: 'revoked' }
    const signedRevoke = await api.signAuthorityBindingOperation(changed,
      { kind: 'revoke', binding: tombstone }, root)
    const revoked = await api.applyAuthorityRevision(changed, signedRevoke)
    expect(api.authorityStateSnapshot(revoked).bindings).toEqual([tombstone])
    expect(signedRevoke.statement.authorityRoot).toBe(api.authorityStateSnapshot(revoked).authorityRoot)
    await expect(api.signAuthorityBindingOperation(changed,
      { kind: 'revoke', binding: { ...tombstone, version: 4 } }, root)).rejects.toThrow()
    await expect(api.signAuthorityBindingOperation(changed,
      { kind: 'revoke', binding: tombstone }, other)).rejects.toThrow()
  })

  it('refuses a binding revision when its map commitment is changed', async () => {
    const { state } = await initial()
    const signed = await api.signAuthorityBindingRevision(state, await active(), root)
    await expect(api.applyAuthorityRevision(state, { ...signed, statement: {
      ...signed.statement, authorityRoot: HASH,
    } })).rejects.toThrow()
  })

  it('commits the exact recipient key hash to the signed binding and permits a root-signed version update', async () => {
    let { state } = await initial()
    const unbound = await active()
    const recipientKeyCommitment = '1'.repeat(64)
    const bound = { ...unbound, recipientKeyCommitment }
    expect(await api.authorityBindingHash(bound)).not.toBe(await api.authorityBindingHash(unbound))
    const first = await revision(state, { kind: 'bind', binding: bound })
    state = await api.applyAuthorityRevision(state, first)
    expect(api.authorityStateSnapshot(state).bindings).toEqual([bound])
    const updated = { ...bound, version: 2, recipientKeyCommitment: '2'.repeat(64) }
    const second = await revision(state, { kind: 'update', binding: updated })
    const next = await api.applyAuthorityRevision(state, second)
    expect(api.authorityStateSnapshot(next).bindings).toEqual([updated])
    expect(api.authorityStateSnapshot(next).authorityRoot).not.toBe(api.authorityStateSnapshot(state).authorityRoot)
    await expect(api.applyAuthorityRevision(state, { ...second, statement: { ...second.statement,
      operation: { kind: 'update', binding: { ...updated, recipientKeyCommitment: recipientKeyCommitment } } } })).rejects.toThrow()
  })

  it('rejects omitted, invalid and extra recipient commitment fields', async () => {
    const { state } = await initial()
    const valid = await active()
    const { recipientKeyCommitment: _omitted, ...missing } = valid
    for (const binding of [missing, { ...valid, recipientKeyCommitment: 'A'.repeat(64) },
      { ...valid, recipientKeyCommitment: undefined }, { ...valid, recipientKeyCommitment: null, extra: 1 }]) {
      await expect(revision(state, { kind: 'bind', binding })).rejects.toThrow()
    }
  })

  it('rejects sibling revisions, invalid versions, wrong signer and reused actor keys', async () => {
    const { state } = await initial()
    const first = await revision(state, { kind: 'bind', binding: await active() })
    const next = await api.applyAuthorityRevision(state, first)
    await expect(api.applyAuthorityRevision(next, first)).rejects.toThrow()
    await expect(api.applyAuthorityRevision(next, await revision(state, { kind: 'bind', binding: await active(OTHER_SUBJECT, actor2) }))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active(SUBJECT, actor, 2) }))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active(SUBJECT, actor) }, other))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(next, await revision(next, { kind: 'bind', binding: await active(OTHER_SUBJECT, actor) }))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active() }, root, { authorityRoot: HASH }))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active() }, root, { number: 2 }))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active() }, root, { previous: HASH }))).rejects.toThrow()
  })

  it('enforces class syntax, scope, key-role separation and strict record shapes', async () => {
    const { state } = await initial()
    for (const actionClasses of [['document.write', 'document.read'], ['document.read', 'document.read'], ['bad'], []]) {
      await expect(revision(state, { kind: 'bind', binding: { ...await active(), actionClasses } })).rejects.toThrow()
    }
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active(SUBJECT, root) }))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: { ...await active(), scope: { kind: 'workspace', workspaceId: HASH } } }))).rejects.toThrow()
    await expect(revision(state, { kind: 'bind', binding: { ...await active(), extra: true } })).rejects.toThrow()
    let getterCalls = 0
    const bad = { ...await active() }
    Object.defineProperty(bad, 'keyId', { enumerable: true, get() { getterCalls++; return HASH } })
    await expect(revision(state, { kind: 'bind', binding: bad })).rejects.toThrow()
    expect(getterCalls).toBe(0)
  })

  it('changes policy by root signature and preserves it through recovery reset', async () => {
    let { state } = await initial()
    const body = { observer: 'example', strict: true }
    const policyHash = await api.observerPolicyHash(body)
    state = await api.applyAuthorityRevision(state, await revision(state, { kind: 'policy', body, policyHash }))
    expect(api.authorityStateSnapshot(state).policyEpoch).toBe(1)
    expect(api.authorityStateSnapshot(state).observerPolicyHash).toBe(policyHash)
    const newRoot = await library.generateSigningKey()
    const newRecovery = await library.generateSigningKey()
    const head = api.authorityStateSnapshot(state)
    const resetCore = { version: 1, feedId: FEED, workspaceId: WORKSPACE, number: head.revision + 1,
      previous: head.revisionHash, rootKeySpki: await library.exportSigningPublicKey(newRoot.publicKey),
      rootKeyId: await library.signingKeyId(newRoot.publicKey), recoveryKeySpki: await library.exportSigningPublicKey(newRecovery.publicKey),
      recoveryKeyId: await library.signingKeyId(newRecovery.publicKey) }
    const portableCore = api.recoveryResetCore(resetCore)
    expect(portableCore).toEqual(resetCore)
    expect(() => api.recoveryResetCore({ ...resetCore, extra: true })).toThrow()
    const reset = { kind: 'reset', ...Object.fromEntries(Object.entries(resetCore).filter(([key]) => !['version', 'feedId', 'workspaceId', 'number', 'previous'].includes(key))),
      rootPossession: await library.signRecord('authority.reset.new-root', portableCore, newRoot.privateKey),
      recoveryPossession: await library.signRecord('authority.reset.new-recovery', portableCore, newRecovery.privateKey) }
    const signed = await revision(state, reset, recovery)
    await expect(api.applyAuthorityRevision(state, await revision(state, reset, root))).rejects.toThrow()
    state = await api.applyAuthorityRevision(state, signed)
    expect(api.authorityStateSnapshot(state).policyEpoch).toBe(2)
    expect(api.authorityStateSnapshot(state).observerPolicyHash).toBe(policyHash)
    expect(api.authorityStateSnapshot(state).authorityRoot).toBe(await library.orderedMapRoot([]))
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active() }, root))).rejects.toThrow()
  })

  it('retains subject high water and all used key roles after reset', async () => {
    let { state } = await initial()
    state = await api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active() }))
    const newRoot = await library.generateSigningKey()
    const newRecovery = await library.generateSigningKey()
    const head = api.authorityStateSnapshot(state)
    const core = { version: 1, feedId: FEED, workspaceId: WORKSPACE, number: head.revision + 1,
      previous: head.revisionHash, rootKeySpki: await library.exportSigningPublicKey(newRoot.publicKey),
      rootKeyId: await library.signingKeyId(newRoot.publicKey), recoveryKeySpki: await library.exportSigningPublicKey(newRecovery.publicKey),
      recoveryKeyId: await library.signingKeyId(newRecovery.publicKey) }
    const reset = { kind: 'reset', rootKeySpki: core.rootKeySpki, rootKeyId: core.rootKeyId,
      recoveryKeySpki: core.recoveryKeySpki, recoveryKeyId: core.recoveryKeyId,
      rootPossession: await library.signRecord('authority.reset.new-root', core, newRoot.privateKey),
      recoveryPossession: await library.signRecord('authority.reset.new-recovery', core, newRecovery.privateKey) }
    state = await api.applyAuthorityRevision(state, await revision(state, reset, recovery))
    expect(api.authorityStateSnapshot(state).bindings).toEqual([])
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active(SUBJECT, actor, 1) }, newRoot))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active(SUBJECT, actor, 2) }, newRoot))).rejects.toThrow()
    state = await api.applyAuthorityRevision(state, await revision(state, { kind: 'bind', binding: await active(SUBJECT, actor2, 2) }, newRoot))
    expect(api.authorityStateSnapshot(state).bindings).toEqual([await active(SUBJECT, actor2, 2)])
    await expect(api.applyAuthorityRevision(state, await revision(state, { kind: 'policy', body: null, policyHash: null }, root))).rejects.toThrow()
    await expect(api.applyAuthorityRevision(state, await revision(state, { ...reset }, recovery))).rejects.toThrow()
  })

  it('allows only root-authorized fresh provider rotation', async () => {
    const { state } = await initial()
    const rotated = { kind: 'rotate-checkpoint', checkpointKeySpki: await library.exportSigningPublicKey(other.publicKey),
      checkpointKeyId: await library.signingKeyId(other.publicKey) }
    await expect(api.applyAuthorityRevision(state, await revision(state, rotated, provider))).rejects.toThrow()
    const next = await api.applyAuthorityRevision(state, await revision(state, rotated))
    expect(api.authorityStateSnapshot(next).checkpointKeyId).toBe(rotated.checkpointKeyId)
    await expect(api.applyAuthorityRevision(next, await revision(next, { kind: 'rotate-checkpoint', checkpointKeySpki: await library.exportSigningPublicKey(provider.publicKey), checkpointKeyId: await library.signingKeyId(provider.publicKey) }))).rejects.toThrow()
  })

  it('uses fixed domain-separated hashes and rejects alternate serialized leaf bytes', async () => {
    const { state } = await initial()
    const binding = await active()
    const valueHash = createHash('sha256').update('1bridge.authority/v1/binding\n').update(library.canonicalBytes(binding)).digest('hex')
    const keyHash = createHash('sha256').update('1bridge.authority/v1/subject\n').update(Buffer.from(SUBJECT, 'hex')).digest('hex')
    expect(await api.authorityBindingHash(binding)).toBe(valueHash)
    expect(await api.authorityMapKey(SUBJECT)).toBe(keyHash)
    const signed = await revision(state, { kind: 'bind', binding })
    const revisionHash = createHash('sha256').update('1bridge.authority/v1/revision-id\n').update(library.canonicalBytes(signed.statement)).digest('hex')
    expect(await api.authorityRevisionHash(signed.statement)).toBe(revisionHash)
    const leaf = api.authorityRevisionLeaf(signed)
    const parsed = library.parseCanonical(leaf) as any
    expect(parsed).toEqual({ version: 1, kind: 'authority.revision', revision: signed })
    expect(api.authorityStateSnapshot(await api.applyAuthorityRevision(state, parsed.revision)).revision).toBe(1)
    const noncanonical = new TextEncoder().encode(new TextDecoder().decode(leaf).replace('"kind":', '"kind" :'))
    expect(() => library.parseCanonical(noncanonical)).toThrow()
    const duplicate = new TextEncoder().encode(new TextDecoder().decode(leaf).replace('"kind":', '"kind":"authority.revision","kind":'))
    expect(() => library.parseCanonical(duplicate)).toThrow()
  })

  it('accepts only ordered mixed-history extensions with authorized checkpoints', async () => {
    const { signed, pin, state: initialState } = await initial()
    const first = await revision(initialState, { kind: 'bind', binding: await active() })
    const afterBind = await api.applyAuthorityRevision(initialState, first)
    const placeholder = library.canonicalBytes({ kind: 'action.placeholder', version: 1 })
    const firstLeaves = [api.authorityRevisionLeaf(first), placeholder]
    const genesisHead = await library.signCheckpoint({ version: 1, feedId: FEED, size: 0,
      historyRoot: await library.merkleRoot([]), authorityRoot: api.authorityStateSnapshot(initialState).authorityRoot,
      policyEpoch: 0, signerKeyId: await library.signingKeyId(provider.publicKey), previous: null }, provider)
    const firstHead = await library.signCheckpoint({ version: 1, feedId: FEED, size: 2,
      historyRoot: await library.merkleRoot(firstLeaves), authorityRoot: api.authorityStateSnapshot(afterBind).authorityRoot,
      policyEpoch: 0, signerKeyId: await library.signingKeyId(provider.publicKey), previous: await library.checkpointHash(genesisHead.statement) }, provider)
    const firstCase = { signedAnchor: signed, pin, oldHead: genesisHead, newHead: firstHead, leaves: firstLeaves,
      proof: [] as string[] }
    expect(await verifyMixedFixtureExtension(firstCase)).toBe(true)
    const wrongRoot = await library.signCheckpoint({ ...firstHead.statement, authorityRoot: HASH }, provider)
    const wrongEpoch = await library.signCheckpoint({ ...firstHead.statement, policyEpoch: 1 }, provider)
    const wrongHistory = await library.signCheckpoint({ ...firstHead.statement, historyRoot: HASH }, provider)
    const unauthorized = await library.signCheckpoint({ ...firstHead.statement, signerKeyId: await library.signingKeyId(other.publicKey) }, other)
    expect(await library.verifyCheckpoint(wrongRoot, provider.publicKey)).toBe(true)
    expect(await library.verifyCheckpoint(wrongEpoch, provider.publicKey)).toBe(true)
    expect(await verifyMixedFixtureExtension({ ...firstCase, newHead: wrongRoot })).toBe(false)
    expect(await verifyMixedFixtureExtension({ ...firstCase, newHead: wrongEpoch })).toBe(false)
    expect(await verifyMixedFixtureExtension({ ...firstCase, newHead: wrongHistory })).toBe(false)
    expect(await verifyMixedFixtureExtension({ ...firstCase, newHead: unauthorized })).toBe(false)
    expect(await verifyMixedFixtureExtension({ ...firstCase, leaves: [...firstLeaves].reverse() })).toBe(false)

    const rotation = { kind: 'rotate-checkpoint', checkpointKeySpki: await library.exportSigningPublicKey(other.publicKey), checkpointKeyId: await library.signingKeyId(other.publicKey) }
    const rotationRevision = await revision(afterBind, rotation)
    const allLeaves = [...firstLeaves, api.authorityRevisionLeaf(rotationRevision)]
    const proof = await library.consistencyProof(allLeaves, 2)
    const secondHead = await library.signCheckpoint({ ...firstHead.statement, size: 3,
      historyRoot: await library.merkleRoot(allLeaves), signerKeyId: rotation.checkpointKeyId,
      previous: await library.checkpointHash(firstHead.statement) }, other)
    const secondCase = { signedAnchor: signed, pin, oldHead: firstHead, newHead: secondHead, leaves: allLeaves, proof }
    expect(await verifyMixedFixtureExtension(secondCase)).toBe(true)
    expect(await library.verifyCheckpointExtension(firstHead, secondHead, proof, provider.publicKey)).toBe(false)
    const oldSigner = await library.signCheckpoint({ ...secondHead.statement, signerKeyId: await library.signingKeyId(provider.publicKey) }, provider)
    const stalePredecessor = await library.signCheckpoint({ ...secondHead.statement, previous: HASH }, other)
    expect(await verifyMixedFixtureExtension({ ...secondCase, newHead: oldSigner })).toBe(false)
    expect(await verifyMixedFixtureExtension({ ...secondCase, newHead: stalePredecessor })).toBe(false)
    expect(await verifyMixedFixtureExtension({ ...secondCase, proof: [HASH] })).toBe(false)
  })

  it('replays only against the supplied pin and isolates returned snapshots', async () => {
    const { signed, pin, state } = await initial()
    const first = await revision(state, { kind: 'bind', binding: await active() })
    const replayed = await api.replayAuthorityRevisions(signed, pin, [first])
    const view = api.authorityStateSnapshot(replayed)
    view.bindings[0].version = 999
    view.authorityRoot = HASH
    expect(api.authorityStateSnapshot(replayed).bindings[0].version).toBe(1)
    expect(api.authorityStateSnapshot(replayed).authorityRoot).toBe(first.statement.authorityRoot)
    await expect(api.replayAuthorityRevisions(signed, HASH, [first])).rejects.toThrow()
    await expect(api.replayAuthorityRevisions(signed, pin, [first, first])).rejects.toThrow()
    await expect(api.replayAuthorityRevisions(signed, pin, Array(1025).fill(first))).rejects.toThrow()
  })
})
