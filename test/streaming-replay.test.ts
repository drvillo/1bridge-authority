import { expect, it } from 'vitest'
import * as api from '../src/index.js'

const FEED = '1'.repeat(64)
const WORKSPACE = '2'.repeat(64)
const ALICE = '3'.repeat(64)

it('replays a mixed authenticated history beyond the complete-prefix input ceiling', async () => {
  const started = performance.now()
  const [root, recovery, provider, rotated, alice] = await Promise.all([
    api.generateSigningKey(), api.generateSigningKey(), api.generateSigningKey(),
    api.generateSigningKey(), api.generateSigningKey(),
  ])
  const anchor = await api.createAuthorityAnchor({ feedId: FEED, workspaceId: WORKSPACE,
    rootPublicKey: root.publicKey, recoveryPublicKey: recovery.publicKey,
    checkpointPublicKey: provider.publicKey })
  const signedAnchor = await api.signAuthorityAnchor(anchor, root, recovery)
  const pin = await api.anchorHash(anchor)
  let state = await api.verifyAuthorityAnchor(signedAnchor, pin)
  let frontier = api.emptyHistoryFrontier()
  const leaves: Uint8Array[] = []
  const heads: api.SignedCheckpoint[] = []

  async function append(leaf: Uint8Array) {
    leaves.push(leaf)
    frontier = await api.appendHistory(frontier, leaf)
  }
  async function seal(signer: CryptoKeyPair) {
    const current = api.authorityStateSnapshot(state)
    heads.push(await api.signCheckpoint({ version: 1, feedId: FEED, size: leaves.length,
      historyRoot: await api.historyFrontierRoot(frontier), authorityRoot: current.authorityRoot,
      policyEpoch: current.policyEpoch, signerKeyId: await api.signingKeyId(signer.publicKey),
      previous: heads.length ? await api.checkpointHash(heads.at(-1)!.statement) : null }, signer))
  }
  async function revise(operation: api.AuthorityOperation, authorityRoot?: api.Hash) {
    const current = api.authorityStateSnapshot(state)
    const signed = await api.signAuthorityRevision({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
      number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
      expectedPolicyEpoch: current.policyEpoch, operation, authorityRoot: authorityRoot ?? current.authorityRoot,
      policyEpoch: current.policyEpoch + (operation.kind === 'policy' ? 1 : 0),
      signerKeyId: await api.signingKeyId(root.publicKey) }, root)
    state = await api.applyAuthorityRevision(state, signed)
    await append(api.authorityRevisionLeaf(signed))
  }

  await seal(provider)
  const actor: api.ActiveBinding = { subjectId: ALICE,
    keySpki: await api.exportSigningPublicKey(alice.publicKey), keyId: await api.signingKeyId(alice.publicKey),
    version: 1, scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClasses: ['document.read'],
    recipientKeyCommitment: null, status: 'active' }
  const actorRoot = await api.orderedMapRoot([{ key: await api.authorityMapKey(ALICE),
    valueHash: await api.authorityBindingHash(actor) }])
  await revise({ kind: 'bind', binding: actor }, actorRoot)
  await seal(provider)
  const current = api.authorityStateSnapshot(state)
  const signedAction = await api.signGovernanceAction({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
    operationId: '4'.repeat(64), actorSubjectId: ALICE, actorKeyId: actor.keyId, actorVersion: 1,
    scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClass: 'document.read',
    authorityRevision: current.revision, authorityRevisionHash: current.revisionHash,
    authorityRoot: current.authorityRoot, policyEpoch: current.policyEpoch,
    observerPolicyHash: current.observerPolicyHash, intentCommitment: '5'.repeat(64),
    effectCommitment: '6'.repeat(64),
    observedCheckpointHash: await api.checkpointHash(heads.at(-1)!.statement),
    previousActionHash: null, previousReceipt: null }, alice)
  await append(api.governanceCompletionLeaf(signedAction))
  await seal(provider)
  await revise({ kind: 'rotate-checkpoint', checkpointKeySpki: await api.exportSigningPublicKey(rotated.publicKey),
    checkpointKeyId: await api.signingKeyId(rotated.publicKey) })
  await seal(rotated)

  for (let index = 0; index < 10_001; index++) {
    await revise({ kind: 'policy', body: null, policyHash: null })
    if ([100, 1000, 10_000, 10_004].includes(leaves.length)) await seal(rotated)
  }
  expect(leaves.length).toBe(10_004)
  expect(heads.at(-1)!.statement.historyRoot).toBe(await api.merkleRoot(leaves))
  await expect(api.replayGovernanceHistory(signedAnchor, pin, leaves, heads)).rejects.toThrow(/bounded dense leaf/)

  const generatedMs = performance.now() - started
  const session = await api.createGovernanceReplaySession(signedAnchor, pin, heads[0]!)
  let offset = 0
  const samples: { size: number; elapsedMs: number; heapMiB: number }[] = []
  const replayStarted = performance.now()
  for (const head of heads.slice(1)) {
    while (offset < head.statement.size) {
      const next = Math.min(offset + 64, head.statement.size)
      await session.appendLeaves(leaves.slice(offset, next), head)
      offset = next
    }
    await session.sealCheckpoint(head)
    if ([100, 1000, 10_000, 10_004].includes(head.statement.size)) {
      samples.push({ size: head.statement.size, elapsedMs: performance.now() - replayStarted,
        heapMiB: process.memoryUsage().heapUsed / 1024 / 1024 })
    }
  }
  expect(session.snapshot()).toMatchObject({ size: 10_004,
    checkpointHash: await api.checkpointHash(heads.at(-1)!.statement),
    authorityRoot: api.authorityStateSnapshot(state).authorityRoot,
    policyEpoch: 10_001,
    actorHeads: [{ actorKeyId: actor.keyId, actionHash: await api.governanceActionHash(signedAction.statement) }] })
  console.info('streaming replay benchmark', JSON.stringify({ generatedMs, samples }))
}, 120_000)
