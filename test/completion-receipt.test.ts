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
let actor: CryptoKeyPair
let provider: CryptoKeyPair
let action: any
let leaf: Uint8Array

beforeAll(async () => {
  actor = await library.generateSigningKey()
  provider = await library.generateSigningKey()
  action = await api.signGovernanceAction({ version: 1, feedId: FEED, workspaceId: WORKSPACE,
    operationId: OPERATION, actorSubjectId: SUBJECT, actorKeyId: await library.signingKeyId(actor.publicKey),
    actorVersion: 1, scope: { kind: 'workspace', workspaceId: WORKSPACE }, actionClass: 'document.read',
    authorityRevision: 1, authorityRevisionHash: OTHER, authorityRoot: OTHER,
    policyEpoch: 0, observerPolicyHash: null, intentCommitment: COMMITMENT, effectCommitment: COMMITMENT,
    observedCheckpointHash: OBSERVED, previousActionHash: null, previousReceipt: null }, actor)
  leaf = api.governanceCompletionLeaf(action)
})

async function fixture(extra: Uint8Array[] = []) {
  const leaves = [library.canonicalBytes({ kind: 'authority.revision', version: 1, revision: { fixture: 1 } }), leaf, ...extra]
  const checkpoint = await library.signCheckpoint({ version: 1, feedId: FEED, size: leaves.length,
    historyRoot: await library.merkleRoot(leaves), authorityRoot: OTHER, policyEpoch: 0,
    signerKeyId: await library.signingKeyId(provider.publicKey), previous: OBSERVED }, provider)
  const receipt = { version: 1 as const, status: 'integrated' as const, feedId: FEED, operationId: OPERATION,
    actionHash: await api.governanceActionHash(action.statement), effectCommitment: COMMITMENT, leafIndex: 1,
    leafHash: await library.hashLeaf(leaf), checkpoint, inclusionProof: await library.inclusionProof(leaves, 1) }
  return { receipt, checkpoint, leaves }
}

describe('compact integrated completion receipt', () => {
  it('exports a bounded receipt hash and scoped inclusion verifier', () => {
    expect(api).toHaveProperty('completionReceiptHash')
    expect(api).toHaveProperty('verifyReceiptInclusion')
  })

  it('checks the exact canonical leaf against an explicitly supplied signed head', async () => {
    const { receipt, checkpoint } = await fixture()
    expect(await api.verifyReceiptInclusion(receipt, leaf, checkpoint)).toBe(true)
    expect(await api.completionReceiptHash(receipt)).toBe(createHash('sha256')
      .update('1bridge.authority/v1/completion-receipt-id\n').update(library.canonicalBytes(receipt)).digest('hex'))
    expect(await api.verifyReceiptInclusion(receipt, leaf, { ...checkpoint, signature: 'bad' })).toBe(false)
    expect(await api.verifyReceiptInclusion(receipt, library.canonicalBytes({ ...library.parseCanonical(leaf) as object, effectCommitment: OTHER }), checkpoint)).toBe(false)
  })

  it('rejects mismatched leaf identities and RFC inclusion evidence', async () => {
    const { receipt, checkpoint } = await fixture()
    const cases = [
      { ...receipt, feedId: OTHER }, { ...receipt, operationId: OTHER }, { ...receipt, actionHash: OTHER },
      { ...receipt, effectCommitment: OTHER }, { ...receipt, leafHash: OTHER }, { ...receipt, leafIndex: 0 },
      { ...receipt, inclusionProof: [] }, { ...receipt, inclusionProof: [OTHER] },
      { ...receipt, checkpoint: { ...checkpoint, statement: { ...checkpoint.statement, historyRoot: OTHER } } },
    ]
    for (const changed of cases) expect(await api.verifyReceiptInclusion(changed, leaf, checkpoint)).toBe(false)
    expect(await api.verifyReceiptInclusion(receipt, library.canonicalBytes({ ...library.parseCanonical(leaf) as object, extra: 1 }), checkpoint)).toBe(false)
  })

  it('accepts two distinct integrated artifacts for one stable action predecessor', async () => {
    const first = await fixture()
    const second = await fixture([library.canonicalBytes({ kind: 'opaque.fixture', version: 1 })])
    expect(await api.verifyReceiptInclusion(first.receipt, leaf, first.checkpoint)).toBe(true)
    expect(await api.verifyReceiptInclusion(second.receipt, leaf, second.checkpoint)).toBe(true)
    expect(await api.completionReceiptHash(first.receipt)).not.toBe(await api.completionReceiptHash(second.receipt))
    expect(first.receipt.actionHash).toBe(second.receipt.actionHash)
  })

  it('enforces exact receipt fields, counters, proof bounds and canonical signatures', async () => {
    const { receipt, checkpoint } = await fixture()
    const malformed: unknown[] = [
      { ...receipt, extra: 1 }, { ...receipt, version: 2 }, { ...receipt, status: 'pending' },
      { ...receipt, leafIndex: -0 }, { ...receipt, leafIndex: Number.MAX_SAFE_INTEGER + 1 },
      { ...receipt, checkpoint: { ...checkpoint, signature: 'bad' } },
      { ...receipt, inclusionProof: Array.from({ length: 55 }, () => OTHER) },
      { ...receipt, inclusionProof: ['A'.repeat(64)] },
    ]
    let getterCalls = 0
    const accessor = { ...receipt }
    Object.defineProperty(accessor, 'operationId', { enumerable: true, get() { getterCalls++; return OPERATION } })
    malformed.push(accessor)
    for (const bad of malformed) {
      await expect(api.completionReceiptHash(bad)).rejects.toThrow()
      expect(await api.verifyReceiptInclusion(bad, leaf, checkpoint)).toBe(false)
    }
    expect(getterCalls).toBe(0)
  })

  it('does not treat a syntactically valid but unauthorized or tampered head as authenticated', async () => {
    const { receipt, checkpoint } = await fixture()
    const wrong = await library.generateSigningKey()
    const alternative = await library.signCheckpoint({ ...checkpoint.statement,
      signerKeyId: await library.signingKeyId(wrong.publicKey) }, wrong)
    // Inclusion alone says nothing about customer authorization of the provider signer.
    expect(await api.verifyReceiptInclusion({ ...receipt, checkpoint: alternative }, leaf, alternative)).toBe(true)
    expect(await library.verifyCheckpoint(alternative, provider.publicKey)).toBe(false)
  })

  it('snapshots caller-owned leaf bytes before the first await', async () => {
    const { receipt, checkpoint } = await fixture()
    const callerLeaf = new Uint8Array(leaf)
    const pending = api.verifyReceiptInclusion(receipt, callerLeaf, checkpoint)
    callerLeaf[0] = 0
    expect(await pending).toBe(true)
  })
})
