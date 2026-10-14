import { canonicalBytes, canonicalJson } from './canonical.js'
import { decodeBase64Url } from './encoding.js'
import { sha256, validHash, type Hash } from './hash.js'
import { orderedMapRoot, type MapEntry } from './ordered-map.js'
import { exportSigningPublicKey, importSigningPublicKey, signRecord, signingKeyId, verifyRecord } from './signatures.js'

const encoder = new TextEncoder()
const ANCHOR_PREFIX = encoder.encode('1bridge.authority/v1/anchor-id\n')
const REVISION_PREFIX = encoder.encode('1bridge.authority/v1/revision-id\n')
const SUBJECT_PREFIX = encoder.encode('1bridge.authority/v1/subject\n')
const BINDING_PREFIX = encoder.encode('1bridge.authority/v1/binding\n')
const POLICY_PREFIX = encoder.encode('1bridge.authority/v1/observer-policy\n')
const ACTION_CLASS = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){1,3}$/
const ANCHOR_FIELDS = ['version', 'feedId', 'workspaceId', 'rootKeySpki', 'rootKeyId', 'recoveryKeySpki', 'recoveryKeyId', 'checkpointKeySpki', 'checkpointKeyId', 'authorityRoot', 'policyEpoch', 'observerPolicyHash']
const REVISION_FIELDS = ['version', 'feedId', 'workspaceId', 'number', 'previous', 'previousRoot', 'expectedPolicyEpoch', 'operation', 'authorityRoot', 'policyEpoch', 'signerKeyId']

export interface AuthorityAnchor {
  version: 1
  feedId: Hash
  workspaceId: Hash
  rootKeySpki: string
  rootKeyId: Hash
  recoveryKeySpki: string
  recoveryKeyId: Hash
  checkpointKeySpki: string
  checkpointKeyId: Hash
  authorityRoot: Hash
  policyEpoch: 0
  observerPolicyHash: null
}
export interface SignedAuthorityAnchor { anchor: AuthorityAnchor; rootSignature: string; recoverySignature: string }
export type AuthorityScope = { kind: 'workspace'; workspaceId: Hash } | { kind: 'vault'; workspaceId: Hash; vaultId: Hash }
export interface ActiveBinding { subjectId: Hash; keySpki: string; keyId: Hash; version: number; scope: AuthorityScope; actionClasses: string[]; recipientKeyCommitment: Hash | null; status: 'active' }
export interface RevokedBinding { subjectId: Hash; keyId: Hash; version: number; status: 'revoked' }
export type AuthorityBinding = ActiveBinding | RevokedBinding
export type AuthorityOperation =
  | { kind: 'bind' | 'update' | 'regrant'; binding: ActiveBinding }
  | { kind: 'revoke'; binding: RevokedBinding }
  | { kind: 'policy'; body: unknown | null; policyHash: Hash | null }
  | { kind: 'rotate-checkpoint'; checkpointKeySpki: string; checkpointKeyId: Hash }
  | { kind: 'reset'; rootKeySpki: string; rootKeyId: Hash; recoveryKeySpki: string; recoveryKeyId: Hash; rootPossession: string; recoveryPossession: string }
export type AuthorityBindingOperation = Extract<AuthorityOperation, { binding: AuthorityBinding }>
export interface AuthorityRevision {
  version: 1
  feedId: Hash
  workspaceId: Hash
  number: number
  previous: Hash
  previousRoot: Hash
  expectedPolicyEpoch: number
  operation: AuthorityOperation
  authorityRoot: Hash
  policyEpoch: number
  signerKeyId: Hash
}
export interface SignedAuthorityRevision { statement: AuthorityRevision; signature: string }
export interface AuthoritySnapshot {
  feedId: Hash; workspaceId: Hash; revision: number; revisionHash: Hash; authorityRoot: Hash
  policyEpoch: number; observerPolicyHash: Hash | null; rootKeyId: Hash; recoveryKeyId: Hash
  checkpointKeyId: Hash; checkpointKeySpki: string; bindings: AuthorityBinding[]
}
interface Internal {
  anchor: AuthorityAnchor; pin: Hash; revision: number; revisionHash: Hash; authorityRoot: Hash
  policyEpoch: number; observerPolicyHash: Hash | null; rootKeySpki: string; rootKeyId: Hash
  recoveryKeySpki: string; recoveryKeyId: Hash; checkpointKeySpki: string; checkpointKeyId: Hash
  bindings: Map<Hash, AuthorityBinding>; highWater: Map<Hash, number>; usedKeys: Set<Hash>
}
const states = new WeakMap<AuthorityState, Internal>()
export class AuthorityState { private constructor() {} }
function makeState(value: Internal): AuthorityState {
  const state = Object.freeze(Object.create(AuthorityState.prototype)) as AuthorityState
  states.set(state, value)
  return state
}

function exact(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected plain record')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain record')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== names.length || keys.some(key => typeof key !== 'string' || !names.includes(key))) throw new TypeError('Expected exact record fields')
  const result: Record<string, unknown> = {}
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected enumerable data fields')
    result[name] = descriptor.value
  }
  return result
}
function array(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max || Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError('Expected bounded dense array')
  const result: unknown[] = []
  for (let i = 0; i < value.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i))
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected array data fields')
    result.push(descriptor.value)
  }
  return result
}
function count(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0) }
function positive(value: unknown): value is number { return count(value) && value > 0 }
function signature(value: unknown): string {
  if (typeof value !== 'string' || decodeBase64Url(value, 64).length !== 64) throw new TypeError('Expected canonical 64-byte signature')
  return value
}
function hashBytes(value: Hash): Uint8Array {
  if (!validHash(value)) throw new TypeError('Expected hash')
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = Number.parseInt(value.slice(2 * i, 2 * i + 2), 16)
  return bytes
}
async function domainHash(prefix: Uint8Array, body: Uint8Array): Promise<Hash> {
  const bytes = new Uint8Array(prefix.length + body.length)
  bytes.set(prefix); bytes.set(body, prefix.length)
  return sha256(bytes)
}
async function key(spki: unknown, id: unknown): Promise<CryptoKey> {
  if (typeof spki !== 'string' || !validHash(id)) throw new TypeError('Expected signing key identity')
  const publicKey = await importSigningPublicKey(spki)
  if (await signingKeyId(publicKey) !== id) throw new TypeError('Signing key fingerprint mismatch')
  return publicKey
}
function distinct(ids: readonly Hash[]): void { if (new Set(ids).size !== ids.length) throw new TypeError('Signing roles must use distinct keys') }
function pair(value: unknown): CryptoKeyPair {
  return exact(value, ['publicKey', 'privateKey']) as unknown as CryptoKeyPair
}
function snapshotScope(value: unknown): AuthorityScope {
  const kind = exact(value, Reflect.ownKeys(value as object).includes('vaultId') ? ['kind', 'workspaceId', 'vaultId'] : ['kind', 'workspaceId'])
  if (!validHash(kind.workspaceId)) throw new TypeError('Expected workspace ID')
  if (kind.kind === 'workspace' && !Object.hasOwn(kind, 'vaultId')) return kind as AuthorityScope
  if (kind.kind === 'vault' && validHash(kind.vaultId)) return kind as AuthorityScope
  throw new TypeError('Expected exact authority scope')
}
function snapshotBinding(value: unknown): AuthorityBinding {
  const statusDescriptor = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'status') : undefined
  const status = statusDescriptor && Object.hasOwn(statusDescriptor, 'value') ? statusDescriptor.value : undefined
  if (status === 'revoked') {
    const record = exact(value, ['subjectId', 'keyId', 'version', 'status'])
    if (!validHash(record.subjectId) || !validHash(record.keyId) || !positive(record.version)) throw new TypeError('Invalid tombstone')
    return record as unknown as RevokedBinding
  }
  if (status === 'active') {
    const record = exact(value, ['subjectId', 'keySpki', 'keyId', 'version', 'scope', 'actionClasses', 'recipientKeyCommitment', 'status'])
    if (!validHash(record.subjectId) || !validHash(record.keyId) || !positive(record.version) || typeof record.keySpki !== 'string') throw new TypeError('Invalid active binding')
    if (record.recipientKeyCommitment !== null && !validHash(record.recipientKeyCommitment)) throw new TypeError('Invalid recipient key commitment')
    const classes = array(record.actionClasses, 32)
    if (classes.length === 0 || classes.some(item => typeof item !== 'string' || item.length > 64 || !ACTION_CLASS.test(item))) throw new TypeError('Invalid action classes')
    for (let i = 1; i < classes.length; i++) if ((classes[i - 1] as string) >= (classes[i] as string)) throw new TypeError('Action classes must be sorted and unique')
    return { subjectId: record.subjectId, keySpki: record.keySpki, keyId: record.keyId, version: record.version,
      scope: snapshotScope(record.scope), actionClasses: classes as string[], recipientKeyCommitment: record.recipientKeyCommitment as Hash | null, status: 'active' }
  }
  throw new TypeError('Expected binding status')
}
function snapshotOperation(value: unknown): AuthorityOperation {
  const descriptor = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'kind') : undefined
  const kind = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined
  if (kind === 'bind' || kind === 'update' || kind === 'regrant' || kind === 'revoke') {
    const operation = exact(value, ['kind', 'binding'])
    const binding = snapshotBinding(operation.binding)
    if (kind === 'revoke' ? binding.status !== 'revoked' : binding.status !== 'active') throw new TypeError('Binding status does not match operation')
    return { kind, binding } as AuthorityOperation
  }
  if (kind === 'policy') {
    const operation = exact(value, ['kind', 'body', 'policyHash'])
    if (operation.policyHash !== null && !validHash(operation.policyHash)) throw new TypeError('Expected policy hash')
    if (operation.body === null ? operation.policyHash !== null : operation.policyHash === null) throw new TypeError('Policy hash/body mismatch')
    if (operation.body !== null && canonicalBytes(operation.body).length > 8192) throw new RangeError('Policy body exceeds 8 KiB')
    return { kind, body: operation.body === null ? null : JSON.parse(canonicalJson(operation.body)), policyHash: operation.policyHash as Hash | null }
  }
  if (kind === 'rotate-checkpoint') {
    const operation = exact(value, ['kind', 'checkpointKeySpki', 'checkpointKeyId'])
    if (typeof operation.checkpointKeySpki !== 'string' || !validHash(operation.checkpointKeyId)) throw new TypeError('Expected provider key')
    return operation as unknown as AuthorityOperation
  }
  if (kind === 'reset') {
    const operation = exact(value, ['kind', 'rootKeySpki', 'rootKeyId', 'recoveryKeySpki', 'recoveryKeyId', 'rootPossession', 'recoveryPossession'])
    if (typeof operation.rootKeySpki !== 'string' || !validHash(operation.rootKeyId) || typeof operation.recoveryKeySpki !== 'string' || !validHash(operation.recoveryKeyId)) throw new TypeError('Expected reset keys')
    signature(operation.rootPossession); signature(operation.recoveryPossession)
    return operation as unknown as AuthorityOperation
  }
  throw new TypeError('Unknown authority operation')
}
function snapshotStatement(value: unknown): AuthorityRevision {
  const record = exact(value, REVISION_FIELDS)
  if (record.version !== 1 || !validHash(record.feedId) || !validHash(record.workspaceId) || !positive(record.number)
    || !validHash(record.previous) || !validHash(record.previousRoot) || !count(record.expectedPolicyEpoch)
    || !validHash(record.authorityRoot) || !count(record.policyEpoch) || !validHash(record.signerKeyId)) throw new TypeError('Invalid authority revision')
  return { ...record, operation: snapshotOperation(record.operation) } as unknown as AuthorityRevision
}
function snapshotSigned(value: unknown): SignedAuthorityRevision {
  const record = exact(value, ['statement', 'signature'])
  const signed = { statement: snapshotStatement(record.statement), signature: signature(record.signature) }
  if (canonicalBytes(signed).length > 16384) throw new RangeError('Revision exceeds 16 KiB')
  return signed
}
async function snapshotAnchor(value: unknown): Promise<AuthorityAnchor> {
  const record = exact(value, ANCHOR_FIELDS)
  if (record.version !== 1 || !validHash(record.feedId) || !validHash(record.workspaceId)
    || record.policyEpoch !== 0 || record.observerPolicyHash !== null || record.authorityRoot !== await orderedMapRoot([])) throw new TypeError('Invalid authority anchor')
  await Promise.all([key(record.rootKeySpki, record.rootKeyId), key(record.recoveryKeySpki, record.recoveryKeyId), key(record.checkpointKeySpki, record.checkpointKeyId)])
  distinct([record.rootKeyId, record.recoveryKeyId, record.checkpointKeyId] as Hash[])
  return record as unknown as AuthorityAnchor
}
function internal(state: AuthorityState): Internal {
  const value = states.get(state)
  if (!value) throw new TypeError('Expected verified authority state')
  return value
}
function copyBinding(binding: AuthorityBinding): AuthorityBinding {
  return binding.status === 'revoked' ? { ...binding } : { ...binding, scope: { ...binding.scope }, actionClasses: [...binding.actionClasses] }
}
async function mapRoot(bindings: Map<Hash, AuthorityBinding>): Promise<Hash> {
  const entries: MapEntry[] = []
  for (const binding of bindings.values()) entries.push({ key: await authorityMapKey(binding.subjectId), valueHash: await authorityBindingHash(binding) })
  entries.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
  return orderedMapRoot(entries)
}
function resetCore(statement: AuthorityRevision, operation: Extract<AuthorityOperation, {kind:'reset'}>) {
  return { version: 1, feedId: statement.feedId, workspaceId: statement.workspaceId, number: statement.number, previous: statement.previous,
    rootKeySpki: operation.rootKeySpki, rootKeyId: operation.rootKeyId, recoveryKeySpki: operation.recoveryKeySpki, recoveryKeyId: operation.recoveryKeyId }
}

export async function createAuthorityAnchor(input: {feedId: Hash; workspaceId: Hash; rootPublicKey: CryptoKey; recoveryPublicKey: CryptoKey; checkpointPublicKey: CryptoKey}): Promise<AuthorityAnchor> {
  const fields = exact(input, ['feedId', 'workspaceId', 'rootPublicKey', 'recoveryPublicKey', 'checkpointPublicKey'])
  if (!validHash(fields.feedId) || !validHash(fields.workspaceId)) throw new TypeError('Expected feed and workspace IDs')
  const [rootKeySpki, recoveryKeySpki, checkpointKeySpki, rootKeyId, recoveryKeyId, checkpointKeyId, authorityRoot] = await Promise.all([
    exportSigningPublicKey(fields.rootPublicKey as CryptoKey), exportSigningPublicKey(fields.recoveryPublicKey as CryptoKey), exportSigningPublicKey(fields.checkpointPublicKey as CryptoKey),
    signingKeyId(fields.rootPublicKey as CryptoKey), signingKeyId(fields.recoveryPublicKey as CryptoKey), signingKeyId(fields.checkpointPublicKey as CryptoKey), orderedMapRoot([])])
  distinct([rootKeyId, recoveryKeyId, checkpointKeyId])
  return { version: 1, feedId: fields.feedId, workspaceId: fields.workspaceId, rootKeySpki, rootKeyId, recoveryKeySpki, recoveryKeyId,
    checkpointKeySpki, checkpointKeyId, authorityRoot, policyEpoch: 0, observerPolicyHash: null }
}
export async function anchorHash(anchor: AuthorityAnchor): Promise<Hash> { return domainHash(ANCHOR_PREFIX, canonicalBytes(await snapshotAnchor(anchor))) }
export async function signAuthorityAnchor(anchor: AuthorityAnchor, rootPair: CryptoKeyPair, recoveryPair: CryptoKeyPair): Promise<SignedAuthorityAnchor> {
  const statement = await snapshotAnchor(anchor)
  const root = pair(rootPair); const recovery = pair(recoveryPair)
  if (await signingKeyId(root.publicKey) !== statement.rootKeyId || await signingKeyId(recovery.publicKey) !== statement.recoveryKeyId) throw new TypeError('Anchor signing key mismatch')
  const rootSignature = await signRecord('authority.anchor.root', statement, root.privateKey)
  const recoverySignature = await signRecord('authority.anchor.recovery', statement, recovery.privateKey)
  if (!await verifyRecord('authority.anchor.root', statement, rootSignature, root.publicKey) || !await verifyRecord('authority.anchor.recovery', statement, recoverySignature, recovery.publicKey)) throw new TypeError('Anchor key pair mismatch')
  return { anchor: statement, rootSignature, recoverySignature }
}
export async function verifyAuthorityAnchor(signed: SignedAuthorityAnchor, expectedPin: Hash): Promise<AuthorityState> {
  if (!validHash(expectedPin)) throw new TypeError('An independently authenticated pin is required')
  const record = exact(signed, ['anchor', 'rootSignature', 'recoverySignature'])
  const rootSignature = signature(record.rootSignature); const recoverySignature = signature(record.recoverySignature)
  const anchor = await snapshotAnchor(record.anchor)
  const pin = await anchorHash(anchor)
  if (pin !== expectedPin) throw new TypeError('Anchor pin mismatch')
  const root = await key(anchor.rootKeySpki, anchor.rootKeyId)
  const recovery = await key(anchor.recoveryKeySpki, anchor.recoveryKeyId)
  if (!await verifyRecord('authority.anchor.root', anchor, rootSignature, root)
    || !await verifyRecord('authority.anchor.recovery', anchor, recoverySignature, recovery)) throw new TypeError('Anchor possession proof failed')
  return makeState({ anchor, pin, revision: 0, revisionHash: pin, authorityRoot: anchor.authorityRoot,
    policyEpoch: 0, observerPolicyHash: null, rootKeySpki: anchor.rootKeySpki, rootKeyId: anchor.rootKeyId,
    recoveryKeySpki: anchor.recoveryKeySpki, recoveryKeyId: anchor.recoveryKeyId, checkpointKeySpki: anchor.checkpointKeySpki,
    checkpointKeyId: anchor.checkpointKeyId, bindings: new Map(), highWater: new Map(),
    usedKeys: new Set([anchor.rootKeyId, anchor.recoveryKeyId, anchor.checkpointKeyId]) })
}
export function authorityStateSnapshot(state: AuthorityState): AuthoritySnapshot {
  const value = internal(state)
  return { feedId: value.anchor.feedId, workspaceId: value.anchor.workspaceId, revision: value.revision,
    revisionHash: value.revisionHash, authorityRoot: value.authorityRoot, policyEpoch: value.policyEpoch,
    observerPolicyHash: value.observerPolicyHash, rootKeyId: value.rootKeyId, recoveryKeyId: value.recoveryKeyId,
    checkpointKeyId: value.checkpointKeyId, checkpointKeySpki: value.checkpointKeySpki,
    bindings: [...value.bindings.values()].map(copyBinding).sort((a, b) => a.subjectId < b.subjectId ? -1 : a.subjectId > b.subjectId ? 1 : 0) }
}
export async function authorityMapKey(subjectId: Hash): Promise<Hash> { return domainHash(SUBJECT_PREFIX, hashBytes(subjectId)) }
export async function authorityBindingHash(binding: AuthorityBinding): Promise<Hash> { return domainHash(BINDING_PREFIX, canonicalBytes(snapshotBinding(binding))) }
export async function observerPolicyHash(body: unknown): Promise<Hash> {
  const bytes = canonicalBytes(body)
  if (bytes.length > 8192) throw new RangeError('Policy body exceeds 8 KiB')
  return domainHash(POLICY_PREFIX, bytes)
}
export async function authorityRevisionHash(statement: AuthorityRevision): Promise<Hash> { return domainHash(REVISION_PREFIX, canonicalBytes(snapshotStatement(statement))) }
export async function signAuthorityRevision(statement: AuthorityRevision, signer: CryptoKeyPair): Promise<SignedAuthorityRevision> {
  const snapshot = snapshotStatement(statement)
  const keys = pair(signer)
  if (await signingKeyId(keys.publicKey) !== snapshot.signerKeyId) throw new TypeError('Revision signer mismatch')
  const signed = { statement: snapshot, signature: await signRecord('authority.revision', snapshot, keys.privateKey) }
  if (!await verifyRecord('authority.revision', snapshot, signed.signature, keys.publicKey)) throw new TypeError('Revision signing pair mismatch')
  return snapshotSigned(signed)
}
export async function signAuthorityBindingOperation(state: AuthorityState, operation: AuthorityBindingOperation,
  rootPair: CryptoKeyPair): Promise<SignedAuthorityRevision> {
  const current = internal(state)
  const proposed = snapshotBinding(operation.binding)
  let nextOperation: AuthorityBindingOperation
  if (operation.kind === 'revoke') {
    if (proposed.status !== 'revoked') throw new TypeError('Expected revoked binding')
    nextOperation = { kind: 'revoke', binding: proposed }
  } else {
    if (proposed.status !== 'active') throw new TypeError('Expected active binding')
    nextOperation = { kind: operation.kind, binding: proposed }
  }
  const bindings = new Map(current.bindings)
  bindings.set(proposed.subjectId, proposed)
  const statement: AuthorityRevision = {
    version: 1, feedId: current.anchor.feedId, workspaceId: current.anchor.workspaceId,
    number: current.revision + 1, previous: current.revisionHash, previousRoot: current.authorityRoot,
    expectedPolicyEpoch: current.policyEpoch, operation: nextOperation,
    authorityRoot: await mapRoot(bindings), policyEpoch: current.policyEpoch, signerKeyId: current.rootKeyId,
  }
  const signed = await signAuthorityRevision(statement, rootPair)
  await applyAuthorityRevision(state, signed)
  return signed
}
export async function signAuthorityBindingRevision(state: AuthorityState, binding: ActiveBinding,
  rootPair: CryptoKeyPair): Promise<SignedAuthorityRevision> {
  return signAuthorityBindingOperation(state, { kind: 'bind', binding }, rootPair)
}
export function authorityRevisionLeaf(revision: SignedAuthorityRevision): Uint8Array {
  const signed = snapshotSigned(revision)
  return canonicalBytes({ version: 1, kind: 'authority.revision', revision: signed })
}
export async function applyAuthorityRevision(state: AuthorityState, revision: SignedAuthorityRevision): Promise<AuthorityState> {
  const current = internal(state)
  const signed = snapshotSigned(revision)
  const statement = signed.statement
  if (current.revision === Number.MAX_SAFE_INTEGER || statement.number !== current.revision + 1
    || statement.feedId !== current.anchor.feedId || statement.workspaceId !== current.anchor.workspaceId
    || statement.previous !== current.revisionHash || statement.previousRoot !== current.authorityRoot
    || statement.expectedPolicyEpoch !== current.policyEpoch) throw new TypeError('Stale or foreign authority revision')
  const operation = statement.operation
  const authorizedId = operation.kind === 'reset' ? current.recoveryKeyId : current.rootKeyId
  const authorizedSpki = operation.kind === 'reset' ? current.recoveryKeySpki : current.rootKeySpki
  if (statement.signerKeyId !== authorizedId || !await verifyRecord('authority.revision', statement, signed.signature,
    await key(authorizedSpki, authorizedId))) throw new TypeError('Unauthorized authority revision')
  const next: Internal = { ...current, bindings: new Map(current.bindings), highWater: new Map(current.highWater), usedKeys: new Set(current.usedKeys) }
  if (operation.kind === 'bind' || operation.kind === 'update' || operation.kind === 'regrant' || operation.kind === 'revoke') {
    const binding = operation.binding
    const previous = next.bindings.get(binding.subjectId)
    const highWater = next.highWater.get(binding.subjectId) ?? 0
    if (highWater === Number.MAX_SAFE_INTEGER || binding.version !== highWater + 1) throw new TypeError('Binding version mismatch')
    if (operation.kind === 'bind' && previous || operation.kind === 'update' && previous?.status !== 'active'
      || operation.kind === 'revoke' && previous?.status !== 'active' || operation.kind === 'regrant' && previous?.status !== 'revoked') throw new TypeError('Binding state mismatch')
    if (binding.status === 'active') {
      if (binding.scope.workspaceId !== current.anchor.workspaceId) throw new TypeError('Binding scope mismatch')
      await key(binding.keySpki, binding.keyId)
    }
    if (operation.kind === 'update' || operation.kind === 'revoke') {
      if (previous?.keyId !== binding.keyId || operation.kind === 'update' && previous?.status === 'active' && previous.keySpki !== (binding as ActiveBinding).keySpki) throw new TypeError('Binding key mismatch')
    } else {
      if (next.usedKeys.has(binding.keyId)) throw new TypeError('Signing key has held another role')
      next.usedKeys.add(binding.keyId)
    }
    if (operation.kind === 'bind' && next.bindings.size >= 10000) throw new RangeError('Current subject limit reached')
    next.bindings.set(binding.subjectId, copyBinding(binding)); next.highWater.set(binding.subjectId, binding.version)
  } else if (operation.kind === 'policy') {
    if (current.policyEpoch === Number.MAX_SAFE_INTEGER) throw new RangeError('Policy epoch overflow')
    if (operation.body === null ? operation.policyHash !== null : operation.policyHash !== await observerPolicyHash(operation.body)) throw new TypeError('Policy commitment mismatch')
    next.policyEpoch += 1; next.observerPolicyHash = operation.policyHash
  } else if (operation.kind === 'rotate-checkpoint') {
    await key(operation.checkpointKeySpki, operation.checkpointKeyId)
    if (next.usedKeys.has(operation.checkpointKeyId)) throw new TypeError('Checkpoint key reused')
    next.usedKeys.add(operation.checkpointKeyId)
    next.checkpointKeySpki = operation.checkpointKeySpki; next.checkpointKeyId = operation.checkpointKeyId
  } else if (operation.kind === 'reset') {
    if (current.policyEpoch === Number.MAX_SAFE_INTEGER) throw new RangeError('Policy epoch overflow')
    const root = await key(operation.rootKeySpki, operation.rootKeyId)
    const recovery = await key(operation.recoveryKeySpki, operation.recoveryKeyId)
    distinct([operation.rootKeyId, operation.recoveryKeyId])
    if (next.usedKeys.has(operation.rootKeyId) || next.usedKeys.has(operation.recoveryKeyId)) throw new TypeError('Recovery key reused')
    const core = resetCore(statement, operation)
    if (!await verifyRecord('authority.reset.new-root', core, operation.rootPossession, root)
      || !await verifyRecord('authority.reset.new-recovery', core, operation.recoveryPossession, recovery)) throw new TypeError('New recovery key possession failed')
    next.usedKeys.add(operation.rootKeyId); next.usedKeys.add(operation.recoveryKeyId)
    next.rootKeySpki = operation.rootKeySpki; next.rootKeyId = operation.rootKeyId
    next.recoveryKeySpki = operation.recoveryKeySpki; next.recoveryKeyId = operation.recoveryKeyId
    next.bindings.clear(); next.policyEpoch += 1
  }
  const root = await mapRoot(next.bindings)
  if (root !== statement.authorityRoot || next.policyEpoch !== statement.policyEpoch) throw new TypeError('Authority commitment mismatch')
  next.authorityRoot = root; next.revision = statement.number; next.revisionHash = await authorityRevisionHash(statement)
  return makeState(next)
}
export async function replayAuthorityRevisions(signedAnchor: SignedAuthorityAnchor, expectedPin: Hash, revisions: readonly SignedAuthorityRevision[]): Promise<AuthorityState> {
  if (!Array.isArray(revisions) || Object.getPrototypeOf(revisions) !== Array.prototype || revisions.length > 1024 || Reflect.ownKeys(revisions).length !== revisions.length + 1) throw new TypeError('Expected bounded dense revision batch')
  const snapshots: SignedAuthorityRevision[] = []
  for (let i = 0; i < revisions.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(revisions, String(i))
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Expected revision data entry')
    snapshots.push(snapshotSigned(descriptor.value))
  }
  let state = await verifyAuthorityAnchor(signedAnchor, expectedPin)
  for (const revision of snapshots) state = await applyAuthorityRevision(state, revision)
  return state
}
