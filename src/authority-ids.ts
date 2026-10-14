import { canonicalBytes } from './canonical.js'
import { sha256, validHash, type Hash } from './hash.js'

const encoder = new TextEncoder()
const kinds = ['workspace', 'vault', 'membership', 'membership-key-row', 'operation'] as const
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const subjectFields = ['workspaceId', 'membershipId', 'actorKeyId'] as const
const subjectPrefix = encoder.encode('1bridge.authority/v1/actor-subject\n')

export type AuthorityIdKind = typeof kinds[number]
export interface AuthoritySubjectIdentity {
  workspaceId: Hash
  membershipId: Hash
  actorKeyId: Hash
}

export async function authorityId(kind: AuthorityIdKind, uuid: string): Promise<Hash> {
  if (!kinds.includes(kind) || typeof uuid !== 'string' || !uuidPattern.test(uuid)) {
    throw new TypeError('Expected fixed authority ID kind and UUID')
  }
  return sha256(encoder.encode(`1bridge.authority/v1/id/${kind}\n${uuid.toLowerCase()}`))
}

export async function authoritySubjectId(identity: AuthoritySubjectIdentity): Promise<Hash> {
  if (identity === null || typeof identity !== 'object' || Array.isArray(identity)) throw new TypeError('Expected actor subject record')
  const prototype = Object.getPrototypeOf(identity)
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Expected plain actor subject record')
  const keys = Reflect.ownKeys(identity)
  if (keys.length !== subjectFields.length || keys.some(key => typeof key !== 'string' || !subjectFields.includes(key as typeof subjectFields[number]))) {
    throw new TypeError('Expected exact actor subject fields')
  }
  const snapshot: Record<string, unknown> = {}
  for (const name of subjectFields) {
    const descriptor = Object.getOwnPropertyDescriptor(identity, name)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value') || !validHash(descriptor.value)) {
      throw new TypeError('Expected enumerable lowercase hash data fields')
    }
    snapshot[name] = descriptor.value
  }
  const body = canonicalBytes(snapshot)
  const bytes = new Uint8Array(subjectPrefix.length + body.length)
  bytes.set(subjectPrefix)
  bytes.set(body, subjectPrefix.length)
  return sha256(bytes)
}
