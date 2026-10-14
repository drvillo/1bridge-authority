import { sha256, validHash, type Hash } from './hash.js'

export interface MapEntry {
  key: Hash
  valueHash: Hash
}

export interface MapPathStep extends MapEntry {
  sibling: Hash
  direction: 'left' | 'right'
}

export type MapProof =
  | { kind: 'present'; key: Hash; valueHash: Hash; left: Hash; right: Hash; path: MapPathStep[] }
  | { kind: 'absent'; path: MapPathStep[] }

function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('Expected a plain object')
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || fields.some((field) => !keys.includes(field))) {
    throw new TypeError('Unexpected object fields')
  }
  const snapshot: Record<string, unknown> = {}
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) throw new TypeError('Expected enumerable data fields')
    snapshot[field] = descriptor.value
  }
  return snapshot
}

function arrayItems(value: unknown, maxLength?: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError('Expected an array')
  }
  const size = value.length
  if (maxLength !== undefined && size > maxLength) throw new TypeError('Array exceeds maximum length')
  if (Reflect.ownKeys(value).length !== size + 1) throw new TypeError('Expected dense array')
  const items: unknown[] = []
  for (let index = 0; index < size; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) throw new TypeError('Expected dense data array')
    items.push(descriptor.value)
  }
  return items
}

function snapshotEntry(value: unknown): MapEntry {
  const entry = record(value, ['key', 'valueHash'])
  if (!validHash(entry.key) || !validHash(entry.valueHash)) throw new TypeError('Expected lowercase hash entry')
  return { key: entry.key, valueHash: entry.valueHash }
}

function snapshotEntries(value: unknown): MapEntry[] {
  const entries = arrayItems(value).map(snapshotEntry)
  for (let index = 1; index < entries.length; index += 1) {
    if (entries[index - 1]!.key >= entries[index]!.key) throw new TypeError('Expected ascending unique keys')
  }
  return entries
}

function snapshotStep(value: unknown): MapPathStep {
  const step = record(value, ['key', 'valueHash', 'sibling', 'direction'])
  if (!validHash(step.key) || !validHash(step.valueHash) || !validHash(step.sibling)) {
    throw new TypeError('Expected lowercase hash step')
  }
  if (step.direction !== 'left' && step.direction !== 'right') throw new TypeError('Expected path direction')
  return { key: step.key, valueHash: step.valueHash, sibling: step.sibling, direction: step.direction }
}

function snapshotProof(value: unknown): MapProof {
  if (value === null || typeof value !== 'object') throw new TypeError('Expected proof object')
  const kindField = Object.getOwnPropertyDescriptor(value, 'kind')
  if (!kindField || !('value' in kindField)) throw new TypeError('Expected proof kind')
  const kind = kindField.value
  if (kind === 'present') {
    const proof = record(value, ['kind', 'key', 'valueHash', 'left', 'right', 'path'])
    if (!validHash(proof.key) || !validHash(proof.valueHash) || !validHash(proof.left) || !validHash(proof.right)) {
      throw new TypeError('Expected lowercase hash proof')
    }
    return {
      kind: 'present', key: proof.key, valueHash: proof.valueHash, left: proof.left, right: proof.right,
      path: arrayItems(proof.path, 53).map(snapshotStep),
    }
  }
  if (kind === 'absent') {
    const proof = record(value, ['kind', 'path'])
    return { kind: 'absent', path: arrayItems(proof.path, 53).map(snapshotStep) }
  }
  throw new TypeError('Expected proof kind')
}

function hashBytes(hash: Hash): Uint8Array {
  const bytes = new Uint8Array(32)
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(hash.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

async function nodeHash(entry: MapEntry, left: Hash, right: Hash): Promise<Hash> {
  const bytes = new Uint8Array(129)
  bytes[0] = 0x02
  bytes.set(hashBytes(entry.key), 1)
  bytes.set(hashBytes(entry.valueHash), 33)
  bytes.set(hashBytes(left), 65)
  bytes.set(hashBytes(right), 97)
  return sha256(bytes)
}

async function subtreeRoot(entries: readonly MapEntry[], start: number, end: number): Promise<Hash> {
  if (start === end) return sha256(Uint8Array.of(0x03))
  const middle = start + Math.floor((end - start) / 2)
  const left = await subtreeRoot(entries, start, middle)
  const right = await subtreeRoot(entries, middle + 1, end)
  return nodeHash(entries[middle]!, left, right)
}

export async function orderedMapRoot(entries: readonly MapEntry[]): Promise<Hash> {
  const snapshot = snapshotEntries(entries)
  return subtreeRoot(snapshot, 0, snapshot.length)
}

async function searchPath(entries: readonly MapEntry[], key: Hash, start: number, end: number): Promise<MapProof> {
  if (start === end) return { kind: 'absent', path: [] }
  const middle = start + Math.floor((end - start) / 2)
  const entry = entries[middle]!
  if (key === entry.key) {
    return {
      kind: 'present', key: entry.key, valueHash: entry.valueHash,
      left: await subtreeRoot(entries, start, middle),
      right: await subtreeRoot(entries, middle + 1, end), path: [],
    }
  }
  if (key < entry.key) {
    const proof = await searchPath(entries, key, start, middle)
    proof.path.push({ key: entry.key, valueHash: entry.valueHash,
      sibling: await subtreeRoot(entries, middle + 1, end), direction: 'left' })
    return proof
  }
  const proof = await searchPath(entries, key, middle + 1, end)
  proof.path.push({ key: entry.key, valueHash: entry.valueHash,
    sibling: await subtreeRoot(entries, start, middle), direction: 'right' })
  return proof
}

export async function orderedMapProof(entries: readonly MapEntry[], key: Hash): Promise<MapProof> {
  const snapshot = snapshotEntries(entries)
  if (!validHash(key)) throw new TypeError('Expected lowercase hash key')
  return searchPath(snapshot, key, 0, snapshot.length)
}

export async function verifyOrderedMapProof(key: Hash, proof: MapProof, root: Hash): Promise<boolean> {
  try {
    if (!validHash(key) || !validHash(root)) return false
    const snapshot = snapshotProof(proof)
    if (snapshot.kind === 'present' && snapshot.key !== key) return false
    let current = snapshot.kind === 'present'
      ? await nodeHash(snapshot, snapshot.left, snapshot.right)
      : await sha256(Uint8Array.of(0x03))
    let lowest = key
    let highest = key
    for (const step of snapshot.path) {
      if (step.direction === 'left') {
        if (highest >= step.key) return false
        current = await nodeHash(step, current, step.sibling)
        highest = step.key
      } else {
        if (lowest <= step.key) return false
        current = await nodeHash(step, step.sibling, current)
        lowest = step.key
      }
    }
    return current === root
  } catch {
    return false
  }
}
