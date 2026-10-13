import { hashLeaf, hashNode, sha256, validHash, type Hash } from './hash.js'

function validSize(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function proofLimit(size: number): number {
  let capacity = 1
  let height = 0
  while (capacity < size) {
    capacity *= 2
    height += 1
  }
  return height
}

function splitSize(size: number): number {
  let split = 1
  while (split * 2 < size) split *= 2
  return split
}

function snapshotLeaves(leaves: readonly Uint8Array[]): Uint8Array[] {
  if (!Array.isArray(leaves)) throw new TypeError('Expected an array of leaves')
  const size = leaves.length
  if (!validSize(size)) throw new TypeError('Expected a nonnegative safe integer array length')
  const snapshot: Uint8Array[] = []
  for (let index = 0; index < size; index += 1) {
    const leaf = leaves[index]
    if (!(leaf instanceof Uint8Array)) throw new TypeError('Expected Uint8Array leaf bytes')
    snapshot.push(new Uint8Array(leaf))
  }
  return snapshot
}

function snapshotProof(proof: readonly Hash[], limit: number): Hash[] | undefined {
  if (!Array.isArray(proof)) return undefined
  const size = proof.length
  if (!validSize(size) || size > limit) return undefined
  const snapshot: Hash[] = []
  for (let index = 0; index < size; index += 1) {
    const hash = proof[index]
    if (!validHash(hash)) return undefined
    snapshot.push(hash)
  }
  return snapshot
}

async function rootHash(leaves: readonly Uint8Array[], start: number, size: number): Promise<Hash> {
  if (size === 0) return sha256(new Uint8Array())
  if (size === 1) return hashLeaf(leaves[start]!)
  const split = splitSize(size)
  const left = await rootHash(leaves, start, split)
  const right = await rootHash(leaves, start + split, size - split)
  return hashNode(left, right)
}

export async function merkleRoot(leaves: readonly Uint8Array[]): Promise<Hash> {
  const snapshot = snapshotLeaves(leaves)
  return rootHash(snapshot, 0, snapshot.length)
}

async function inclusionPath(
  leaves: readonly Uint8Array[], start: number, size: number, index: number,
): Promise<Hash[]> {
  if (size === 1) return []
  const split = splitSize(size)
  if (index < split) {
    const path = await inclusionPath(leaves, start, split, index)
    path.push(await rootHash(leaves, start + split, size - split))
    return path
  }
  const path = await inclusionPath(leaves, start + split, size - split, index - split)
  path.push(await rootHash(leaves, start, split))
  return path
}

export async function inclusionProof(leaves: readonly Uint8Array[], index: number): Promise<Hash[]> {
  const snapshot = snapshotLeaves(leaves)
  if (!validSize(index) || index >= snapshot.length) throw new RangeError('Leaf index is outside the tree')
  return inclusionPath(snapshot, 0, snapshot.length, index)
}

export async function verifyInclusion(
  leaf: Uint8Array, index: number, size: number, proof: readonly Hash[], root: Hash,
): Promise<boolean> {
  try {
    if (!(leaf instanceof Uint8Array) || !validSize(size) || !validSize(index) || index >= size) return false
    if (!validHash(root)) return false
    const path = snapshotProof(proof, proofLimit(size))
    if (path === undefined) return false
    const snapshot = new Uint8Array(leaf)
    let fn = index
    let sn = size - 1
    let reconstructed = await hashLeaf(snapshot)
    for (const sibling of path) {
      if (sn === 0) return false
      if (fn % 2 === 1 || fn === sn) {
        reconstructed = await hashNode(sibling, reconstructed)
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2)
          sn = Math.floor(sn / 2)
        }
      } else {
        reconstructed = await hashNode(reconstructed, sibling)
      }
      fn = Math.floor(fn / 2)
      sn = Math.floor(sn / 2)
    }
    return sn === 0 && reconstructed === root
  } catch {
    return false
  }
}

async function consistencyPath(
  leaves: readonly Uint8Array[], start: number, size: number, oldSize: number, known: boolean,
): Promise<Hash[]> {
  if (oldSize === size) return known ? [] : [await rootHash(leaves, start, size)]
  const split = splitSize(size)
  if (oldSize <= split) {
    const path = await consistencyPath(leaves, start, split, oldSize, known)
    path.push(await rootHash(leaves, start + split, size - split))
    return path
  }
  const path = await consistencyPath(leaves, start + split, size - split, oldSize - split, false)
  path.push(await rootHash(leaves, start, split))
  return path
}

export async function consistencyProof(leaves: readonly Uint8Array[], oldSize: number): Promise<Hash[]> {
  const snapshot = snapshotLeaves(leaves)
  if (!validSize(oldSize) || oldSize > snapshot.length) throw new RangeError('Old size is outside the tree')
  if (oldSize === 0 || oldSize === snapshot.length) return []
  return consistencyPath(snapshot, 0, snapshot.length, oldSize, true)
}

export async function verifyConsistency(
  oldSize: number, newSize: number, oldRoot: Hash, newRoot: Hash, proof: readonly Hash[],
): Promise<boolean> {
  try {
    if (!validSize(oldSize) || !validSize(newSize) || oldSize > newSize) return false
    if (!validHash(oldRoot) || !validHash(newRoot)) return false
    const path = snapshotProof(proof, proofLimit(newSize) + 1)
    if (path === undefined) return false
    if (oldSize === 0) {
      if (path.length !== 0 || oldRoot !== await sha256(new Uint8Array())) return false
      return newSize !== 0 || oldRoot === newRoot
    }
    if (oldSize === newSize) return path.length === 0 && oldRoot === newRoot
    if (path.length === 0) return false

    let fn = oldSize - 1
    let sn = newSize - 1
    while (fn % 2 === 1) {
      fn = Math.floor(fn / 2)
      sn = Math.floor(sn / 2)
    }
    let oldHash = fn === 0 ? oldRoot : path.shift()!
    let newHash = oldHash
    for (const sibling of path) {
      if (sn === 0) return false
      if (fn % 2 === 1 || fn === sn) {
        oldHash = await hashNode(sibling, oldHash)
        newHash = await hashNode(sibling, newHash)
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2)
          sn = Math.floor(sn / 2)
        }
      } else {
        newHash = await hashNode(newHash, sibling)
      }
      fn = Math.floor(fn / 2)
      sn = Math.floor(sn / 2)
    }
    return sn === 0 && oldHash === oldRoot && newHash === newRoot
  } catch {
    return false
  }
}
