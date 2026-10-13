import { describe, expect, it, vi } from 'vitest'
import * as history from '../src/index.js'
import { EMPTY_ROOT, fixtureLeaves, oracleLeaf, oracleNode, oracleRoot } from './oracle.js'

const sizes = [...Array.from({ length: 33 }, (_, index) => index + 1), 63, 64, 65, 127, 128, 129]
const malformedHashes: unknown[] = ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), '0x' + 'a'.repeat(64), 'a'.repeat(64) + '\n', 'a'.repeat(64) + '\r', 'a'.repeat(64) + '\r\n', null, 7, {}]
const invalidNumbers: unknown[] = [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN, null, '1', undefined]

describe('hash domains and roots', () => {
  it('exports the requested hashing functions', () => {
    expect(history).toHaveProperty('hashLeaf')
    expect(history).toHaveProperty('hashNode')
    expect(history).toHaveProperty('merkleRoot')
  })

  it('hashes an empty tree to the literal SHA-256 empty digest', async () => {
    expect(await history.merkleRoot([])).toBe(EMPTY_ROOT)
  })

  it('uses the leaf domain for empty, binary, and UTF-8 bytes', async () => {
    for (const leaf of [new Uint8Array(), Uint8Array.of(0, 1, 255, 128), new TextEncoder().encode('ñ🙂')]) {
      expect(await history.hashLeaf(leaf)).toBe(oracleLeaf(leaf))
    }
    expect(await history.hashLeaf(new Uint8Array())).not.toBe(EMPTY_ROOT)
  })

  it('uses the node domain on decoded 32-byte child hashes', async () => {
    const left = oracleLeaf(Uint8Array.of(1))
    const right = oracleLeaf(Uint8Array.of(2))
    expect(await history.hashNode(left, right)).toBe(oracleNode(left, right))
    expect(await history.hashNode(left, right)).not.toBe(await history.hashNode(right, left))
  })

  it.each(sizes)('matches the independent frontier root for size %i', async (size) => {
    const leaves = fixtureLeaves(size)
    expect(await history.merkleRoot(leaves)).toBe(oracleRoot(leaves))
  })

  it('rejects malformed hash encodings', async () => {
    for (const malformed of malformedHashes) {
      await expect(history.hashNode(malformed as string, EMPTY_ROOT)).rejects.toThrow()
      await expect(history.hashNode(EMPTY_ROOT, malformed as string)).rejects.toThrow()
    }
  })

  it('rejects non-byte leaves and non-array trees', async () => {
    for (const malformed of [null, undefined, 4, {}, [], new Uint16Array([1])]) {
      await expect(history.hashLeaf(malformed as Uint8Array)).rejects.toThrow()
    }
    for (const malformed of [null, undefined, {}, 'leaves', [null], Array(1)]) {
      await expect(history.merkleRoot(malformed as Uint8Array[])).rejects.toThrow()
    }
  })

  it('snapshots a leaf buffer before the first await', async () => {
    const leaf = Uint8Array.of(1, 2, 3)
    const expected = oracleLeaf(leaf)
    const pending = history.hashLeaf(leaf)
    leaf.fill(9)
    expect(await pending).toBe(expected)
  })

  it('rejects malformed array entries even when a custom iterator hides them', async () => {
    const leaves = [null] as unknown as Uint8Array[]
    Object.defineProperty(leaves, Symbol.iterator, { value: function* () { yield Uint8Array.of(1) } })
    await expect(history.merkleRoot(leaves)).rejects.toThrow()
  })

  it('snapshots all root buffers and the array before the first await', async () => {
    const leaves = fixtureLeaves(7)
    const expected = oracleRoot(leaves)
    const pending = history.merkleRoot(leaves)
    for (const leaf of leaves) leaf.fill(9)
    leaves.reverse()
    leaves.push(Uint8Array.of(9))
    expect(await pending).toBe(expected)
  })
})

describe('inclusion proofs', () => {
  it('exports the requested inclusion functions', () => {
    expect(history).toHaveProperty('inclusionProof')
    expect(history).toHaveProperty('verifyInclusion')
  })

  it.each(sizes)('proves every index against an independent root for size %i', async (size) => {
    const leaves = fixtureLeaves(size)
    const root = oracleRoot(leaves)
    for (let index = 0; index < size; index += 1) {
      const proof = await history.inclusionProof(leaves, index)
      expect(await history.verifyInclusion(leaves[index]!, index, size, proof, root)).toBe(true)
    }
  })

  it('uses the RFC seven-leaf inclusion path order', async () => {
    const leaves = fixtureLeaves(7)
    expect(await history.inclusionProof(leaves, 0)).toEqual([
      oracleRoot(leaves.slice(1, 2)),
      oracleRoot(leaves.slice(2, 4)),
      oracleRoot(leaves.slice(4, 7)),
    ])
    expect(await history.inclusionProof(leaves, 6)).toEqual([
      oracleRoot(leaves.slice(4, 6)),
      oracleRoot(leaves.slice(0, 4)),
    ])
  })

  it('uses an empty proof for the only leaf', async () => {
    const leaves = fixtureLeaves(1)
    expect(await history.inclusionProof(leaves, 0)).toEqual([])
    expect(await history.verifyInclusion(leaves[0]!, 0, 1, [], oracleRoot(leaves))).toBe(true)
  })

  it('rejects altered, deleted, and reordered leaf commitments', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    const root = oracleRoot(leaves)
    expect(await history.verifyInclusion(Uint8Array.of(99), 2, 7, proof, root)).toBe(false)
    expect(await history.verifyInclusion(leaves[2]!, 2, 7, proof, oracleRoot(leaves.slice(1)))).toBe(false)
    expect(await history.verifyInclusion(leaves[2]!, 2, 7, proof, oracleRoot([...leaves].reverse()))).toBe(false)
  })

  it('rejects wrong index, size, and root', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    const root = oracleRoot(leaves)
    expect(await history.verifyInclusion(leaves[2]!, 3, 7, proof, root)).toBe(false)
    expect(await history.verifyInclusion(leaves[2]!, 2, 9, proof, root)).toBe(false)
    expect(await history.verifyInclusion(leaves[2]!, 2, 7, proof, EMPTY_ROOT)).toBe(false)
  })

  it('requires a trusted root-size pair because sibling hashes hide subtree sizes', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    expect(await history.verifyInclusion(leaves[2]!, 2, 8, proof, oracleRoot(leaves))).toBe(true)
  })

  it('rejects extra, truncated, altered, reordered, and reversed proof nodes', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    const root = oracleRoot(leaves)
    for (const malformed of [
      [...proof, EMPTY_ROOT],
      proof.slice(1),
      [],
      [EMPTY_ROOT, ...proof.slice(1)],
      [proof[1]!, proof[0]!, ...proof.slice(2)],
      [...proof].reverse(),
    ]) {
      expect(await history.verifyInclusion(leaves[2]!, 2, 7, malformed, root)).toBe(false)
    }
  })

  it('rejects malformed leaf, root, and proof runtime inputs', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    const root = oracleRoot(leaves)
    for (const malformed of malformedHashes) {
      expect(await history.verifyInclusion(leaves[2]!, 2, 7, proof, malformed as string)).toBe(false)
      expect(await history.verifyInclusion(leaves[2]!, 2, 7, [malformed as string, ...proof.slice(1)], root)).toBe(false)
    }
    for (const malformed of [null, undefined, {}, 'proof', Array(proof.length)]) {
      expect(await history.verifyInclusion(leaves[2]!, 2, 7, malformed as string[], root)).toBe(false)
    }
    for (const malformed of [null, undefined, [], {}, new Uint16Array([1])]) {
      expect(await history.verifyInclusion(malformed as Uint8Array, 2, 7, proof, root)).toBe(false)
    }
  })

  it('rejects invalid numeric bounds in generators and verifiers', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    const root = oracleRoot(leaves)
    for (const malformed of invalidNumbers) {
      await expect(history.inclusionProof(leaves, malformed as number)).rejects.toThrow()
      expect(await history.verifyInclusion(leaves[2]!, malformed as number, 7, proof, root)).toBe(false)
      expect(await history.verifyInclusion(leaves[2]!, 2, malformed as number, proof, root)).toBe(false)
    }
    await expect(history.inclusionProof(leaves, leaves.length)).rejects.toThrow()
    await expect(history.inclusionProof([], 0)).rejects.toThrow()
    expect(await history.verifyInclusion(leaves[2]!, 7, 7, proof, root)).toBe(false)
    expect(await history.verifyInclusion(leaves[2]!, 0, 0, [], EMPTY_ROOT)).toBe(false)
    await expect(history.inclusionProof(null as unknown as Uint8Array[], 0)).rejects.toThrow()
    await expect(history.inclusionProof([null] as unknown as Uint8Array[], 0)).rejects.toThrow()
  })

  it('bounds oversized proof arrays before any hashing', async () => {
    const digest = vi.spyOn(globalThis.crypto.subtle, 'digest')
    try {
      expect(await history.verifyInclusion(Uint8Array.of(1), 0, 7, Array(100_000).fill(EMPTY_ROOT), EMPTY_ROOT)).toBe(false)
      expect(digest).not.toHaveBeenCalled()
    } finally {
      digest.mockRestore()
    }
  })

  it('rejects malformed proof entries even when a custom iterator hides them', async () => {
    const leaves = fixtureLeaves(7)
    const valid = await history.inclusionProof(leaves, 2)
    const malformed = Array(valid.length).fill('invalid') as string[]
    Object.defineProperty(malformed, Symbol.iterator, { value: function* () { yield* valid } })
    expect(await history.verifyInclusion(leaves[2]!, 2, 7, malformed, oracleRoot(leaves))).toBe(false)
  })

  it('supports safe integer tree sizes above 32 bits', async () => {
    const leaf = Uint8Array.of(7)
    for (const [size, index, depth] of [
      [2 ** 32, 0, 32],
      [2 ** 32, 2 ** 32 - 1, 32],
      [Number.MAX_SAFE_INTEGER, 0, 53],
    ]) {
      const proof = Array.from({ length: depth! }, (_, level) => oracleLeaf(Uint8Array.of(level)))
      let root = oracleLeaf(leaf)
      for (const sibling of proof) {
        root = index === 0 ? oracleNode(root, sibling) : oracleNode(sibling, root)
      }
      expect(await history.verifyInclusion(leaf, index!, size!, proof, root)).toBe(true)
    }
  })

  it('snapshots all generator leaves before the first await', async () => {
    const leaves = fixtureLeaves(7)
    const expected = await history.inclusionProof(leaves, 2)
    const pending = history.inclusionProof(leaves, 2)
    for (const leaf of leaves) leaf.fill(9)
    leaves.reverse()
    leaves.pop()
    expect(await pending).toEqual(expected)
  })

  it('snapshots verifier leaf bytes and the proof array before the first await', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.inclusionProof(leaves, 2)
    const root = oracleRoot(leaves)
    const pending = history.verifyInclusion(leaves[2]!, 2, 7, proof, root)
    leaves[2]!.fill(9)
    proof.fill(EMPTY_ROOT)
    proof.push(EMPTY_ROOT)
    expect(await pending).toBe(true)
  })
})

describe('consistency proofs', () => {
  it('exports the requested consistency functions', () => {
    expect(history).toHaveProperty('consistencyProof')
    expect(history).toHaveProperty('verifyConsistency')
  })

  it.each([0, ...sizes])('proves every prefix against independent roots for new size %i', async (newSize) => {
    const leaves = fixtureLeaves(newSize)
    const newRoot = oracleRoot(leaves)
    for (let oldSize = 0; oldSize <= newSize; oldSize += 1) {
      const proof = await history.consistencyProof(leaves, oldSize)
      const oldRoot = oracleRoot(leaves.slice(0, oldSize))
      expect(await history.verifyConsistency(oldSize, newSize, oldRoot, newRoot, proof)).toBe(true)
      if (oldSize === 0 || oldSize === newSize) expect(proof).toEqual([])
    }
  })

  it('uses RFC seven-leaf consistency SUBPROOF node order', async () => {
    const leaves = fixtureLeaves(7)
    expect(await history.consistencyProof(leaves, 3)).toEqual([
      oracleRoot(leaves.slice(2, 3)),
      oracleRoot(leaves.slice(3, 4)),
      oracleRoot(leaves.slice(0, 2)),
      oracleRoot(leaves.slice(4, 7)),
    ])
    expect(await history.consistencyProof(leaves, 4)).toEqual([oracleRoot(leaves.slice(4, 7))])
    expect(await history.consistencyProof(leaves, 6)).toEqual([
      oracleRoot(leaves.slice(4, 6)),
      oracleRoot(leaves.slice(6, 7)),
      oracleRoot(leaves.slice(0, 4)),
    ])
  })

  it('requires the correct empty old root and an empty zero-prefix proof', async () => {
    const root = oracleRoot(fixtureLeaves(7))
    expect(await history.verifyConsistency(0, 7, EMPTY_ROOT, root, [])).toBe(true)
    expect(await history.verifyConsistency(0, 7, root, root, [])).toBe(false)
    expect(await history.verifyConsistency(0, 7, EMPTY_ROOT, root, [EMPTY_ROOT])).toBe(false)
    expect(await history.verifyConsistency(0, 0, EMPTY_ROOT, EMPTY_ROOT, [])).toBe(true)
    expect(await history.verifyConsistency(0, 0, EMPTY_ROOT, root, [])).toBe(false)
  })

  it('requires equal roots and an empty proof for equal sizes', async () => {
    const root = oracleRoot(fixtureLeaves(7))
    expect(await history.verifyConsistency(7, 7, root, root, [])).toBe(true)
    expect(await history.verifyConsistency(7, 7, EMPTY_ROOT, root, [])).toBe(false)
    expect(await history.verifyConsistency(7, 7, root, root, [root])).toBe(false)
  })

  it('rejects a mismatched old root even when the new root reconstructs', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    const wrongOldRoot = oracleRoot([Uint8Array.of(99), ...leaves.slice(1, 3)])
    expect(await history.verifyConsistency(3, 7, wrongOldRoot, oracleRoot(leaves), proof)).toBe(false)
  })

  it('rejects a mismatched new root even when the old root reconstructs', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    expect(await history.verifyConsistency(3, 7, oracleRoot(leaves.slice(0, 3)), EMPTY_ROOT, proof)).toBe(false)
  })

  it('rejects altered, deleted, and reordered known prefixes', async () => {
    const leaves = fixtureLeaves(7)
    const oldRoot = oracleRoot(leaves.slice(0, 3))
    for (const changed of [
      [Uint8Array.of(99), ...leaves.slice(1)],
      leaves.slice(1),
      [leaves[1]!, leaves[0]!, ...leaves.slice(2)],
    ]) {
      const proof = await history.consistencyProof(changed, 3)
      expect(await history.verifyConsistency(3, changed.length, oldRoot, oracleRoot(changed), proof)).toBe(false)
    }
  })

  it('rejects incorrect sizes and old sizes larger than the new tree', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    const oldRoot = oracleRoot(leaves.slice(0, 3))
    const newRoot = oracleRoot(leaves)
    expect(await history.verifyConsistency(2, 7, oldRoot, newRoot, proof)).toBe(false)
    expect(await history.verifyConsistency(3, 9, oldRoot, newRoot, proof)).toBe(false)
    expect(await history.verifyConsistency(8, 7, newRoot, newRoot, [])).toBe(false)
  })

  it('rejects extra, truncated, altered, reordered, and reversed proof nodes', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    const oldRoot = oracleRoot(leaves.slice(0, 3))
    const newRoot = oracleRoot(leaves)
    for (const malformed of [
      [...proof, EMPTY_ROOT],
      proof.slice(1),
      proof.slice(0, -1),
      [],
      [EMPTY_ROOT, ...proof.slice(1)],
      [proof[1]!, proof[0]!, ...proof.slice(2)],
      [...proof].reverse(),
    ]) {
      expect(await history.verifyConsistency(3, 7, oldRoot, newRoot, malformed)).toBe(false)
    }
  })

  it('rejects malformed roots and proof runtime inputs', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    const oldRoot = oracleRoot(leaves.slice(0, 3))
    const newRoot = oracleRoot(leaves)
    for (const malformed of malformedHashes) {
      expect(await history.verifyConsistency(3, 7, malformed as string, newRoot, proof)).toBe(false)
      expect(await history.verifyConsistency(3, 7, oldRoot, malformed as string, proof)).toBe(false)
      expect(await history.verifyConsistency(3, 7, oldRoot, newRoot, [malformed as string, ...proof.slice(1)])).toBe(false)
    }
    for (const malformed of [null, undefined, {}, 'proof', Array(proof.length)]) {
      expect(await history.verifyConsistency(3, 7, oldRoot, newRoot, malformed as string[])).toBe(false)
    }
  })

  it('rejects invalid numeric bounds in generators and verifiers', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    const oldRoot = oracleRoot(leaves.slice(0, 3))
    const newRoot = oracleRoot(leaves)
    for (const malformed of invalidNumbers) {
      await expect(history.consistencyProof(leaves, malformed as number)).rejects.toThrow()
      expect(await history.verifyConsistency(malformed as number, 7, oldRoot, newRoot, proof)).toBe(false)
      expect(await history.verifyConsistency(3, malformed as number, oldRoot, newRoot, proof)).toBe(false)
    }
    await expect(history.consistencyProof(leaves, 8)).rejects.toThrow()
    await expect(history.consistencyProof([], 1)).rejects.toThrow()
    await expect(history.consistencyProof(null as unknown as Uint8Array[], 0)).rejects.toThrow()
    await expect(history.consistencyProof([null] as unknown as Uint8Array[], 0)).rejects.toThrow()
  })

  it('bounds oversized proof arrays before any hashing', async () => {
    const digest = vi.spyOn(globalThis.crypto.subtle, 'digest')
    try {
      expect(await history.verifyConsistency(3, 7, EMPTY_ROOT, EMPTY_ROOT, Array(100_000).fill(EMPTY_ROOT))).toBe(false)
      expect(digest).not.toHaveBeenCalled()
    } finally {
      digest.mockRestore()
    }
  })

  it('supports safe integer tree sizes above 32 bits', async () => {
    const prefix = oracleLeaf(Uint8Array.of(1))
    for (const [oldSize, newSize] of [[2 ** 32, 2 ** 33], [2 ** 52, Number.MAX_SAFE_INTEGER]]) {
      const suffix = oracleLeaf(Uint8Array.of(2))
      expect(await history.verifyConsistency(oldSize!, newSize!, prefix, oracleNode(prefix, suffix), [suffix])).toBe(true)
    }
  })

  it('snapshots all generator leaves before the first await', async () => {
    const leaves = fixtureLeaves(7)
    const expected = await history.consistencyProof(leaves, 3)
    const pending = history.consistencyProof(leaves, 3)
    for (const leaf of leaves) leaf.fill(9)
    leaves.reverse()
    leaves.pop()
    expect(await pending).toEqual(expected)
  })

  it('snapshots the verifier proof array before the first await', async () => {
    const leaves = fixtureLeaves(7)
    const proof = await history.consistencyProof(leaves, 3)
    const pending = history.verifyConsistency(3, 7, oracleRoot(leaves.slice(0, 3)), oracleRoot(leaves), proof)
    proof.fill(EMPTY_ROOT)
    proof.push(EMPTY_ROOT)
    expect(await pending).toBe(true)
  })

  it('rejects malformed proof entries even when a custom iterator hides them', async () => {
    const leaves = fixtureLeaves(7)
    const valid = await history.consistencyProof(leaves, 3)
    const malformed = Array(valid.length).fill('invalid') as string[]
    Object.defineProperty(malformed, Symbol.iterator, { value: function* () { yield* valid } })
    expect(await history.verifyConsistency(3, 7, oracleRoot(leaves.slice(0, 3)), oracleRoot(leaves), malformed)).toBe(false)
  })

  it('detects a known C0→x fork against C0→y→z while each own inclusion passes', async () => {
    const [c0, x, y, z] = ['C0', 'x', 'y', 'z'].map((value) => new TextEncoder().encode(value))
    const branchX = [c0!, x!]
    const branchYZ = [c0!, y!, z!]
    const rootX = oracleRoot(branchX)
    const rootYZ = oracleRoot(branchYZ)
    expect(await history.verifyInclusion(x!, 1, 2, await history.inclusionProof(branchX, 1), rootX)).toBe(true)
    expect(await history.verifyInclusion(y!, 1, 3, await history.inclusionProof(branchYZ, 1), rootYZ)).toBe(true)
    expect(await history.verifyInclusion(z!, 2, 3, await history.inclusionProof(branchYZ, 2), rootYZ)).toBe(true)
    const proof = await history.consistencyProof(branchYZ, 2)
    expect(await history.verifyConsistency(2, 3, rootX, rootYZ, proof)).toBe(false)
    expect(await history.verifyConsistency(2, 3, oracleRoot(branchYZ.slice(0, 2)), rootYZ, proof)).toBe(true)
    expect(await history.verifyConsistency(1, 3, oracleRoot([c0!]), rootYZ, await history.consistencyProof(branchYZ, 1))).toBe(true)
  })
})
