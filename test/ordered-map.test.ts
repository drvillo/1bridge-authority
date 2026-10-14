import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { orderedMapProof, orderedMapRoot, verifyOrderedMapProof, type MapEntry, type MapProof } from '../src/index.js'

const hash = (byte: number) => byte.toString(16).padStart(2, '0').repeat(32)
const empty = createHash('sha256').update(Buffer.from([0x03])).digest('hex')
const entries: MapEntry[] = [
  { key: hash(1), valueHash: hash(11) },
  { key: hash(2), valueHash: hash(12) },
  { key: hash(3), valueHash: hash(13) },
]

function node(entry: MapEntry, left = empty, right = empty): string {
  return createHash('sha256')
    .update(Buffer.from([0x02]))
    .update(Buffer.from(entry.key, 'hex'))
    .update(Buffer.from(entry.valueHash, 'hex'))
    .update(Buffer.from(left, 'hex'))
    .update(Buffer.from(right, 'hex'))
    .digest('hex')
}

function oracleRoot(items: readonly MapEntry[]): string {
  if (items.length === 0) return empty
  const middle = Math.floor(items.length / 2)
  return node(items[middle]!, oracleRoot(items.slice(0, middle)), oracleRoot(items.slice(middle + 1)))
}

function fixture(size: number): MapEntry[] {
  return Array.from({ length: size }, (_, index) => ({ key: hash(index * 2 + 2), valueHash: hash(index + 80) }))
}

const sizes = [...Array.from({ length: 34 }, (_, index) => index), 63, 64, 65]

describe('ordered map roots', () => {
  it('uses the exact empty domain and midpoint tree bytes', async () => {
    expect(await orderedMapRoot([])).toBe(empty)
    expect(await orderedMapRoot(entries.slice(0, 1))).toBe(node(entries[0]!))
    expect(await orderedMapRoot(entries.slice(0, 2))).toBe(node(entries[1]!, node(entries[0]!)))
    expect(await orderedMapRoot(entries)).toBe(node(entries[1]!, node(entries[0]!), node(entries[2]!)))
  })

  it.each(sizes)('matches the independent midpoint oracle for size %i', async (size) => {
    const items = fixture(size)
    expect(await orderedMapRoot(items)).toBe(oracleRoot(items))
  })
})

describe('ordered map proofs', () => {
  it.each(sizes)('proves every binding and every gap for size %i', async (size) => {
    const items = fixture(size)
    const root = oracleRoot(items)
    for (let index = 0; index < size; index += 1) {
      const entry = items[index]!
      const proof = await orderedMapProof(items, entry.key)
      expect(proof).toMatchObject({ kind: 'present', key: entry.key, valueHash: entry.valueHash })
      expect(await verifyOrderedMapProof(entry.key, proof, root)).toBe(true)
    }
    for (let index = 0; index <= size; index += 1) {
      const key = hash(index * 2 + 1)
      const proof = await orderedMapProof(items, key)
      expect(proof.kind).toBe('absent')
      expect(await verifyOrderedMapProof(key, proof, root)).toBe(true)
    }
  })

  it('uses bottom-up path steps and authenticates both child roots for presence', async () => {
    const items = fixture(7)
    const proof = await orderedMapProof(items, items[0]!.key)
    expect(proof).toEqual({
      kind: 'present', key: items[0]!.key, valueHash: items[0]!.valueHash,
      left: empty, right: empty,
      path: [
        { key: items[1]!.key, valueHash: items[1]!.valueHash, sibling: node(items[2]!), direction: 'left' },
        { key: items[3]!.key, valueHash: items[3]!.valueHash, sibling: oracleRoot(items.slice(4)), direction: 'left' },
      ],
    })
  })

  it('rejects changed values, roots, keys, siblings, directions, order, and truncation', async () => {
    const items = fixture(7)
    const key = items[0]!.key
    const root = oracleRoot(items)
    const proof = await orderedMapProof(items, key)
    expect(proof.kind).toBe('present')
    if (proof.kind !== 'present') return
    const bad: MapProof[] = [
      { ...proof, valueHash: hash(250) },
      { ...proof, key: items[1]!.key },
      { ...proof, left: hash(250) },
      { ...proof, right: hash(250) },
      { ...proof, path: [{ ...proof.path[0]!, sibling: hash(250) }, ...proof.path.slice(1)] },
      { ...proof, path: [{ ...proof.path[0]!, direction: 'right' }, ...proof.path.slice(1)] },
      { ...proof, path: [...proof.path].reverse() },
      { ...proof, path: proof.path.slice(0, -1) },
    ]
    for (const candidate of bad) expect(await verifyOrderedMapProof(key, candidate, root)).toBe(false)
    expect(await verifyOrderedMapProof(key, proof, hash(250))).toBe(false)
    expect(await verifyOrderedMapProof(items[1]!.key, proof, root)).toBe(false)
  })

  it('rejects absence paths that skip a boundary or violate ancestor ordering', async () => {
    const items = fixture(7)
    const key = hash(1)
    const proof = await orderedMapProof(items, key)
    const root = oracleRoot(items)
    expect(proof.kind).toBe('absent')
    expect(await verifyOrderedMapProof(key, proof, root)).toBe(true)
    expect(await verifyOrderedMapProof(key, { ...proof, path: proof.path.slice(1) }, root)).toBe(false)
    expect(await verifyOrderedMapProof(key, { ...proof, path: [
      { ...proof.path[0]!, direction: 'right' }, ...proof.path.slice(1),
    ] }, root)).toBe(false)
    expect(await verifyOrderedMapProof(items[0]!.key, proof, root)).toBe(false)
  })

  it('rejects nested ancestor keys that cross an outer search bound', async () => {
    const query = hash(5)
    const inner = { key: hash(7), valueHash: hash(77), sibling: empty, direction: 'left' as const }
    const outer = { key: hash(6), valueHash: hash(66), sibling: empty, direction: 'left' as const }
    const forgedRoot = node(outer, node(inner), empty)
    expect(await verifyOrderedMapProof(query, { kind: 'absent', path: [inner, outer] }, forgedRoot)).toBe(false)
  })

  it('rejects malformed generator inputs and ordering before hashing', async () => {
    const items = fixture(3)
    const badEntries: unknown[] = [
      [items[0], items[0]], [items[1], items[0]],
      [{ ...items[0], key: 'A'.repeat(64) }],
      [{ ...items[0], valueHash: 'a'.repeat(63) }],
      [Object.defineProperty({ ...items[0] }, 'key', { enumerable: false })],
      Array(1), null,
      [Object.defineProperty({ valueHash: items[0]!.valueHash }, 'key', { get: () => items[0]!.key, enumerable: true }), items[1]],
    ]
    for (const bad of badEntries) {
      await expect(orderedMapRoot(bad as MapEntry[])).rejects.toThrow()
      await expect(orderedMapProof(bad as MapEntry[], items[0]!.key)).rejects.toThrow()
    }
    for (const key of ['A'.repeat(64), 'a'.repeat(63), null, 1]) {
      await expect(orderedMapProof(items, key as string)).rejects.toThrow()
    }
  })

  it('returns false for malformed proof shape, fields, and excessive depth', async () => {
    const items = fixture(7)
    const key = items[0]!.key
    const root = oracleRoot(items)
    const proof = await orderedMapProof(items, key)
    expect(proof.kind).toBe('present')
    if (proof.kind !== 'present') return
    const malformed: unknown[] = [
      null, {}, [], { ...proof, kind: 'other' }, { ...proof, extra: true },
      { ...proof, key: 'A'.repeat(64) }, { ...proof, valueHash: 'a'.repeat(63) },
      Object.defineProperty({ ...proof }, 'key', { enumerable: false }),
      { ...proof, left: null }, { ...proof, path: Array(1) },
      { ...proof, path: Array(54).fill(proof.path[0]) },
      { ...proof, path: [{ ...proof.path[0], direction: 'other' }, ...proof.path.slice(1)] },
      { ...proof, path: [{ ...proof.path[0], sibling: null }, ...proof.path.slice(1)] },
      { ...proof, path: [{ ...proof.path[0], extra: true }, ...proof.path.slice(1)] },
      { ...proof, path: [Object.defineProperty({ ...proof.path[0] }, 'key', { get: () => proof.path[0]!.key })] },
      { ...proof, path: Object.defineProperty([...proof.path], '0', { get: () => proof.path[0] }) },
    ]
    for (const candidate of malformed) expect(await verifyOrderedMapProof(key, candidate as MapProof, root)).toBe(false)
    expect(await verifyOrderedMapProof('A'.repeat(64), proof, root)).toBe(false)
    expect(await verifyOrderedMapProof(key, proof, 'A'.repeat(64))).toBe(false)
  })

  it('snapshots entries and proof fields before the first asynchronous hash', async () => {
    const items = fixture(7)
    const originalRoot = oracleRoot(items)
    const key = items[0]!.key
    const pendingRoot = orderedMapRoot(items)
    const pendingProof = orderedMapProof(items, key)
    items[0]!.valueHash = hash(255)
    items.reverse()
    expect(await pendingRoot).toBe(originalRoot)
    const proof = await pendingProof
    expect(await verifyOrderedMapProof(key, proof, originalRoot)).toBe(true)
    const pendingCheck = verifyOrderedMapProof(key, proof, originalRoot)
    proof.path[0]!.sibling = hash(255)
    proof.path.reverse()
    expect(await pendingCheck).toBe(true)
  })
})
