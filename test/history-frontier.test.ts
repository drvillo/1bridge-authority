import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import * as authority from '../src/index.js'
import { EMPTY_ROOT, fixtureLeaves } from './oracle.js'

type Frontier = authority.HistoryFrontier

function nodeHash(left: string, right: string): string {
  return createHash('sha256').update(Uint8Array.of(1))
    .update(Buffer.from(left, 'hex')).update(Buffer.from(right, 'hex')).digest('hex')
}

function treeRoot(leaves: readonly Uint8Array[]): string {
  if (leaves.length === 0) return EMPTY_ROOT
  if (leaves.length === 1) {
    return createHash('sha256').update(Uint8Array.of(0)).update(leaves[0]!).digest('hex')
  }
  let split = 1
  while (split * 2 < leaves.length) split *= 2
  return nodeHash(treeRoot(leaves.slice(0, split)), treeRoot(leaves.slice(split)))
}

function expectedSlots(size: number): number[] {
  const bits: number[] = []
  for (let value = size; value > 0; value = Math.floor(value / 2)) bits.push(value % 2)
  return bits
}

function validPeaks(size: number): (string | null)[] {
  return expectedSlots(size).map((bit) => bit === 1 ? 'a'.repeat(64) : null)
}

describe('history frontier', () => {
  it('exports an empty frontier and its RFC empty root', async () => {
    expect(authority).toHaveProperty('emptyHistoryFrontier')
    expect(authority).toHaveProperty('historyFrontierRoot')
    const frontier = authority.emptyHistoryFrontier()
    expect(frontier).toEqual({ size: 0, peaks: [] })
    expect(Reflect.ownKeys(frontier)).toEqual(['size', 'peaks'])
    expect(await authority.historyFrontierRoot(frontier)).toBe(EMPTY_ROOT)
  })

  it('appends 0 through 129 leaves with exact peaks and RFC roots', async () => {
    expect(authority).toHaveProperty('appendHistory')
    const leaves = fixtureLeaves(129)
    let frontier = authority.emptyHistoryFrontier()
    for (let size = 0; size <= leaves.length; size += 1) {
      expect(frontier.size).toBe(size)
      expect(frontier.peaks.length).toBe(expectedSlots(size).length)
      expect(frontier.peaks.map((peak) => peak === null ? 0 : 1)).toEqual(expectedSlots(size))
      const root = await authority.historyFrontierRoot(frontier)
      expect(root).toBe(treeRoot(leaves.slice(0, size)))
      expect(root).toBe(await authority.merkleRoot(leaves.slice(0, size)))
      if (size < leaves.length) {
        const previous = structuredClone(frontier)
        const next = await authority.appendHistory(frontier, leaves[size]!)
        expect(frontier).toEqual(previous)
        expect(next).not.toBe(frontier)
        expect(next.peaks).not.toBe(frontier.peaks)
        frontier = next
      }
    }
  })

  it('rejects malformed frontier sizes, peak counts, occupancy and hashes', async () => {
    const bad: unknown[] = [
      null, undefined, [], {}, { size: 0 }, { peaks: [] },
      ...[-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '0', null].map((size) => ({ size, peaks: [] })),
      { size: 0, peaks: [null] }, { size: 1, peaks: [] }, { size: 1, peaks: [null] },
      { size: 2, peaks: ['a'.repeat(64), 'a'.repeat(64)] },
      { size: 3, peaks: ['a'.repeat(64)] },
      ...['', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64), 4, undefined].map((hash) => ({ size: 1, peaks: [hash] })),
    ]
    for (const input of bad) {
      await expect(authority.historyFrontierRoot(input as Frontier)).rejects.toThrow()
      await expect(authority.appendHistory(input as Frontier, Uint8Array.of(1))).rejects.toThrow()
    }
  })

  it('requires exact plain enumerable data properties and dense plain arrays', async () => {
    const accessorSize = Object.defineProperty({ peaks: [] }, 'size', { enumerable: true, get: () => 0 })
    const accessorPeak = Object.defineProperty([], '0', { enumerable: true, get: () => 'a'.repeat(64) })
    accessorPeak.length = 1
    const sparse = Array(1)
    const extraPeak = Object.assign(['a'.repeat(64)], { note: true })
    const symbolPeak = ['a'.repeat(64)] as (string | null)[]
    Object.defineProperty(symbolPeak, Symbol('extra'), { value: true })
    const nonEnumerableSize = Object.defineProperty({ peaks: [] }, 'size', { value: 0 })
    const inherited = Object.create({ size: 0, peaks: [] })
    const bad = [
      accessorSize, nonEnumerableSize, inherited,
      { size: 0, peaks: [], extra: true },
      { size: 1, peaks: accessorPeak }, { size: 1, peaks: sparse },
      { size: 1, peaks: extraPeak }, { size: 1, peaks: symbolPeak },
      { size: 0, peaks: new (class extends Array<string | null> {})() },
    ]
    for (const input of bad) {
      await expect(authority.historyFrontierRoot(input as Frontier)).rejects.toThrow()
      await expect(authority.appendHistory(input as Frontier, Uint8Array.of(1))).rejects.toThrow()
    }
  })

  it('handles sizes above 32 bits and rejects max-safe append overflow', async () => {
    const size = 2 ** 32 + 5
    const frontier = { size, peaks: validPeaks(size) }
    const next = await authority.appendHistory(frontier, Uint8Array.of(1))
    expect(next.size).toBe(size + 1)
    expect(next.peaks.map((peak) => peak === null ? 0 : 1)).toEqual(expectedSlots(size + 1))
    const nearLimit = { size: Number.MAX_SAFE_INTEGER - 1, peaks: validPeaks(Number.MAX_SAFE_INTEGER - 1) }
    const last = await authority.appendHistory(nearLimit, Uint8Array.of(1))
    expect(last.size).toBe(Number.MAX_SAFE_INTEGER)
    expect(last.peaks.map((peak) => peak === null ? 0 : 1)).toEqual(expectedSlots(Number.MAX_SAFE_INTEGER))
    const original = structuredClone(last)
    await expect(authority.appendHistory(last, Uint8Array.of(1))).rejects.toThrow()
    expect(last).toEqual(original)
  })

  it('rejects non-byte leaves without mutating the frontier', async () => {
    const frontier = { size: 1, peaks: ['a'.repeat(64)] }
    const original = structuredClone(frontier)
    for (const leaf of [null, undefined, 1, 'abc', [], new Uint16Array([1])]) {
      await expect(authority.appendHistory(frontier, leaf as unknown as Uint8Array)).rejects.toThrow()
      expect(frontier).toEqual(original)
    }
  })

  it('snapshots frontier peaks and leaf bytes before the first await', async () => {
    const leaves = fixtureLeaves(3)
    let frontier = authority.emptyHistoryFrontier()
    for (const leaf of leaves.slice(0, 2)) frontier = await authority.appendHistory(frontier, leaf)
    const expected = treeRoot(leaves)
    const leaf = new Uint8Array(leaves[2]!)
    const pending = authority.appendHistory(frontier, leaf)
    frontier.peaks[1] = 'b'.repeat(64)
    leaf.fill(9)
    const result = await pending
    expect(await authority.historyFrontierRoot(result)).toBe(expected)
    const rootPending = authority.historyFrontierRoot(result)
    result.peaks[0] = 'c'.repeat(64)
    expect(await rootPending).toBe(expected)
  })
})
