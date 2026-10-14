import { hashLeaf, hashNode, sha256, validHash, type Hash } from './hash.js'

export interface HistoryFrontier {
  size: number
  peaks: (Hash | null)[]
}

export function emptyHistoryFrontier(): HistoryFrontier {
  return { size: 0, peaks: [] }
}

function snapshotFrontier(frontier: HistoryFrontier): HistoryFrontier {
  if (frontier === null || typeof frontier !== 'object' || Object.getPrototypeOf(frontier) !== Object.prototype) {
    throw new TypeError('Expected a plain history frontier')
  }
  const keys = Reflect.ownKeys(frontier)
  if (keys.length !== 2 || !keys.includes('size') || !keys.includes('peaks')) {
    throw new TypeError('Expected only size and peaks fields')
  }
  const sizeField = Object.getOwnPropertyDescriptor(frontier, 'size')
  const peaksField = Object.getOwnPropertyDescriptor(frontier, 'peaks')
  if (!sizeField?.enumerable || !('value' in sizeField) || !peaksField?.enumerable || !('value' in peaksField)) {
    throw new TypeError('Expected enumerable data fields')
  }
  const size: unknown = sizeField.value
  const source: unknown = peaksField.value
  if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) {
    throw new TypeError('Expected a nonnegative safe integer size')
  }
  if (!Array.isArray(source) || Object.getPrototypeOf(source) !== Array.prototype) {
    throw new TypeError('Expected a plain peaks array')
  }
  const bits: number[] = []
  for (let value = size; value > 0; value = Math.floor(value / 2)) bits.push(value % 2)
  if (source.length !== bits.length || Reflect.ownKeys(source).length !== bits.length + 1) {
    throw new TypeError('Expected exact dense peaks array')
  }
  const peaks: (Hash | null)[] = []
  for (let height = 0; height < bits.length; height += 1) {
    const field = Object.getOwnPropertyDescriptor(source, String(height))
    if (!field?.enumerable || !('value' in field)) throw new TypeError('Expected data peak')
    const peak: unknown = field.value
    if (bits[height] === 1 ? !validHash(peak) : peak !== null) {
      throw new TypeError('Peak does not match size bit')
    }
    peaks.push(peak as Hash | null)
  }
  return { size, peaks }
}

export async function appendHistory(frontier: HistoryFrontier, leaf: Uint8Array): Promise<HistoryFrontier> {
  const snapshot = snapshotFrontier(frontier)
  if (!(leaf instanceof Uint8Array)) throw new TypeError('Expected Uint8Array leaf bytes')
  if (snapshot.size === Number.MAX_SAFE_INTEGER) throw new RangeError('History size would overflow')
  const bytes = new Uint8Array(leaf)
  let carry = await hashLeaf(bytes)
  let remainder = snapshot.size
  let height = 0
  while (remainder % 2 === 1) {
    carry = await hashNode(snapshot.peaks[height]!, carry)
    snapshot.peaks[height] = null
    remainder = Math.floor(remainder / 2)
    height += 1
  }
  snapshot.peaks[height] = carry
  return { size: snapshot.size + 1, peaks: snapshot.peaks }
}

export async function historyFrontierRoot(frontier: HistoryFrontier): Promise<Hash> {
  const { peaks } = snapshotFrontier(frontier)
  let root: Hash | undefined
  for (const peak of peaks) {
    if (peak !== null) root = root === undefined ? peak : await hashNode(peak, root)
  }
  return root ?? sha256(new Uint8Array())
}
