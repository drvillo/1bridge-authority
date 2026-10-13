import { createHash } from 'node:crypto'

export const EMPTY_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

export function oracleLeaf(leaf: Uint8Array): string {
  return createHash('sha256').update(Uint8Array.of(0)).update(leaf).digest('hex')
}

export function oracleNode(left: string, right: string): string {
  return createHash('sha256')
    .update(Uint8Array.of(1))
    .update(Buffer.from(left, 'hex'))
    .update(Buffer.from(right, 'hex'))
    .digest('hex')
}

export function oracleRoot(leaves: readonly Uint8Array[]): string {
  const frontier: Array<string | undefined> = []
  for (const leaf of leaves) {
    let current = oracleLeaf(leaf)
    let level = 0
    while (frontier[level] !== undefined) {
      current = oracleNode(frontier[level]!, current)
      frontier[level] = undefined
      level += 1
    }
    frontier[level] = current
  }
  let root: string | undefined
  for (const subtree of frontier) {
    if (subtree !== undefined) {
      root = root === undefined ? subtree : oracleNode(subtree, root)
    }
  }
  return root ?? EMPTY_ROOT
}

export function fixtureLeaves(size: number): Uint8Array[] {
  return Array.from({ length: size }, (_, index) =>
    index % 2 === 0
      ? Uint8Array.of(0, 255, index % 256, Math.floor(index / 256), 128)
      : new TextEncoder().encode(`entry:${index}:ñ:🙂`),
  )
}
