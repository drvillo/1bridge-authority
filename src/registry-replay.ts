import { verifyAuthorityAnchor, type SignedAuthorityAnchor } from './authority-lifecycle.js'
import { canonicalBytes, parseCanonical } from './canonical.js'
import { checkpointHash, type SignedCheckpoint } from './checkpoint.js'
import { type Hash, validHash } from './hash.js'
import { appendHistory, emptyHistoryFrontier, historyFrontierRoot, type HistoryFrontier } from './history-frontier.js'
import { registryCheckpointHash, registryEntryBytes, verifyRegistryCheckpoint,
  verifyRegistryExtension, type RegistryEntry, type SignedRegistryCheckpoint } from './registry.js'

const MAX_PAGE_ENTRIES = 64
const MAX_ENTRY_BYTES = 32 * 1024
const MAX_PAGE_BYTES = 256 * 1024

interface FeedState {
  anchorPin: Hash
  advertisedCheckpointHash: Hash | null
  advertisedSize: number | null
}

export interface RegistryReplaySnapshot {
  size: number
  checkpointHash: Hash
  feeds: ReadonlyArray<Readonly<{ feedId: Hash } & FeedState>>
}

export interface RegistryReplaySession {
  appendRegistryEntries(entries: readonly Uint8Array[], target: SignedRegistryCheckpoint): Promise<void>
  sealRegistryCheckpoint(target: SignedRegistryCheckpoint, proof: readonly Hash[]): Promise<void>
  snapshot(): RegistryReplaySnapshot
}

function densePage(entries: readonly Uint8Array[]): Uint8Array[] {
  if (!Array.isArray(entries) || Object.getPrototypeOf(entries) !== Array.prototype
    || entries.length === 0 || entries.length > MAX_PAGE_ENTRIES
    || Reflect.ownKeys(entries).length !== entries.length + 1) {
    throw new TypeError('Expected bounded dense registry page')
  }
  const copied: Uint8Array[] = []
  let total = 0
  for (let index = 0; index < entries.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(entries, String(index))
    const bytes = descriptor?.value
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')
      || !(bytes instanceof Uint8Array) || Object.getPrototypeOf(bytes) !== Uint8Array.prototype
      || bytes.length === 0 || bytes.length > MAX_ENTRY_BYTES) {
      throw new TypeError('Expected bounded registry entry bytes')
    }
    total += bytes.length
    if (total > MAX_PAGE_BYTES) throw new RangeError('Registry page exceeds byte limit')
    copied.push(new Uint8Array(bytes))
  }
  return copied
}

function signedTarget(value: SignedRegistryCheckpoint): SignedRegistryCheckpoint {
  const bytes = canonicalBytes(value)
  if (bytes.length > 1024) throw new RangeError('Registry checkpoint exceeds byte limit')
  return parseCanonical(bytes) as unknown as SignedRegistryCheckpoint
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

class Replay implements RegistryReplaySession {
  #accepted: SignedRegistryCheckpoint
  #acceptedHash: Hash
  #frontier: HistoryFrontier = emptyHistoryFrontier()
  #feeds = new Map<Hash, FeedState>()
  #tentativeFeeds: Map<Hash, FeedState> | null = null
  #target: SignedRegistryCheckpoint | null = null
  #failed = false
  #busy = false
  #publisher: CryptoKey

  constructor(genesis: SignedRegistryCheckpoint, genesisHash: Hash, publisher: CryptoKey) {
    this.#accepted = genesis
    this.#acceptedHash = genesisHash
    this.#publisher = publisher
  }

  snapshot(): RegistryReplaySnapshot {
    if (this.#failed) throw new TypeError('Cannot read failed registry session')
    const feeds = [...this.#feeds.entries()]
      .map(([feedId, state]) => Object.freeze({ feedId, ...state }))
      .sort((left, right) => left.feedId < right.feedId ? -1 : left.feedId > right.feedId ? 1 : 0)
    return Object.freeze({ size: this.#accepted.statement.size,
      checkpointHash: this.#acceptedHash, feeds: Object.freeze(feeds) })
  }

  async #exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (this.#failed || this.#busy) {
      this.#failed = true
      throw new TypeError('Cannot use failed registry session')
    }
    this.#busy = true
    try { return await work() }
    catch (error) { this.#failed = true; throw error }
    finally { this.#busy = false }
  }

  async #targetFor(value: SignedRegistryCheckpoint): Promise<SignedRegistryCheckpoint> {
    const proposed = signedTarget(value)
    if (this.#target) {
      if (!sameBytes(canonicalBytes(this.#target), canonicalBytes(proposed))) {
        throw new TypeError('Registry target changed within tentative span')
      }
      return this.#target
    }
    if (proposed.statement.size <= this.#accepted.statement.size
      || proposed.statement.previous !== this.#acceptedHash
      || !await verifyRegistryCheckpoint(proposed, this.#publisher)) {
      throw new TypeError('Registry target forks accepted head')
    }
    this.#target = proposed
    this.#tentativeFeeds = new Map(this.#feeds)
    return proposed
  }

  async appendRegistryEntries(entries: readonly Uint8Array[], target: SignedRegistryCheckpoint): Promise<void> {
    return this.#exclusive(async () => {
      const page = densePage(entries)
      const head = await this.#targetFor(target)
      if (this.#frontier.size + page.length > head.statement.size) {
        throw new TypeError('Registry page exceeds fixed target')
      }
      for (const bytes of page) {
        const parsed = parseCanonical(bytes) as unknown as RegistryEntry
        const encoded = registryEntryBytes(parsed)
        if (!sameBytes(bytes, encoded) || parsed.index !== this.#frontier.size) {
          throw new TypeError('Registry entry is not the next canonical leaf')
        }
        const prior = this.#tentativeFeeds!.get(parsed.feedId)
        if (parsed.kind === 'feed_anchor') {
          if (prior) throw new TypeError('Feed is already registered')
          await verifyAuthorityAnchor(parsed.signedAnchor as SignedAuthorityAnchor, parsed.anchorPin)
          this.#tentativeFeeds!.set(parsed.feedId, { anchorPin: parsed.anchorPin,
            advertisedCheckpointHash: null, advertisedSize: null })
        } else {
          if (!prior) throw new TypeError('Feed head precedes registration')
          const signed = parsed.signedCheckpoint as SignedCheckpoint
          const size = signed.statement.size
          const hash = await checkpointHash(signed.statement)
          if (!Number.isSafeInteger(size) || size < 0 || (prior.advertisedSize !== null
            && size <= prior.advertisedSize)) throw new TypeError('Advertised feed head does not advance')
          this.#tentativeFeeds!.set(parsed.feedId, { ...prior,
            advertisedCheckpointHash: hash, advertisedSize: size })
        }
        this.#frontier = await appendHistory(this.#frontier, bytes)
      }
    })
  }

  async sealRegistryCheckpoint(value: SignedRegistryCheckpoint, proof: readonly Hash[]): Promise<void> {
    return this.#exclusive(async () => {
      const head = await this.#targetFor(value)
      if (this.#frontier.size !== head.statement.size
        || await historyFrontierRoot(this.#frontier) !== head.statement.root
        || !await verifyRegistryExtension(this.#accepted, head, proof, this.#publisher)) {
        throw new TypeError('Registry target does not seal replayed entries')
      }
      this.#accepted = head
      this.#acceptedHash = await registryCheckpointHash(head.statement)
      this.#feeds = this.#tentativeFeeds!
      this.#tentativeFeeds = null
      this.#target = null
    })
  }
}

export async function createRegistryReplaySession(genesis: SignedRegistryCheckpoint,
  trustedPublisherKey: CryptoKey): Promise<RegistryReplaySession> {
  const signed = signedTarget(genesis)
  if (signed.statement.size !== 0 || !await verifyRegistryCheckpoint(signed, trustedPublisherKey)) {
    throw new TypeError('Independent signed registry genesis is required')
  }
  const genesisHash = await registryCheckpointHash(signed.statement)
  if (!validHash(genesisHash)) throw new TypeError('Invalid registry genesis hash')
  return new Replay(signed, genesisHash, trustedPublisherKey)
}
