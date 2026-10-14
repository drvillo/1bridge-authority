// Internal RFC 9474 arithmetic. The package root does not export this module.
const MODULUS_BYTES = 512
const HASH_BYTES = 48
const SALT_BYTES = 48

export function os2ip(bytes: Uint8Array): bigint {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new TypeError('Expected nonempty integer bytes')
  return BigInt('0x' + Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(''))
}

export function i2osp(value: bigint, length: number): Uint8Array {
  if (typeof value !== 'bigint' || value < 0n || !Number.isSafeInteger(length) || length < 1 || value >= (1n << BigInt(length * 8))) {
    throw new RangeError('Integer does not fit width')
  }
  const encoded = value.toString(16).padStart(length * 2, '0')
  const result = new Uint8Array(length)
  for (let index = 0; index < length; index += 1) result[index] = Number.parseInt(encoded.slice(index * 2, index * 2 + 2), 16)
  return result
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n || exponent < 0n) throw new RangeError('Expected positive modulus and nonnegative exponent')
  let result = 1n
  let power = base % modulus
  for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
    if (remaining & 1n) result = result * power % modulus
    power = power * power % modulus
  }
  return result
}

export function modInverse(value: bigint, modulus: bigint): bigint {
  if (value <= 0n || value >= modulus) throw new RangeError('Expected integer in modulus range')
  let oldR = modulus
  let r = value
  let oldT = 0n
  let t = 1n
  while (r !== 0n) {
    const quotient = oldR / r
    const nextR = oldR - quotient * r
    const nextT = oldT - quotient * t
    oldR = r
    r = nextR
    oldT = t
    t = nextT
  }
  if (oldR !== 1n) throw new RangeError('Integer is not invertible')
  return (oldT % modulus + modulus) % modulus
}

async function sha384(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-384', new Uint8Array(bytes)))
}

async function mgf1(seed: Uint8Array, length: number): Promise<Uint8Array> {
  const output = new Uint8Array(length)
  const block = new Uint8Array(seed.length + 4)
  block.set(seed)
  for (let offset = 0, counter = 0; offset < length; offset += HASH_BYTES, counter += 1) {
    new DataView(block.buffer).setUint32(seed.length, counter, false)
    output.set((await sha384(block)).subarray(0, Math.min(HASH_BYTES, length - offset)), offset)
  }
  return output
}

export async function emsaPssEncode(message: Uint8Array, salt: Uint8Array, emBits: number): Promise<Uint8Array> {
  if (!(message instanceof Uint8Array) || !(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) throw new TypeError('Expected message and 48-byte PSS salt')
  if (!Number.isSafeInteger(emBits) || emBits < 8 * HASH_BYTES + 8 * SALT_BYTES + 9) throw new RangeError('Invalid encoded-message bit length')
  const emLen = Math.ceil(emBits / 8)
  const dbLen = emLen - HASH_BYTES - 1
  const mHash = await sha384(message)
  const mPrime = new Uint8Array(8 + HASH_BYTES + SALT_BYTES)
  mPrime.set(mHash, 8)
  mPrime.set(salt, 8 + HASH_BYTES)
  const h = await sha384(mPrime)
  const db = new Uint8Array(dbLen)
  db[dbLen - SALT_BYTES - 1] = 1
  db.set(salt, dbLen - SALT_BYTES)
  const mask = await mgf1(h, dbLen)
  for (let index = 0; index < dbLen; index += 1) db[index] = db[index]! ^ mask[index]!
  db[0] = db[0]! & (0xff >>> (8 * emLen - emBits))
  const encoded = new Uint8Array(emLen)
  encoded.set(db)
  encoded.set(h, dbLen)
  encoded[emLen - 1] = 0xbc
  return encoded
}

export interface BlindRsaResult {
  blindedMessage: Uint8Array
  inverse: bigint
}

export async function blindRsa(
  modulus: bigint, exponent: bigint, preparedMessage: Uint8Array, salt: Uint8Array, draw: () => Uint8Array,
): Promise<BlindRsaResult> {
  if (modulus.toString(2).length !== 4096 || exponent !== 65537n) throw new TypeError('Expected RSA-4096/65537 public key')
  const encoded = await emsaPssEncode(preparedMessage, salt, 4095)
  const representative = os2ip(encoded)
  modInverse(representative, modulus)
  for (;;) {
    const sample = draw()
    if (!(sample instanceof Uint8Array) || sample.length !== MODULUS_BYTES) throw new TypeError('Expected 512 random bytes')
    const r = os2ip(sample)
    if (r === 0n || r >= modulus) continue
    let inverse: bigint
    try { inverse = modInverse(r, modulus) } catch { continue }
    const blinded = representative * modPow(r, exponent, modulus) % modulus
    return { blindedMessage: i2osp(blinded, MODULUS_BYTES), inverse }
  }
}
