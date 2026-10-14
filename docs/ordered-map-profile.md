# Ordered authority map profile

`orderedMapRoot(entries)` commits an array of `{ key, valueHash }` entries. Each field is exactly 64 lowercase hexadecimal characters encoding 32 bytes. Keys are opaque commitments to scoped subject identifiers; callers should not use guessable identifiers directly. Entries must be strictly ascending by the fixed-width lowercase key strings. Duplicate, descending, malformed, sparse, or accessor-backed input is rejected. The library snapshots all entries synchronously before hashing.

For an empty subtree, including the entire empty map, the root is `SHA-256(03)`, where `03` is one byte. For a nonempty subtree, choose array index `floor(N / 2)` as its root and recursively divide the entries before and after that index. The node root is:

```text
SHA-256(02 || key[32] || valueHash[32] || leftRoot[32] || rightRoot[32])
```

`02` is one byte; the bracketed fields are raw 32-byte values decoded from hexadecimal, and `||` means byte concatenation. The preimage is 129 bytes. These prefixes are separate from the chronological history tree's `00` and `01` domains. Building a root or producer proof hashes O(N) nodes; the proof path contains O(log N) steps. Updating a binding requires rebuilding the snapshot.

`orderedMapProof(entries, key)` returns either `{ kind: 'present', key, valueHash, left, right, path }` or `{ kind: 'absent', path }`. A present proof begins at the matching node, with its two child roots. An absent proof begins at the `SHA-256(03)` root of the empty child reached by binary search. `path` lists ancestors from the searched node or empty child up to the map root. Each step is `{ key, valueHash, sibling, direction }`; `sibling` is the other child root. `direction: 'left'` means the searched subtree was the ancestor's left child and the query key is less than that ancestor key. `right` means it was the right child and the query key is greater. The verifier rebuilds the root in this bottom-up order, checks strict key inequalities and exact proof fields, rejects paths longer than 53 steps, and returns `false` for malformed input. It snapshots the proof before the first asynchronous hash.

A valid proof establishes only a path under the **supplied root**. It does not establish that the root is the latest customer-authorized state, or that hidden sibling subtrees contain globally sorted, unique keys. A consumer must obtain a trusted signed checkpoint for the root. An observer must replay the chronological history, reconstruct the complete ordered snapshot, reject unsorted or duplicate history, and compare the resulting map root with the checkpoint before making either claim.
