# merkletree-basic

A small Go module for constructing Bitcoin-style Merkle trees from precomputed
leaf digests. It uses SHA-256 for interior nodes by default, preserves sibling
order, and duplicates the last node at each odd level. It does not provide
content types, serialization, or alternate tree constructions.

```go
import (
    "crypto/sha256"
    basic "entiergo.org/merkletree-basic"
)

a, b := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
tree, err := basic.NewTree([][]byte{a[:], b[:]})
if err != nil { /* handle error */ }
root := tree.MerkleRoot()
path, sides, err := tree.GetMerklePathByIndex(0)
if err != nil { /* handle error */ }
valid, err := basic.VerifyProof(a[:], path, sides, root)
```

Use `NewTreeWithHashStrategy(leaves, strategy)` for a different interior hash.
Hash leaf data with a compatible algorithm first, then use
`VerifyRootWithHashStrategy` or `VerifyProofWithHashStrategy` to verify it.
Proof sides use `1` for a right sibling and `0` for a left sibling, matching
the full module's path format. The tree also provides `tree.VerifyProof` using
its own root and hasher. Proofs establish membership only relative to a root
the verifier already trusts.

This construction duplicates odd nodes and does not separate leaf and interior
hashes. It has the same ambiguity as the full module's default construction;
use the full module's RFC 6962 mode when those properties matter.

The full `entiergo.org/merkletree` module imports this module for
default tree construction and interior-node hashing. Publish this module with
tag `v0.1.0` before publishing
the full module. For local development, extract both repositories into sibling
directories and run `go work init ./merkletree-basic ./merkletree` from their
parent directory.
