// Package basic builds Bitcoin-style Merkle trees from already hashed leaves.
// It has no content registry, serialization, or alternate tree constructions.
//
// Leaves are digests supplied by the caller. Interior nodes hash left || right
// with SHA-256 by default, and the final node at an odd level is paired with itself.
// This is the default construction used by the parent merkletree package.
package basic

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

// ErrNoLeaves indicates that a root cannot be built from an empty list.
var ErrNoLeaves = errors.New("basic: cannot construct tree with no leaves")

// ErrNilHashStrategy indicates a missing hash factory or a factory returning nil.
var ErrNilHashStrategy = errors.New("basic: hash strategy cannot be nil")

// ErrInvalidIndex indicates a leaf index outside the original input leaves.
var ErrInvalidIndex = errors.New("basic: leaf index out of range")

// ErrMalformedProof indicates mismatched path lengths or a side other than 0 or 1.
var ErrMalformedProof = errors.New("basic: proof is malformed")

// Node is a leaf or interior node in the constructed tree. Leaf Index values
// refer to the input position. A duplicated padding leaf has Duplicate set.
type Node struct {
	Hash      []byte
	Left      *Node
	Right     *Node
	Parent    *Node
	Index     int
	Duplicate bool
}

// Tree stores the nodes and root of a Merkle tree built from leaf digests.
type Tree struct {
	Root  *Node
	Leafs []*Node
	count int
	strategy func() hash.Hash
}

// NewTree builds a tree from precomputed leaf digests. The input is not modified.
// An odd leaf count (including one) gets a separate padding leaf at the end.
func NewTree(leaves [][]byte) (*Tree, error) {
	return NewTreeWithHashStrategy(leaves, sha256.New)
}

// NewTreeWithHashStrategy builds the same ordered, odd-node-duplicating tree
// using strategy for interior hashes. Leaves must already be hashed by the
// caller with a compatible strategy. The strategy must produce a fresh hash.
func NewTreeWithHashStrategy(leaves [][]byte, strategy func() hash.Hash) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, ErrNoLeaves
	}
	if strategy == nil {
		return nil, ErrNilHashStrategy
	}
	h := strategy()
	if h == nil {
		return nil, ErrNilHashStrategy
	}

	level := make([]*Node, 0, len(leaves)+1)
	for i, leaf := range leaves {
		level = append(level, &Node{Hash: bytes.Clone(leaf), Index: i})
	}
	if len(leaves)%2 == 1 {
		level = append(level, &Node{Hash: bytes.Clone(leaves[len(leaves)-1]), Index: len(leaves)-1, Duplicate: true})
	}
	t := &Tree{Leafs: level, count: len(leaves), strategy: strategy}
	for len(level) > 1 {
		next := make([]*Node, (len(level)+1)/2)
		for i := range next {
			left := level[2*i]
			right := left
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			digest, err := AppendPair(h, nil, left.Hash, right.Hash)
			if err != nil {
				return nil, err
			}
			next[i] = &Node{Hash: digest, Left: left, Right: right}
			left.Parent = next[i]
			right.Parent = next[i]
		}
		level = next
	}
	t.Root = level[0]
	return t, nil
}

// AppendPair appends H(left || right) to dst using the supplied hash. It resets
// the hash before use, so callers can reuse it across nodes. This is shared with
// the full merkletree module, which also supports other hash implementations.
func AppendPair(h hash.Hash, dst, left, right []byte) ([]byte, error) {
	if h == nil {
		return nil, ErrNilHashStrategy
	}
	h.Reset()
	if _, err := h.Write(left); err != nil {
		return nil, err
	}
	if _, err := h.Write(right); err != nil {
		return nil, err
	}
	return h.Sum(dst), nil
}

// MerkleRoot returns a copy of the root digest.
func (t *Tree) MerkleRoot() []byte {
	return bytes.Clone(t.Root.Hash)
}

// LeafCount returns the number of leaves supplied to NewTree.
func (t *Tree) LeafCount() int {
	return t.count
}

// VerifyRoot recomputes the root for leaves and compares it with expected.
func VerifyRoot(leaves [][]byte, expected []byte) (bool, error) {
	return VerifyRootWithHashStrategy(leaves, expected, sha256.New)
}

// VerifyRootWithHashStrategy recomputes and compares a root using strategy.
func VerifyRootWithHashStrategy(leaves [][]byte, expected []byte, strategy func() hash.Hash) (bool, error) {
	t, err := NewTreeWithHashStrategy(leaves, strategy)
	if err != nil {
		return false, err
	}
	return bytes.Equal(t.Root.Hash, expected), nil
}

// GetMerklePathByIndex returns sibling hashes and their sides, starting at
// the leaf. A side is 1 for a right sibling and 0 for a left sibling. The
// returned hashes belong to the tree; callers must treat them as read-only.
func (t *Tree) GetMerklePathByIndex(i int) ([][]byte, []int64, error) {
	if i < 0 || i >= t.count {
		return nil, nil, fmt.Errorf("%w: %d", ErrInvalidIndex, i)
	}
	var path [][]byte
	var sides []int64
	for node := t.Leafs[i]; node.Parent != nil; node = node.Parent {
		if node.Parent.Left == node {
			path = append(path, node.Parent.Right.Hash)
			sides = append(sides, 1)
		} else {
			path = append(path, node.Parent.Left.Hash)
			sides = append(sides, 0)
		}
	}
	return path, sides, nil
}

// VerifyProof checks a precomputed leaf digest against root using SHA-256.
// Proofs must follow the ordered construction used by NewTree.
func VerifyProof(digest []byte, path [][]byte, sides []int64, root []byte) (bool, error) {
	return VerifyProofWithHashStrategy(digest, path, sides, root, sha256.New)
}

// VerifyProofWithHashStrategy checks an ordered proof with a custom hasher.
// A matching root must come from a trusted source for this to establish anything.
func VerifyProofWithHashStrategy(digest []byte, path [][]byte, sides []int64, root []byte, strategy func() hash.Hash) (bool, error) {
	if len(path) != len(sides) {
		return false, fmt.Errorf("%w: path and side lengths differ", ErrMalformedProof)
	}
	for _, side := range sides {
		if side != 0 && side != 1 {
			return false, fmt.Errorf("%w: invalid side %d", ErrMalformedProof, side)
		}
	}
	if strategy == nil {
		return false, ErrNilHashStrategy
	}
	h := strategy()
	if h == nil {
		return false, ErrNilHashStrategy
	}
	current := bytes.Clone(digest)
	for i, sibling := range path {
		var err error
		if sides[i] == 1 {
			current, err = AppendPair(h, nil, current, sibling)
		} else {
			current, err = AppendPair(h, nil, sibling, current)
		}
		if err != nil {
			return false, err
		}
	}
	return bytes.Equal(current, root), nil
}

// VerifyProof checks an ordered proof against this tree's root and hasher.
func (t *Tree) VerifyProof(digest []byte, path [][]byte, sides []int64) (bool, error) {
	return VerifyProofWithHashStrategy(digest, path, sides, t.Root.Hash, t.strategy)
}
