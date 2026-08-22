package basic_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"testing"

	basic "entiergo.org/merkletree-basic"
)

func TestTree(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	c := sha256.Sum256([]byte("c"))
	leaves := [][]byte{a[:], b[:], c[:]}
	tree, err := basic.NewTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	ab := sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...))
	cc := sha256.Sum256(append(append([]byte{}, c[:]...), c[:]...))
	want := sha256.Sum256(append(append([]byte{}, ab[:]...), cc[:]...))
	if tree.LeafCount() != 3 || !bytes.Equal(tree.MerkleRoot(), want[:]) {
		t.Fatal("unexpected root or leaf count")
	}
	ok, err := basic.VerifyRoot(leaves, want[:])
	if err != nil || !ok {
		t.Fatalf("valid root: %v, %v", ok, err)
	}
	root := tree.MerkleRoot()
	root[0] ^= 0xff
	leaves[0][0] ^= 0xff
	if !bytes.Equal(tree.MerkleRoot(), want[:]) {
		t.Fatal("tree root changed after caller mutated a slice")
	}
	ok, err = basic.VerifyRoot(leaves, want[:])
	if err != nil || ok {
		t.Fatalf("modified leaf verified: %v, %v", ok, err)
	}
}

func TestEmpty(t *testing.T) {
	if _, err := basic.NewTree(nil); !errors.Is(err, basic.ErrNoLeaves) {
		t.Fatalf("NewTree: %v", err)
	}
	if _, err := basic.VerifyRoot(nil, nil); !errors.Is(err, basic.ErrNoLeaves) {
		t.Fatalf("VerifyRoot: %v", err)
	}
}

func TestSingleLeafIsDuplicated(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	tree, err := basic.NewTree([][]byte{a[:]})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append(append([]byte{}, a[:]...), a[:]...))
	if !bytes.Equal(tree.MerkleRoot(), want[:]) || len(tree.Leafs) != 2 || !tree.Leafs[1].Duplicate {
		t.Fatal("one leaf must be paired with a padding copy")
	}
}

func TestProofsAndCustomHasher(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy func() hash.Hash
	}{
		{name: "sha256", strategy: sha256.New},
		{name: "sha512", strategy: sha512.New},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for n := 1; n <= 17; n++ {
				leaves := make([][]byte, n)
				for i := range leaves {
					h := tc.strategy()
					_, _ = h.Write([]byte{byte(i)})
					leaves[i] = h.Sum(nil)
				}
				tree, err := basic.NewTreeWithHashStrategy(leaves, tc.strategy)
				if err != nil {
					t.Fatal(err)
				}
				ok, err := basic.VerifyRootWithHashStrategy(leaves, tree.MerkleRoot(), tc.strategy)
				if err != nil || !ok {
					t.Fatalf("%d leaves: root rejected: %v, %v", n, ok, err)
				}
				for i := range leaves {
					path, sides, err := tree.GetMerklePathByIndex(i)
					if err != nil {
						t.Fatal(err)
					}
					ok, err := tree.VerifyProof(leaves[i], path, sides)
					if err != nil || !ok {
						t.Fatalf("%d leaves, proof %d: %v, %v", n, i, ok, err)
					}
					modified := bytes.Clone(leaves[i])
					modified[0] ^= 0xff
					ok, err = basic.VerifyProofWithHashStrategy(modified, path, sides, tree.MerkleRoot(), tc.strategy)
					if err != nil || ok {
						t.Fatalf("%d leaves, altered proof %d: %v, %v", n, i, ok, err)
					}
					if tc.name == "sha256" {
						ok, err = basic.VerifyProof(leaves[i], path, sides, tree.MerkleRoot())
						if err != nil || !ok {
							t.Fatalf("%d leaves, default proof %d: %v, %v", n, i, ok, err)
						}
					}
				}
			}
		})
	}
}

func TestProofAndHasherErrors(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	if _, err := basic.NewTreeWithHashStrategy([][]byte{a[:]}, nil); !errors.Is(err, basic.ErrNilHashStrategy) {
		t.Fatalf("nil hash strategy: %v", err)
	}
	if _, err := basic.NewTreeWithHashStrategy([][]byte{a[:]}, func() hash.Hash { return nil }); !errors.Is(err, basic.ErrNilHashStrategy) {
		t.Fatalf("nil hash returned: %v", err)
	}
	tree, err := basic.NewTree([][]byte{a[:]})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{-1, 1, 2} {
		if _, _, err := tree.GetMerklePathByIndex(i); !errors.Is(err, basic.ErrInvalidIndex) {
			t.Fatalf("index %d: %v", i, err)
		}
	}
	if _, err := basic.VerifyProof(a[:], [][]byte{a[:]}, nil, tree.MerkleRoot()); !errors.Is(err, basic.ErrMalformedProof) {
		t.Fatalf("unequal proof lengths: %v", err)
	}
	if _, err := basic.VerifyProof(a[:], [][]byte{a[:]}, []int64{2}, tree.MerkleRoot()); !errors.Is(err, basic.ErrMalformedProof) {
		t.Fatalf("invalid side: %v", err)
	}
}
