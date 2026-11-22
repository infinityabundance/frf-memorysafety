// Copyright 2026 The FRF-MemorySafety authors.
//
// RFC 6962 Merkle tree helpers used only to derive inclusion and consistency
// proofs from a log's own tiles. The hashes are checked against the signed
// checkpoint by the independent verifiers; this file is instrument code, not
// an authority.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

func leafHash(entry []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func emptyRoot() [32]byte {
	return sha256.Sum256(nil)
}

// mth computes RFC 6962 MTH over leaves[0:n].
func mth(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return emptyRoot()
	case 1:
		return leaves[0]
	default:
		k := splitPoint(uint64(len(leaves)))
		return nodeHash(mth(leaves[:k]), mth(leaves[k:]))
	}
}

// splitPoint returns the largest power of two strictly less than n.
func splitPoint(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// auditPath returns the RFC 6962 inclusion path for index in a tree of size.
func auditPath(leaves [][32]byte, index uint64) ([][32]byte, error) {
	if index >= uint64(len(leaves)) {
		return nil, errors.New("leaf index outside tree")
	}
	if len(leaves) == 1 {
		return nil, nil
	}
	k := splitPoint(uint64(len(leaves)))
	if index < k {
		left, err := auditPath(leaves[:k], index)
		if err != nil {
			return nil, err
		}
		return append(left, mth(leaves[k:])), nil
	}
	right, err := auditPath(leaves[k:], index-k)
	if err != nil {
		return nil, err
	}
	return append(right, mth(leaves[:k])), nil
}

// consistencyProof returns the RFC 6962 consistency proof from oldSize to the
// full tree.
func consistencyProof(leaves [][32]byte, oldSize uint64) ([][32]byte, error) {
	if oldSize == 0 || oldSize > uint64(len(leaves)) {
		return nil, fmt.Errorf("invalid old size %d", oldSize)
	}
	return subproof(leaves, oldSize, true), nil
}

func subproof(leaves [][32]byte, m uint64, b bool) [][32]byte {
	n := uint64(len(leaves))
	if m == n {
		if b {
			return nil
		}
		return [][32]byte{mth(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(leaves[:k], m, b), mth(leaves[k:]))
	}
	return append(subproof(leaves[k:], m-k, false), mth(leaves[:k]))
}

// leafHashesFromTiles reconstructs the ordered leaf hashes from level-0 tiles.
func leafHashesFromTiles(tiles map[uint64][][32]byte, size uint64) ([][32]byte, error) {
	out := make([][32]byte, 0, size)
	for i := uint64(0); i < size; i += 256 {
		tileIndex := i / 256
		tile, ok := tiles[tileIndex]
		if !ok {
			return nil, fmt.Errorf("missing level-0 tile %d", tileIndex)
		}
		for _, h := range tile {
			if uint64(len(out)) >= size {
				break
			}
			out = append(out, h)
		}
	}
	if uint64(len(out)) != size {
		return nil, fmt.Errorf("tiles yielded %d leaf hashes for size %d", len(out), size)
	}
	return out, nil
}

func parseEntriesBundle(b []byte) ([][]byte, error) {
	out := [][]byte{}
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("truncated entry bundle length")
		}
		n := int(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
		if n > len(b) {
			return nil, errors.New("truncated entry bundle entry")
		}
		out = append(out, append([]byte(nil), b[:n]...))
		b = b[n:]
	}
	return out, nil
}
