// Copyright 2026 The FRF-MemorySafety authors.
//
// frf-tlog is a minimal, pinned driver for a local, test-only tlog-tiles log.
// It is built from github.com/transparency-dev/tessera v1.0.4, the Go library
// used by Rekor v2. It is not a public transparency log, not a witness, and
// not a log personality for submission from untrusted clients.
//
// Modes:
//
//	keygen  - generate an Ed25519 checkpoint key for one local log origin.
//	append  - append a batch of entry files and copy the published checkpoint.
//	proof   - derive an inclusion/consistency proof and tile snapshot from the
//	          log's own immutable tiles, checked against the signed checkpoint.
//
// Private key material is written only to the caller-supplied path under
// target/. The gate removes it.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/storage/posix"
)

const (
	exitUsage     = 2
	exitIntegrity = 3
	exitNotRun    = 6
	exitHarness   = 7
)

func main() {
	mode := flag.String("mode", "", "keygen|append|proof")
	origin := flag.String("origin", "", "log origin line")
	keyOut := flag.String("key-out", "", "private key output path (keygen)")
	pubOut := flag.String("public-key-out", "", "public verifier key output path (keygen)")
	storageDir := flag.String("storage", "", "log storage directory")
	privateKey := flag.String("private-key", "", "private key file")
	entriesGlob := flag.String("entries", "", "entry file glob")
	checkpointOut := flag.String("checkpoint-out", "", "copy of the published checkpoint")
	index := flag.Uint64("index", 0, "leaf index for proof")
	oldCheckpoint := flag.String("old-checkpoint", "", "older checkpoint for a consistency proof")
	proofOut := flag.String("proof-out", "", "proof JSON output path")
	flag.Parse()
	ctx := context.Background()

	var err error
	switch *mode {
	case "keygen":
		err = keygen(*origin, *keyOut, *pubOut)
	case "append":
		err = appendEntries(ctx, *storageDir, *privateKey, *entriesGlob, *checkpointOut)
	case "proof":
		err = buildProof(ctx, *storageDir, *index, *checkpointOut, *oldCheckpoint, *proofOut)
	default:
		err = usageError("unknown mode")
	}
	if err != nil {
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitUsage)
		}
		var n notRunError
		if errors.As(err, &n) {
			fmt.Fprintln(os.Stderr, "NOT_RUN: "+err.Error())
			os.Exit(exitNotRun)
		}
		var i integrityError
		if errors.As(err, &i) {
			fmt.Fprintln(os.Stderr, "INTEGRITY: "+err.Error())
			os.Exit(exitIntegrity)
		}
		fmt.Fprintln(os.Stderr, "frf-tlog: "+err.Error())
		os.Exit(exitHarness)
	}
}

type usageError string

func (e usageError) Error() string { return string(e) }

type notRunError string

func (e notRunError) Error() string { return string(e) }

type integrityError string

func (e integrityError) Error() string { return string(e) }

func keygen(origin, keyOut, pubOut string) error {
	if origin == "" || keyOut == "" || pubOut == "" {
		return usageError("keygen requires -origin, -key-out, and -public-key-out")
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return fmt.Errorf("generate note key: %w", err)
	}
	if err := os.WriteFile(keyOut, []byte(skey+"\n"), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubOut, []byte(vkey+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// publishedCheckpoint reads the mutable checkpoint file from a POSIX log.
func publishedCheckpoint(dir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, layout.CheckpointPath))
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	if len(b) == 0 {
		return nil, integrityError("published checkpoint is empty")
	}
	return b, nil
}

func appendEntries(ctx context.Context, storageDir, privateKey, entriesGlob, checkpointOut string) error {
	if storageDir == "" || privateKey == "" || entriesGlob == "" {
		return usageError("append requires -storage, -private-key, and -entries")
	}
	keyBytes, err := os.ReadFile(privateKey)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	signer, err := note.NewSigner(string(trimSpace(keyBytes)))
	if err != nil {
		return fmt.Errorf("parse note signer: %w", err)
	}
	files, err := filepath.Glob(entriesGlob)
	if err != nil {
		return fmt.Errorf("glob entries: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return usageError("no entries matched")
	}
	driver, err := posix.New(ctx, posix.Config{Path: storageDir})
	if err != nil {
		return fmt.Errorf("open posix log: %w", err)
	}
	batchSize := uint(len(files))
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(batchSize, 100*time.Millisecond).
		WithCheckpointInterval(100 * time.Millisecond)
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		return fmt.Errorf("create appender: %w", err)
	}
	await := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 100*time.Millisecond)
	type pending struct {
		name string
		f    tessera.IndexFuture
	}
	queue := make([]pending, 0, len(files))
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			_ = shutdown(ctx)
			return fmt.Errorf("read entry %s: %w", path, err)
		}
		queue = append(queue, pending{name: filepath.Base(path), f: appender.Add(ctx, tessera.NewEntry(b))})
	}
	type result struct {
		Name  string `json:"name"`
		Index uint64 `json:"index"`
	}
	results := make([]result, 0, len(queue))
	for _, entry := range queue {
		seq, _, err := await.Await(ctx, entry.f)
		if err != nil {
			_ = shutdown(ctx)
			return fmt.Errorf("await %s: %w", entry.name, err)
		}
		results = append(results, result{Name: entry.name, Index: seq.Index})
	}
	if err := shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown appender: %w", err)
	}
	checkpoint, err := publishedCheckpoint(storageDir)
	if err != nil {
		return err
	}
	if checkpointOut != "" {
		if err := os.WriteFile(checkpointOut, checkpoint, 0o644); err != nil {
			return fmt.Errorf("write checkpoint copy: %w", err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Entries    []result `json:"entries"`
		Checkpoint string   `json:"checkpoint_sha256"`
	}{Entries: results, Checkpoint: sha256Hex(checkpoint)})
}

// tileRecord is a snapshot of one immutable tile.
type tileRecord struct {
	Level  uint64 `json:"level"`
	Index  uint64 `json:"index"`
	Width  int    `json:"width"`
	SHA256 string `json:"sha256"`
	Base64 string `json:"base64"`
}

func readTile(storageDir string, level, index uint64, treeSize uint64) (*tileRecord, error) {
	partial := layout.PartialTileSize(level, index, treeSize)
	path := filepath.Join(storageDir, layout.TilePath(level, index, partial))
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read tile %d/%d: %w", level, index, err)
	}
	if len(b) == 0 || len(b)%32 != 0 {
		return nil, integrityError(fmt.Sprintf("malformed tile %d/%d: %d bytes", level, index, len(b)))
	}
	return &tileRecord{
		Level:  level,
		Index:  index,
		Width:  len(b) / 32,
		SHA256: sha256Hex(b),
		Base64: base64.StdEncoding.EncodeToString(b),
	}, nil
}

// buildProof reads the log's immutable tiles, checks the reconstructed tree
// against the signed checkpoint, and writes a proof bundle. It does not touch
// the verifier.
func buildProof(ctx context.Context, storageDir string, index uint64, checkpointPath, oldCheckpointPath, proofOut string) error {
	_ = ctx
	if storageDir == "" || checkpointPath == "" || proofOut == "" {
		return usageError("proof requires -storage, -checkpoint-out, and -proof-out")
	}
	checkpointBytes, err := os.ReadFile(checkpointPath)
	if err != nil {
		return fmt.Errorf("read checkpoint: %w", err)
	}
	cp, err := parseCheckpointFacts(checkpointBytes)
	if err != nil {
		return err
	}
	if index >= cp.size {
		return usageError("index is outside the checkpoint")
	}

	// Load every level-0 tile and check the reconstructed root.
	level0 := map[uint64][][32]byte{}
	tiles := []tileRecord{}
	for level := uint64(0); level < 16; level++ {
		hashesAtLevel := cp.size / pow256(level)
		if hashesAtLevel == 0 {
			break
		}
		tileCount := (hashesAtLevel + 255) / 256
		for tileIndex := uint64(0); tileIndex < tileCount; tileIndex++ {
			rec, err := readTile(storageDir, level, tileIndex, cp.size)
			if err != nil {
				return err
			}
			if rec == nil {
				return integrityError(fmt.Sprintf("missing tile %d/%d", level, tileIndex))
			}
			tiles = append(tiles, *rec)
			raw, err := base64.StdEncoding.DecodeString(rec.Base64)
			if err != nil {
				return integrityError("tile base64 round-trip failed")
			}
			if level == 0 {
				list := make([][32]byte, 0, rec.Width)
				for i := 0; i+32 <= len(raw); i += 32 {
					var h [32]byte
					copy(h[:], raw[i:i+32])
					list = append(list, h)
				}
				level0[tileIndex] = list
			}
		}
	}
	leaves, err := leafHashesFromTiles(level0, cp.size)
	if err != nil {
		return integrityError(err.Error())
	}
	if mth(leaves) != cp.root {
		return integrityError("reconstructed root does not match the signed checkpoint")
	}

	// Read the entry bundle and extract the exact entry bytes at the index.
	bundleIndex := index / 256
	bundlePartial := layout.PartialTileSize(0, bundleIndex, cp.size)
	bundlePath := filepath.Join(storageDir, layout.EntriesPath(bundleIndex, bundlePartial))
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read entry bundle: %w", err)
	}
	entries, err := parseEntriesBundle(bundle)
	if err != nil {
		return integrityError(err.Error())
	}
	offset := index % 256
	if offset >= uint64(len(entries)) {
		return integrityError("entry bundle does not contain the requested index")
	}
	entry := entries[offset]
	if leafHash(entry) != leaves[index] {
		return integrityError("entry bundle leaf hash disagrees with the level-0 tile")
	}
	audit, err := auditPath(leaves, index)
	if err != nil {
		return integrityError(err.Error())
	}
	leaf := leafHash(entry)
	if err := checkInclusion(index, cp.size, cp.root, leaf, audit); err != nil {
		return integrityError(err.Error())
	}

	type consistency struct {
		OldSize uint64   `json:"old_size"`
		OldRoot string   `json:"old_root"`
		NewSize uint64   `json:"new_size"`
		NewRoot string   `json:"new_root"`
		Proof   []string `json:"proof"`
	}
	var cons *consistency
	if oldCheckpointPath != "" {
		oldBytes, err := os.ReadFile(oldCheckpointPath)
		if err != nil {
			return fmt.Errorf("read old checkpoint: %w", err)
		}
		old, err := parseCheckpointFacts(oldBytes)
		if err != nil {
			return err
		}
		if old.size > cp.size || old.origin != cp.origin {
			return usageError("old checkpoint is not a prefix of the new checkpoint")
		}
		proof, err := consistencyProof(leaves, old.size)
		if err != nil {
			return integrityError(err.Error())
		}
		cons = &consistency{
			OldSize: old.size,
			OldRoot: hexLower(old.root[:]),
			NewSize: cp.size,
			NewRoot: hexLower(cp.root[:]),
			Proof:   hashesB64(proof),
		}
	}

	proof := map[string]any{
		"schema":            "frf-etp.transparency-proof.v1",
		"spec":              "frf-etp-v1",
		"log_version":       "tlog-tiles-v1",
		"log_origin":        cp.origin,
		"log_id":            "sha256:" + sha256Hex([]byte(cp.origin)),
		"tree_size":         cp.size,
		"root_hash":         hexLower(cp.root[:]),
		"leaf_index":        index,
		"entry_sha256":      sha256Hex(entry),
		"entry_base64":      base64.StdEncoding.EncodeToString(entry),
		"leaf_hash":         hexLower(leaf[:]),
		"audit_path":        hashesB64(audit),
		"checkpoint_sha256": sha256Hex(checkpointBytes),
		"tiles":             tiles,
	}
	if cons != nil {
		proof["consistency"] = cons
	}
	if err := os.MkdirAll(filepath.Dir(proofOut), 0o755); err != nil {
		return fmt.Errorf("create proof directory: %w", err)
	}
	f, err := os.Create(proofOut)
	if err != nil {
		return fmt.Errorf("create proof: %w", err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(proof)
}

type checkpointFacts struct {
	origin string
	size   uint64
	root   [32]byte
	text   []byte
}

func parseCheckpointFacts(b []byte) (checkpointFacts, error) {
	// Note text is everything up to the blank line before the signatures.
	idx := -1
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\n' && b[i+1] == '\n' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return checkpointFacts{}, integrityError("checkpoint has no signature block")
	}
	text := b[:idx+1]
	lines := splitLines(text)
	if len(lines) < 3 {
		return checkpointFacts{}, integrityError("checkpoint has fewer than three lines")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return checkpointFacts{}, integrityError("checkpoint size is not decimal")
	}
	rootBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(rootBytes) != 32 {
		return checkpointFacts{}, integrityError("checkpoint root is not 32-byte base64")
	}
	var root [32]byte
	copy(root[:], rootBytes)
	return checkpointFacts{origin: lines[0], size: size, root: root, text: text}, nil
}

func splitLines(b []byte) []string {
	out := []string{}
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	return out
}

func checkInclusion(index, size uint64, root [32]byte, leaf [32]byte, path [][32]byte) error {
	if size == 0 || index >= size {
		return integrityError("invalid inclusion range")
	}
	fn := index
	sn := size - 1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return integrityError("inclusion proof longer than the tree")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return integrityError("inclusion proof shorter than the tree")
	}
	if r != root {
		return integrityError("inclusion proof root mismatch")
	}
	return nil
}

func hashesB64(hs [][32]byte) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, base64.StdEncoding.EncodeToString(h[:]))
	}
	return out
}

func pow256(n uint64) uint64 {
	v := uint64(1)
	for i := uint64(0); i < n; i++ {
		v *= 256
	}
	return v
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func hexLower(b []byte) string { return hex.EncodeToString(b) }

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
