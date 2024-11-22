// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
)

// PseudoRandomReader is an io.Reader implementation that produces pseudo-random bytes
// based on a seed derived from a byte array. We are using this to ensure idempotent creation of resources.
// Security of PEM is broken already, so we are not making the problem worse.
type PseudoRandomReader struct {
	rand *rand.Rand
}

// NewPseudoRandomReader creates a new PseudoRandomReader with the provided byte array seed.
func NewPseudoRandomReader(seed []byte) *PseudoRandomReader {
	// Use SHA-256 to hash the seed for consistent length, then take the first 8 bytes for int64
	hash := sha256.Sum256(seed)
	seedInt := int64(binary.LittleEndian.Uint64(hash[:8])) // Convert first 8 bytes to int64
	source := rand.NewSource(seedInt)
	return &PseudoRandomReader{
		rand: rand.New(source),
	}
}

// Read generates pseudo-random bytes into the provided buffer.
func (r *PseudoRandomReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r.rand.Intn(256)) // Generate random byte (0-255)
	}
	return len(p), nil
}
