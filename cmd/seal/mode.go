package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type mode struct {
	description string
	isAEAD      bool
	keySize     int
	ivSize      int
	cipher      func(key, iv []byte) (any, error)
}

var modes = map[string]mode{
	"aes-256-ctr": {
		description: "AES 256-bit in Counter Mode",
		keySize:     32,
		ivSize:      aes.BlockSize,
		cipher: func(key, iv []byte) (any, error) {
			if len(iv) != aes.BlockSize {
				return nil, fmt.Errorf("IV length must equal block size")
			}

			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}

			return cipher.NewCTR(b, iv), nil
		},
	},
	"aes-256-gcm": {
		description: "AES 256-bit in Galois Counter Mode",
		isAEAD:      true,
		keySize:     32,
		cipher: func(key, iv []byte) (any, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}

			return cipher.NewGCM(b)
		},
	},
	"chacha20": {
		description: "ChaCha20",
		keySize:     chacha20.KeySize,
		ivSize:      chacha20.NonceSize,
		cipher:      func(key, iv []byte) (any, error) { return chacha20.NewUnauthenticatedCipher(key, iv) },
	},
	"chacha20-poly1305": {
		description: "ChaCha20 with Poly1305 MAC",
		isAEAD:      true,
		keySize:     chacha20poly1305.KeySize,
		cipher:      func(key, iv []byte) (any, error) { return chacha20poly1305.New(key) },
	},
}
