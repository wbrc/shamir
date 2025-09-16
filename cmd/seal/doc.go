// seal allows you to encrypt a file and split the key into shares using Shamir's
// Secret Sharing.
//
// Usage:
// seal -i <input> -o <output> -s <shares> -t <threshold> -n <share count> -m <mode>
// seal -u -i <input> -o <output> -s <shares> -m <mode>
//
// The <input> and <output> files are optional and, if omitted (or set to '-'),
// will default to stdin and stdout respectively. The <shares> file is always
// required. When in seal mode, the <threshold> and <share count> flags are
// required, and the threshold must be less than or equal to the share count.
// The <shares> file will contain one share per line, in hexadecimal format. When
// in unseal mode, <shares> must contain at least <threshold> shares. The -m flag
// specifies the encryption mode to use. Supported modes are listed below. On
// unseal, the mode must match the mode used to seal. AEAD modes provide
// authenticated encryption, but the entire input/output is kept in memory.
//
// Flags:
//
//	-i string
//	      file to seal/unseal
//	-m string
//	      encryption mode (default "aes-256-gcm")
//	-n int
//	      share count - number of shares to generate
//	-o string
//	      file to write sealed/unsealed data
//	-s string
//	      file to write/read shares
//	-t int
//	      threshold - number of shares required to unseal
//	-u    unseal file
//
// Shamir's Secret Sharing is a cryptographic algorithm that allows you to split a
// secret into multiple shares, such that a subset of the shares can be combined
// to reconstruct the secret.
//
// Example:
// Encrypt the file 'archive.tar.gz' and split the key into 300 shares,
// requiring 201 to unseal:
//
// > seal -i archive.tar.gz -o archive.tar.gz.seal -s shares.txt -t 201 -n 300
//
// Decrypt the file 'archive.tar.gz.seal' using the shares in 'shares.txt' (must
// contain at least 201 distinct shares):
//
// > seal -u -i archive.tar.gz.seal -o archive.tar.gz -s shares.txt
//
// Supported Modes:
//
//	aes-256-ctr
//	      AES 256-bit in Counter Mode
//	aes-256-gcm
//	      AES 256-bit in Galois Counter Mode (AEAD)
//	chacha20
//	      ChaCha20
//	chacha20-poly1305
//	      ChaCha20 with Poly1305 MAC (AEAD)
package main
