package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/wbrc/gf65536"
	"github.com/wbrc/shamir"
)

var (
	dealer *shamir.Dealer
)

func init() {
	field, err := gf65536.New(0x1002b)
	if err != nil {
		panic(err)
	}

	dealer = &shamir.Dealer{
		F:         field,
		Rand:      rand.Reader,
		ByteOrder: binary.BigEndian,
	}
}

var (
	inputFilename  = flag.String("i", "", "file to seal/unseal")
	outputFilename = flag.String("o", "", "file to write sealed/unsealed data")
	sharesFilename = flag.String("s", "", "file to write/read shares")
	threshold      = flag.Int("t", 0, "threshold - number of shares required to unseal")
	shareCount     = flag.Int("n", 0, "share count - number of shares to generate")
	combineMode    = flag.Bool("u", false, "unseal mode")
)

const usage = `seal allows you to encrypt a file and split the key into shares using Shamir's
Secret Sharing.

Usage:
seal -i <input> -o <output> -s <shares> -t <threshold> -n <share count>
seal -u -i <input> -o <output> -s <shares>

The <input> and <output> files are optional and, if omitted (or set to '-'),
will default to stdin and stdout respectively. The <shares> file is always
required. When in seal mode, the <threshold> and <share count> flags are
required, and the threshold must be less than or equal to the share count.
The <shares> file will contain one share per line, in hexadecimal format. When
in unseal mode, <shares> must contain at least <threshold> shares.

`

const description = `

Shamir's Secret Sharing is a cryptographic algorithm that allows you to split a
secret into multiple shares, such that a subset of the shares can be combined
to reconstruct the secret.

Example:
Encrypt the file 'archive.tar.gz' and split the key into 300 shares,
requiring 201 to unseal:

> seal -i archive.tar.gz -o archive.tar.gz.seal -s shares.txt -t 201 -n 300

Decrypt the file 'archive.tar.gz.seal' using the shares in 'shares.txt' (must
contain at least 201 distinct shares):

> seal -u -i archive.tar.gz.seal -o archive.tar.gz -s shares.txt

`

func main() {

	flag.CommandLine.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.CommandLine.PrintDefaults()
		fmt.Fprint(flag.CommandLine.Output(), description)
	}

	flag.Parse()

	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var input io.Reader = os.Stdin
	if *inputFilename != "" && *inputFilename != "-" {
		f, err := os.Open(*inputFilename)
		if err != nil {
			return fmt.Errorf("failed to open input file %s: %w", *inputFilename, err)
		}
		defer f.Close()
		input = f
	}

	var output io.Writer = os.Stdout
	if *outputFilename != "" && *outputFilename != "-" {
		f, err := os.Create(*outputFilename)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", *outputFilename, err)
		}
		defer f.Close()
		output = f
	}

	if !*combineMode {
		if *sharesFilename == "" {
			return fmt.Errorf("shares filename is required")
		}
		if *threshold == 0 {
			return fmt.Errorf("threshold > 0 is required")
		}
		if *shareCount == 0 {
			return fmt.Errorf("share count > 0 is required")
		}
		if *threshold > *shareCount {
			return fmt.Errorf("threshold must be less than or equal to share count")
		}

		sharesFile, err := os.Create(*sharesFilename)
		if err != nil {
			return fmt.Errorf("failed to create shares file %s: %w", *sharesFilename, err)
		}
		defer sharesFile.Close()

		err = seal(input, output, sharesFile, *threshold, *shareCount)
		if err != nil {
			return err
		}
	} else {
		sharesFile, err := os.Open(*sharesFilename)
		if err != nil {
			return fmt.Errorf("failed to open shares file %s: %w", *sharesFilename, err)
		}
		defer sharesFile.Close()

		err = unseal(input, output, sharesFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func seal(r io.Reader, w io.Writer, sharesW io.Writer, t, n int) error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	if err := encrypt(aead, r, w); err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	shares, err := dealer.Split(t, n, key)
	if err != nil {
		return fmt.Errorf("failed to split key: %w", err)
	}

	for _, share := range shares {
		fmt.Fprintf(sharesW, "%x\n", share)
	}

	return nil
}

func unseal(r io.Reader, w io.Writer, sharesR io.Reader) error {
	var shares [][]byte
	s := bufio.NewScanner(sharesR)
	for s.Scan() {
		share, err := hex.DecodeString(s.Text())
		if err != nil {
			return fmt.Errorf("failed to read share: %w", err)
		}
		shares = append(shares, share)
	}
	err := s.Err()
	if err != nil {
		return fmt.Errorf("failed to read shares: %w", err)
	}

	key, err := dealer.Combine(shares)
	if err != nil {
		return fmt.Errorf("failed to combine shares: %w", err)
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	if err := decrypt(aead, r, w); err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	return nil
}

func encrypt(aead cipher.AEAD, r io.Reader, w io.Writer) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	if _, err := io.Copy(w, bytes.NewReader(ciphertext)); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return nil
}

func decrypt(aead cipher.AEAD, r io.Reader, w io.Writer) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err)
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to unseal: %w", err)
	}

	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return fmt.Errorf("failed to write plaintext: %w", err)
	}

	return nil
}
