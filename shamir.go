package shamir

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/wbrc/gf65536"
)

var (
	defaultField     = gf65536.Default
	defaultRandSrc   = rand.Reader
	defaultByteOrder = binary.BigEndian
)

// Dealer is a Shamir secret sharing dealer. A zero-value Dealer is ready to
// use with default settings. The default field is gf65536.Default, the default
// random source is crypto/rand.Reader, and the default byte order is
// binary.BigEndian.
type Dealer struct {
	F         gf65536.Field    // the GF(2^16) field to use
	Rand      io.Reader        // cryptographically secure random source
	ByteOrder binary.ByteOrder // byte order for encoding/decoding bytes to GF(2^16) words
}

// Split splits a secret into n shares such that any threshold number of shares
// can be combined to recover the secret. The secret must be a multiple of 2
// bytes. The threshold must be less than or equal to n, and both must be
// greater than 0. On success, Split returns a slice of n shares, each of which
// is a distinct share.
func (d *Dealer) Split(threshold, n int, secret []byte) ([][]byte, error) {
	d.init()

	if len(secret)%2 != 0 {
		return nil, errors.New("secret must be a multiple of 2 bytes")
	}

	secretWords := make([]uint16, len(secret)/2)
	_, err := binary.Decode(secret, d.ByteOrder, secretWords)
	if err != nil {
		return nil, err
	}

	shares, err := split(d.F, d.Rand, threshold, n, secretWords)
	if err != nil {
		return nil, err
	}

	byteShares := make([][]byte, len(shares))
	for i := range shares {
		byteShares[i] = make([]byte, len(secret)+2)
		_, err = binary.Encode(byteShares[i], d.ByteOrder, shares[i])
		if err != nil {
			return nil, err
		}
	}

	return byteShares, nil
}

// Combine combines a slice of shares to recover the secret. len(shares) must be
// at least the threshold used to split the secret. On success, Combine returns
// the secret.
func (d *Dealer) Combine(shares [][]byte) ([]byte, error) {
	d.init()

	if len(shares) == 0 {
		return nil, errors.New("nil shares")
	}

	wordShares := make([][]uint16, len(shares))
	for i := range shares {
		wordShares[i] = make([]uint16, len(shares[0])/2)
		_, err := binary.Decode(shares[i], d.ByteOrder, wordShares[i])
		if err != nil {
			return nil, err
		}
	}

	secretWords, err := combine(d.F, wordShares)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, len(secretWords)*2)
	_, err = binary.Encode(secret, d.ByteOrder, secretWords)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// Default is a zero-value Dealer ready to use with default settings.
var Default = new(Dealer)

// Split a secret using the default dealer.
func Split(threshold, n int, secret []byte) ([][]byte, error) {
	return Default.Split(threshold, n, secret)
}

// Combine a secret using the default dealer.
func Combine(shares [][]byte) ([]byte, error) {
	return Default.Combine(shares)
}

func (d *Dealer) init() {
	if d.F == 0 {
		d.F = defaultField
	}
	if d.Rand == nil {
		d.Rand = defaultRandSrc
	}
	if d.ByteOrder == nil {
		d.ByteOrder = defaultByteOrder
	}
}

func split(f gf65536.Field, random io.Reader, threshold, n int, secret []uint16) ([][]uint16, error) {
	if threshold > n {
		return nil, errors.New("threshold must be less than or equal to n")
	}
	if threshold < 1 {
		return nil, errors.New("threshold must be greater than 0")
	}
	if n < 1 {
		return nil, errors.New("n must be greater than 0")
	}
	if len(secret) == 0 {
		return nil, errors.New("nil secret")
	}

	xvals := make([]uint16, n)
	z := make([]uint16, n)
	shares := make([][]uint16, n)

	err := distinctXes(random, xvals)
	if err != nil {
		return nil, err
	}

	for i := range shares {
		shares[i] = make([]uint16, len(secret)+1)
		shares[i][0] = xvals[i]
	}

	for i := range secret {
		err = splitSingle(f, random, threshold, z, xvals, secret[i])
		if err != nil {
			return nil, err
		}

		for j := range shares {
			shares[j][i+1] = z[j]
		}
	}

	return shares, nil
}

func combine(f gf65536.Field, shares [][]uint16) ([]uint16, error) {
	if len(shares) == 0 {
		return nil, errors.New("nil shares")
	}

	secretLen := len(shares[0]) - 1
	for _, share := range shares[1:] {
		if len(share) != secretLen+1 {
			return nil, errors.New("inconsistent share length")
		}
	}

	xvals := make([]uint16, len(shares))
	yvals := make([]uint16, len(shares))
	secrets := make([]uint16, secretLen)

	for r := range shares {
		xvals[r] = shares[r][0]
	}

	for c := 1; c < len(shares[0]); c++ {
		for r := range shares {
			yvals[r] = shares[r][c]
		}

		secret, err := combineSingle(f, xvals, yvals)
		if err != nil {
			return nil, err
		}

		secrets[c-1] = secret
	}

	return secrets, nil
}

func splitSingle(f gf65536.Field, random io.Reader, threshold int, z, xvals []uint16, secret uint16) error {
	polynomial := make([]uint16, threshold)

	polynomial[0] = secret

	err := binary.Read(random, binary.NativeEndian, polynomial[1:])
	if err != nil {
		return err
	}

	for i, x := range xvals {
		z[i] = evalPoly(f, polynomial, x)
	}

	return nil
}

func combineSingle(f gf65536.Field, xvals, yvals []uint16) (uint16, error) {
	m := make([][]uint16, len(xvals))
	for i := range m {
		m[i] = make([]uint16, len(xvals)+1)
		pows(f, m[i][:len(m[i])-1], xvals[i])
		m[i][len(m[i])-1] = yvals[i]
	}

	err := gauss(f, m)
	if err != nil {
		return 0, err
	}

	return m[0][len(m[0])-1], nil
}

// creates len(v) random distinct values of GF(2^16)\0
func distinctXes(random io.Reader, v []uint16) error {
	xes := make(map[uint16]struct{}, len(v))
	for i := 0; i < len(v); {
		err := binary.Read(random, binary.NativeEndian, &v[i])
		if err != nil {
			return err
		}

		if v[i] == 0 {
			continue
		}
		if _, ok := xes[v[i]]; ok {
			continue
		}
		xes[v[i]] = struct{}{}
		i++
	}

	return nil
}
