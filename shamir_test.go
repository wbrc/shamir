package shamir

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"reflect"
	"testing"
)

func TestDealer(t *testing.T) {
	var d Dealer
	type args struct {
		t, n   int
		secret []byte
	}
	type test struct {
		name        string
		args        args
		wantErr     bool
		wantInvalid bool
	}
	tests := []test{
		{
			name: "invalid secret",
			args: args{
				t:      3,
				n:      5,
				secret: []byte{0xde, 0xca, 0xfb},
			},
			wantErr: true,
		},
		{
			name: "invalid params",
			args: args{
				t:      0,
				n:      10,
				secret: []byte{0xde, 0xca, 0xfb, 0xad},
			},
			wantErr: true,
		},
		{
			name: "t==n",
			args: args{
				t:      7,
				n:      7,
				secret: []byte{0xde, 0xca, 0xfb, 0xad},
			},
		},
	}

	mktest := func(prefix string) test {
		threshold := mrand.IntN(50) + 2
		n := mrand.IntN(50) + threshold

		secret := make([]byte, (mrand.IntN(100)+1)*2)
		_, err := rand.Read(secret)
		if err != nil {
			t.Fatal(err)
		}

		return test{
			name: fmt.Sprintf("%s-%d-%d-%d", prefix, len(secret), threshold, n),
			args: args{
				t:      threshold,
				n:      n,
				secret: secret,
			},
		}
	}

	// add some random valid tests
	for range 10 {
		tests = append(tests, mktest("valid"))
	}

	// add some random tests for invalid combining (not enough shares)
	for range 10 {
		tt := mktest("invalid")
		tt.wantInvalid = true
		tests = append(tests, tt)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := d.Split(tt.args.t, tt.args.n, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			mrand.Shuffle(len(shares), func(i, j int) {
				shares[i], shares[j] = shares[j], shares[i]
			})

			thresReconstruct := tt.args.t
			if tt.wantInvalid {
				thresReconstruct = mrand.IntN(tt.args.t-1) + 1
			}

			combined, err := d.Combine(shares[:thresReconstruct])
			if err != nil {
				t.Fatal(err)
			}

			if bytes.Equal(combined, tt.args.secret) != !tt.wantInvalid {
				t.Fatalf("%v==%v should be %t", tt.args.secret, combined, !tt.wantInvalid)
			}
		})
	}
}

func Test_split(t *testing.T) {
	type args struct {
		random    io.Reader
		threshold int
		n         int
		secret    []uint16
	}
	tests := []struct {
		name    string
		args    args
		result  [][]uint16
		wantErr bool
	}{
		{
			name: "invalid params",
			args: args{
				random:    rand.Reader,
				threshold: 5,
				n:         3,
				secret:    []uint16{42069},
			},
			wantErr: true,
		},
		{
			name: "invalid params",
			args: args{
				random:    rand.Reader,
				threshold: 0,
				n:         0,
				secret:    []uint16{0xdeca, 0xfbad},
			},
			wantErr: true,
		},
		{
			name: "invalid params",
			args: args{
				random:    rand.Reader,
				threshold: 3,
				n:         5,
				secret:    []uint16{},
			},
			wantErr: true,
		}, {
			name: "invalid params",
			args: args{
				random:    rand.Reader,
				threshold: 0,
				n:         5,
				secret:    []uint16{0xf00d},
			},
			wantErr: true,
		},
		{
			name: "bad rand source",
			args: args{
				random:    bytes.NewReader([]byte("not enough entropy")),
				threshold: 5,
				n:         10,
				secret:    []uint16{0xdeca, 0xfbad},
			},
			wantErr: true,
		},
		{ // result has been manually reviewed and verified
			name: "valid",
			args: args{
				random: bytes.NewReader([]byte{0xf0, 0xa7, 0x7a, 0x0e, 0x1e,
					0x8a, 0x2e, 0x36, 0xfb, 0x59, 0xbb, 0x84, 0x97, 0x65}),
				threshold: 3,
				n:         3,
				secret:    []uint16{0xb16b, 0x00b5},
			},
			result: [][]uint16{
				{0xa7f0, 0xc423, 0xe7ac},
				{0xe7a, 0xdcbc, 0x4e6e},
				{0x8a1e, 0xd0da, 0x1523},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := split(f, tt.args.random, tt.args.threshold, tt.args.n, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			if !reflect.DeepEqual(shares, tt.result) {
				t.Fatalf("expected %v, got %v", tt.result, shares)
			}
		})
	}
}

func Test_combine(t *testing.T) {
	tests := []struct {
		name    string
		shares  [][]uint16
		want    []uint16
		wantErr bool
	}{
		{
			name:    "nil shares",
			shares:  nil,
			wantErr: true,
		},
		{
			name: "inconsistent",
			shares: [][]uint16{
				{1, 2, 3},
				{1, 2},
				{5, 4, 3},
			},
			wantErr: true,
		},
		{
			name: "unsolvable",
			shares: [][]uint16{
				{0xa7f0, 0xc423, 0xe7ac},
				{0xe7a, 0xdcbc, 0x4e6e},
				{0xe7a, 0xdcbc, 0x4e6e},
			},
			wantErr: true,
		},
		{
			name: "valid",
			shares: [][]uint16{
				{0xa7f0, 0xc423, 0xe7ac},
				{0xe7a, 0xdcbc, 0x4e6e},
				{0x8a1e, 0xd0da, 0x1523},
			},
			want: []uint16{0xb16b, 0x00b5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := combine(f, tt.shares)
			if (err != nil) != tt.wantErr {
				t.Errorf("combine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("combine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_split_combine_single(t *testing.T) {
	var secret uint16 = 42069
	threshold := 5

	shares := make([]uint16, threshold)
	xvals := make([]uint16, threshold)

	err := distinctXes(rand.Reader, xvals)
	if err != nil {
		t.Fatal(err)
	}

	err = splitSingle(f, rand.Reader, threshold, shares, xvals, secret)
	if err != nil {
		t.Fatal(err)
	}

	combined, err := combineSingle(f, xvals, shares)
	if err != nil {
		t.Fatal(err)
	}
	if combined != secret {
		t.Fatalf("expected %d, got %d", secret, combined)
	}
}
