package shamir_test

import (
	"encoding/hex"
	"fmt"

	"github.com/wbrc/shamir"
)

func ExampleSplit() {
	secret := []byte("hello, world!!")

	shares, err := shamir.Split(4, 8, secret)
	if err != nil {
		panic(err)
	}

	fmt.Printf("shares:\n")
	for i, share := range shares {
		fmt.Printf("share %d: %x\n", i, share)
	}
}

func ExampleCombine() {
	stringShares := []string{
		"2b5fa84e897199d026b9b469fee4090f",
		"a9c313cbbd97c90024791b249488d987",
		"bbf4de08656d1ed177f85ecb7b9c9fb1",
		"e38d56eb3ae280910595df9515ca7e2d",
	}

	var shares [][]byte
	for _, s := range stringShares {
		share, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}

		shares = append(shares, share)
	}

	secret, err := shamir.Combine(shares)
	if err != nil {
		panic(err)
	}

	fmt.Printf("secret: %q\n", secret)
}
