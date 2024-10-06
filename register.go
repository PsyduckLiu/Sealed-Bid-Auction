package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	crand "crypto/rand"
	"math/big"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func Register(n int, g curves.Point) ([]curves.Scalar, []curves.Point, []*big.Int, []*ecdsa.PrivateKey, []curves.Point, []*big.Int, int64, int64) {
	var err error

	curve := curves.ED25519()
	max_order := new(big.Int)
	max_order.Exp(big.NewInt(2), big.NewInt(128), nil)

	// ElGamal Key Pair
	SK := make([]curves.Scalar, n)
	PK := make([]curves.Point, n)
	R := make([]*big.Int, n)
	G_w := make([]curves.Point, n)
	S := make([]*big.Int, n)

	// ECDSA Key Pair
	Sig_SK := make([]*ecdsa.PrivateKey, n)

	var generateTime time.Duration
	var verifyTime time.Duration

	// Generate ElGamal keypairs (x_i , g^x_i) and random numbers r_i
	for i := 0; i < n; i++ {
		generateStart := time.Now()

		// ElGamal Key Pair
		SK[i] = curve.Scalar.Random(crand.Reader)
		PK[i] = g.Mul(SK[i])
		R[i], err = crand.Int(crand.Reader, max_order)
		if err != nil {
			panic(err)
		}

		// ECDSA Key Pair
		Sig_SK[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		// Generate ElGamal Key Pair Proof
		G_w[i], S[i] = DLProve(g, SK[i])

		generateDuration := time.Since(generateStart)
		generateTime += generateDuration
		verifyStart := time.Now()

		// Verify ElGamal Key Pair Proof
		verified := DLVerify(g, PK[i], G_w[i], S[i])
		if !verified {
			panic("DLVerify Failed")
		}

		verifyDuration := time.Since(verifyStart)
		verifyTime += verifyDuration
	}

	return SK, PK, R, Sig_SK, G_w, S, generateTime.Milliseconds(), verifyTime.Milliseconds()
}
