package main

import (
	crand "crypto/rand"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func getcapVBatched(v, r []curves.Scalar, g, h curves.Point) []curves.Point {
	out := make([]curves.Point, len(v))
	for i, vi := range v {
		out[i] = h.Mul(r[i]).Add(g.Mul(vi))
	}
	return out
}

func Setup() (curves.Point, curves.Point, int, int, *big.Int) {
	curve := curves.ED25519()

	// Commitment Setup and ElGamal Setup
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)

	// Bidder Number + Upper Bound
	n := 4
	l := 32
	maxFund := new(big.Int)
	maxFund.Exp(big.NewInt(2), big.NewInt(int64(l)), nil).Sub(maxFund, big.NewInt(1))

	return g, h, n, l, maxFund
}
