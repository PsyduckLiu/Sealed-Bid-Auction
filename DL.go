package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func DLProve(g curves.Point, sk curves.Scalar) (curves.Point, *big.Int) {
	curve := curves.ED25519()
	max_order := new(big.Int)
	max_order.Exp(big.NewInt(2), big.NewInt(128), nil)

	w, err := crand.Int(crand.Reader, max_order)
	if err != nil {
		panic(err)
	}
	w_curve, err := curve.Scalar.SetBigInt(w)
	if err != nil {
		panic(err)
	}
	g_w := g.Mul(w_curve)

	// random number e
	hash := sha256.New()
	hash.Write(g_w.Scalar().Bytes())
	hashedBytes := hash.Sum(nil)
	e := new(big.Int).SetBytes(hashedBytes)
	e.Mod(e, max_order)

	s := new(big.Int)
	s.Mul(e, sk.BigInt())
	s.Add(w, s)

	return g_w, s
}

func DLVerify(g, pk, g_w curves.Point, s *big.Int) bool {
	curve := curves.ED25519()
	max_order := new(big.Int)
	max_order.Exp(big.NewInt(2), big.NewInt(128), nil)

	s_curve, err := curve.Scalar.SetBigInt(s)
	if err != nil {
		panic(err)
	}

	// random number e
	hash := sha256.New()
	hash.Write(g_w.Scalar().Bytes())
	hashedBytes := hash.Sum(nil)
	e := new(big.Int).SetBytes(hashedBytes)
	e.Mod(e, max_order)
	e_curve, err := curve.Scalar.SetBigInt(e)
	if err != nil {
		panic(err)
	}

	if !g.Mul(s_curve).Equal(g_w.Add(pk.Mul(e_curve))) {
		return false
	}

	return true
}
