package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
)

func CCEProve(g, h, pk, commitment curves.Point, ciphertext elgamal.HomomorphicCipherText, R, x *big.Int) (curves.Point, curves.Point, *big.Int, *big.Int, curves.Point) {
	curve := curves.ED25519()
	max_order := new(big.Int)
	max_order.Exp(big.NewInt(2), big.NewInt(128), nil)

	s, _ := crand.Int(crand.Reader, max_order)
	t, _ := crand.Int(crand.Reader, max_order)
	s_curve, _ := curve.Scalar.SetBigInt(s)
	t_curve, _ := curve.Scalar.SetBigInt(t)

	a_1 := g.Mul(t_curve)
	a_2 := g.Mul(s_curve).Add(pk.Mul(t_curve))
	A := g.Mul(s_curve).Add(h.Mul(t_curve))

	// random number e
	hash := sha256.New()
	hash.Write(commitment.Scalar().Bytes())
	ciphertextBytes, _ := ciphertext.MarshalBinary()
	hash.Write(ciphertextBytes)
	hash.Write(pk.Scalar().Bytes())
	hash.Write(a_1.Scalar().Bytes())
	hash.Write(a_2.Scalar().Bytes())
	hash.Write(A.Scalar().Bytes())
	hashedBytes := hash.Sum(nil)
	e := new(big.Int).SetBytes(hashedBytes)
	e.Mod(e, max_order)

	z_1 := new(big.Int)
	z_2 := new(big.Int)
	z_1.Mul(e, x)
	z_1.Add(z_1, s)
	z_2.Mul(e, R)
	z_2.Add(z_2, t)

	return a_1, a_2, z_1, z_2, A
}

func CCEVerify(z_1, z_2 *big.Int, g, h, pk, commitment, a_1, a_2, A curves.Point, ciphertext elgamal.HomomorphicCipherText) bool {
	curve := curves.ED25519()
	max_order := new(big.Int)
	max_order.Exp(big.NewInt(2), big.NewInt(128), nil)

	z_1_curve, _ := curve.Scalar.SetBigInt(z_1)
	z_2_curve, _ := curve.Scalar.SetBigInt(z_2)

	// random number e
	hash := sha256.New()
	hash.Write(commitment.Scalar().Bytes())
	ciphertextBytes, _ := ciphertext.MarshalBinary()
	hash.Write(ciphertextBytes)
	hash.Write(pk.Scalar().Bytes())
	hash.Write(a_1.Scalar().Bytes())
	hash.Write(a_2.Scalar().Bytes())
	hash.Write(A.Scalar().Bytes())
	hashedBytes := hash.Sum(nil)
	e := new(big.Int).SetBytes(hashedBytes)
	e.Mod(e, max_order)
	e_curve, _ := curve.Scalar.SetBigInt(e)

	// Test 1
	left_1 := g.Mul(z_2_curve)
	right_1 := (ciphertext.C1.Mul(e_curve)).Add(a_1)
	if !left_1.Equal(right_1) {
		return false
	}

	// Test 2
	left_2 := (g.Mul(z_1_curve)).Add(pk.Mul(z_2_curve))
	right_2 := (ciphertext.C2.Mul(e_curve)).Add(a_2)
	if !left_2.Equal(right_2) {
		return false
	}

	// Test 3
	left_3 := (g.Mul(z_1_curve)).Add(h.Mul(z_2_curve))
	right_3 := A.Add(commitment.Mul(e_curve))
	if !left_3.Equal(right_3) {
		return false
	}

	return true
}
