package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
)

func Open(l int, g, h, pk, bidCommitment curves.Point, sig_sk *ecdsa.PrivateKey, R, bid *big.Int) (elgamal.HomomorphicCipherText, curves.Point, curves.Point, *big.Int, *big.Int, curves.Point, []byte, int64, int64) {
	generateStart := time.Now()

	curve := curves.ED25519()
	b, err := curve.Scalar.SetBigInt(bid)
	if err != nil {
		panic(err)
	}
	r, err := curve.Scalar.SetBigInt(R)
	if err != nil {
		panic(err)
	}

	var bidCiphertext elgamal.HomomorphicCipherText
	var msg []byte

	// Bid Ciphertext
	bidCiphertext.C1 = g.Mul(r)
	bidCiphertext.C2 = pk.Mul(r).Add(g.Mul(b))

	// Bid Consistence Proof
	a_1, a_2, z_1, z_2, A := CCEProve(g, h, pk, bidCommitment, bidCiphertext, R, bid)

	// Open Signature
	msg = append(msg, bidCiphertext.C1.Scalar().Bytes()...)
	msg = append(msg, bidCiphertext.C2.Scalar().Bytes()...)
	msg = append(msg, a_1.Scalar().Bytes()...)
	msg = append(msg, a_2.Scalar().Bytes()...)
	msg = append(msg, z_1.Bytes()...)
	msg = append(msg, z_2.Bytes()...)
	msg = append(msg, A.Scalar().Bytes()...)

	hash := sha256.Sum256([]byte(msg))

	openSig, err := ecdsa.SignASN1(crand.Reader, sig_sk, hash[:])
	if err != nil {
		panic(err)
	}

	generateDuration := time.Since(generateStart)
	verifyStart := time.Now()

	// Verify Bid Consistence Proof
	verified_consistence_proof := CCEVerify(z_1, z_2, g, h, pk, bidCommitment, a_1, a_2, A, bidCiphertext)
	if !verified_consistence_proof {
		panic("Verify Bid Consistence Proof Failed")
	}

	// Verify Bid Signature
	verified_open_sig := ecdsa.VerifyASN1(&sig_sk.PublicKey, hash[:], openSig)
	if !verified_open_sig {
		panic("Verify Bid Signature Failed")
	}

	verifyDuration := time.Since(verifyStart)

	return bidCiphertext, a_1, a_2, z_1, z_2, A, openSig, generateDuration.Milliseconds(), verifyDuration.Milliseconds()
}
