package main

import (
	"bulletproof"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
	"github.com/gtank/merlin"
)

func Deposit(l int, g, h, pk curves.Point, sig_sk *ecdsa.PrivateKey, R, deposit *big.Int) (elgamal.HomomorphicCipherText, curves.Point, curves.Point, curves.Point, *big.Int, *big.Int, curves.Point, *bulletproof.RangeProof, []byte, int64, int64) {
	generateStart := time.Now()

	curve := curves.ED25519()
	d, err := curve.Scalar.SetBigInt(deposit)
	if err != nil {
		panic(err)
	}
	r, err := curve.Scalar.SetBigInt(R)
	if err != nil {
		panic(err)
	}

	var depositCiphertext elgamal.HomomorphicCipherText
	var msg []byte

	// Deposit Ciphertext
	depositCiphertext.C1 = g.Mul(r)
	depositCiphertext.C2 = pk.Mul(r).Add(g.Mul(d))

	// Deposit Commitment
	depositCommitment := h.Mul(r).Add(g.Mul(d))

	// Deposit Consistence Proof
	a_1, a_2, z_1, z_2, A := CCEProve(g, h, pk, depositCommitment, depositCiphertext, R, deposit)

	// Deposit Range Proof
	u := curve.Point.Random(crand.Reader)
	proofGenerators := bulletproof.RangeProofGenerators{
		G: g,
		H: h,
		U: u,
	}

	prover, err := bulletproof.NewRangeProver(l, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	if err != nil {
		panic(err)
	}
	transcript := merlin.NewTranscript("auction")
	depositProof, err := prover.Prove(d, r, l, proofGenerators, transcript)
	if err != nil {
		panic(err)
	}

	// Deposit Signature
	msg = append(msg, depositCiphertext.C1.Scalar().Bytes()...)
	msg = append(msg, depositCiphertext.C2.Scalar().Bytes()...)
	msg = append(msg, depositCommitment.Scalar().Bytes()...)
	msg = append(msg, a_1.Scalar().Bytes()...)
	msg = append(msg, a_2.Scalar().Bytes()...)
	msg = append(msg, z_1.Bytes()...)
	msg = append(msg, z_2.Bytes()...)
	msg = append(msg, A.Scalar().Bytes()...)
	msg = append(msg, depositProof.MarshalBinary()...)

	hash := sha256.Sum256([]byte(msg))

	depositSig, err := ecdsa.SignASN1(crand.Reader, sig_sk, hash[:])
	if err != nil {
		panic(err)
	}

	generateDuration := time.Since(generateStart)
	verifyStart := time.Now()

	// Verify Deposit Consistence Proof
	verified_consistence_proof := CCEVerify(z_1, z_2, g, h, pk, depositCommitment, a_1, a_2, A, depositCiphertext)
	if !verified_consistence_proof {
		panic("Verify Deposit Consistence Proof Failed")
	}

	// Verify Deposit Range Proof
	verifier, err := bulletproof.NewRangeVerifier(l, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	if err != nil {
		panic(err)
	}

	transcriptVerifier := merlin.NewTranscript("auction")
	verified_range_proof, err := verifier.Verify(depositProof, depositCommitment, proofGenerators, l, transcriptVerifier)
	if err != nil {
		panic(err)
	}
	if !verified_range_proof {
		panic("Verify Deposit Range Proof Failed")
	}

	// Verify Deposit Signature
	verified_deposit_sig := ecdsa.VerifyASN1(&sig_sk.PublicKey, hash[:], depositSig)
	if !verified_deposit_sig {
		panic("Verify Deposit Signature Failed")
	}
	verifyDuration := time.Since(verifyStart)

	return depositCiphertext, depositCommitment, a_1, a_2, z_1, z_2, A, depositProof, depositSig, generateDuration.Milliseconds(), verifyDuration.Milliseconds()
}
