package main

import (
	"bulletproof"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/gtank/merlin"
)

func Bid(l int, g, h, pk, depositCommitment curves.Point, sig_sk *ecdsa.PrivateKey, R, deposit, bid *big.Int) (curves.Point, *bulletproof.RangeProof, *bulletproof.RangeProof, []byte, int64, int64) {
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

	var msg []byte

	// Bid Commitment
	bidCommitment := h.Mul(r).Add(g.Mul(b))

	// Bid Range Proof
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

	bidProof, err := prover.Prove(b, r, l, proofGenerators, transcript)
	if err != nil {
		panic(err)
	}

	// PPIC Difference Proof (bid < deposit)
	deposit_sub_bid := new(big.Int)
	deposit_sub_bid.Sub(deposit, bid)

	d_s_b, _ := curve.Scalar.SetBigInt(deposit_sub_bid)
	u2 := curve.Point.Random(crand.Reader)
	proofGenerators2 := bulletproof.RangeProofGenerators{
		G: g,
		H: h,
		U: u2,
	}

	differenceProof, err := prover.Prove(d_s_b, r, l, proofGenerators2, transcript)
	if err != nil {
		panic(err)
	}

	// Bid Signature
	msg = append(msg, bidCommitment.Scalar().Bytes()...)
	msg = append(msg, bidProof.MarshalBinary()...)
	msg = append(msg, differenceProof.MarshalBinary()...)

	hash := sha256.Sum256([]byte(msg))

	bidSig, err := ecdsa.SignASN1(crand.Reader, sig_sk, hash[:])
	if err != nil {
		panic(err)
	}

	generateDuration := time.Since(generateStart)
	verifyStart := time.Now()

	// Verify Bid Range Proof
	verifier, err := bulletproof.NewRangeVerifier(l, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	if err != nil {
		panic(err)
	}
	transcriptVerifier := merlin.NewTranscript("auction")
	verified_range_proof, err := verifier.Verify(bidProof, bidCommitment, proofGenerators, l, transcriptVerifier)
	if err != nil {
		panic(err)
	}
	if !verified_range_proof {
		panic("Verify Bid Range Proof Failed")
	}

	// Verify Deposit-Bid Difference Proof
	differenceCommitment := h.Mul(r).Add(g.Mul(d_s_b))
	verified_difference_proof, err := verifier.Verify(differenceProof, differenceCommitment, proofGenerators2, l, transcriptVerifier)
	if err != nil {
		panic(err)
	}
	if !verified_difference_proof {
		panic("Verify Deposit-Bid Difference Proof Failed")
	}

	// Verify Bid Signature
	verified_bid_sig := ecdsa.VerifyASN1(&sig_sk.PublicKey, hash[:], bidSig)
	if !verified_bid_sig {
		panic("Verify Bid Signature Failed")
	}

	verifyDuration := time.Since(verifyStart)

	return bidCommitment, bidProof, differenceProof, bidSig, generateDuration.Milliseconds(), verifyDuration.Milliseconds()
}
