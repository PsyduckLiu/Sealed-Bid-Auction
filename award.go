package main

import (
	"bulletproof"
	crand "crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
	"github.com/gtank/merlin"
)

func findMax(arr []*big.Int) (*big.Int, int) {
	if len(arr) == 0 {
		return nil, 0
	}

	max := arr[0]
	max_index := 0
	for i := 1; i < len(arr); i++ {
		if arr[i].Cmp(max) > 0 {
			max = arr[i]
			max_index = i
		}
	}
	return max, max_index
}

func arrayEqual(a, b []*big.Int) bool {
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for key, val := range a {
		if val.Cmp(b[key]) != 0 {
			return false
		}
	}
	return true
}

func Award(n, l int, maxFund *big.Int, g, h curves.Point, pk []curves.Point, rs, bids []*big.Int, bidCiphertext []elgamal.HomomorphicCipherText) (int, *bulletproof.RangeProof, int64, int64) {
	generateStart := time.Now()

	curve := curves.ED25519()

	// Batch BulletProofs
	difference := new(big.Int)

	var Differences []curves.Scalar
	var Rs []curves.Scalar
	// var Bids []*big.Int

	// Determine the winning bid
	// for i := 0; i < len(bidCiphertext); i++ {
	// 	r, err := curve.Scalar.SetBigInt(rs[i])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	Rs = append(Rs, r)

	// 	p := big.NewInt(0)
	// 	for {
	// 		if p.Cmp(maxFund) > 0 {
	// 			break
	// 		}

	// 		plainExp, err := curve.Scalar.SetBigInt(p)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		plainText := pk[i].Mul(r).Add(g.Mul(plainExp))
	// 		if plainText.Equal(bidCiphertext[i].C2) {
	// 			Bids = append(Bids, p)
	// 			break
	// 		}

	// 		p.Add(p, big.NewInt(1))
	// 	}
	// }
	// if !arrayEqual(bids, Bids) {
	// 	panic("Bids are not equal")
	// }

	winningBid, max_index := findMax(bids)
	fmt.Println("Bids are", bids)
	fmt.Println("The winning bid is", winningBid)

	// Winning Range Proof
	u := curve.Point.Random(crand.Reader)
	proofGenerators := bulletproof.RangeProofGenerators{
		G: g,
		H: h,
		U: u,
	}

	for i := 0; i < n; i++ {
		difference.Sub(winningBid, bids[i])
		v, err := curve.Scalar.SetBigInt(difference)
		if err != nil {
			panic(err)
		}
		r, err := curve.Scalar.SetBigInt(rs[i])
		if err != nil {
			panic(err)
		}
		Rs = append(Rs, r)

		Differences = append(Differences, v)
	}

	prover, err := bulletproof.NewRangeProver(n*l, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	if err != nil {
		panic(err)
	}
	transcript := merlin.NewTranscript("auction")

	differenceProofs, err := prover.BatchProve(Differences, Rs, l, proofGenerators, transcript)
	if err != nil {
		panic(err)
	}
	capV := getcapVBatched(Differences, Rs, g, h)

	generateDuration := time.Since(generateStart)
	verifyStart := time.Now()

	// Verify Winning Range Proof
	verifier, err := bulletproof.NewRangeVerifier(n*l, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	if err != nil {
		panic(err)
	}
	transcriptVerifier := merlin.NewTranscript("auction")
	verified_difference_proofs, err := verifier.VerifyBatched(differenceProofs, capV, proofGenerators, l, transcriptVerifier)
	if err != nil {
		panic(err)
	}
	if !verified_difference_proofs {
		panic("Verify Deposit-Bid Difference Range Proof Failed")
	}

	verifyDuration := time.Since(verifyStart)

	return max_index, differenceProofs, generateDuration.Milliseconds(), verifyDuration.Milliseconds()
}
