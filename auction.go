package main

import (
	"bulletproof"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
)

func main() {
	// 1. Setup Phase
	g, h, n, l, maxFund := Setup()

	setupLen := 0
	setupLen += len(g.Scalar().Bytes())
	setupLen += len(h.Scalar().Bytes())
	setupLen += 16 // length of n,l
	fmt.Printf("[1]Setup Phase: Length of messages is %v bytes\n", setupLen)

	// 2. Register Phase
	SK, PK, R, Sig_SK, G_w, S, register_gen_time, register_verify_time := Register(n, g)
	fmt.Println("[2]Register Phase: PK is", hex.EncodeToString(PK[0].ToAffineCompressed()))
	fmt.Println("[2]Register Phase: G_w is", hex.EncodeToString(G_w[0].ToAffineCompressed()))
	fmt.Println("[2]Register Phase: S is", S[0].String())

	registerLen := 0
	for i := 0; i < n; i++ {
		registerLen += len(SK[i].Bytes())
		registerLen += len(PK[i].ToAffineCompressed())
		registerLen += len(R[i].Bytes())
		registerLen += len(Sig_SK[i].D.Bytes())
		registerLen += len(Sig_SK[i].X.Bytes())
		registerLen += len(Sig_SK[i].Y.Bytes())
		registerLen += len(G_w[i].ToAffineCompressed())
		registerLen += len(S[i].Bytes())
	}
	fmt.Printf("[2]Register Phase: Length of one message is %v bytes\n", registerLen/n)
	fmt.Println("[2]Register Phase: Time of generating messages is", int(register_gen_time)/n, "ms")
	fmt.Println("[2]Register Phase: Time of verifying messages is", int(register_verify_time)/n, "ms")

	// 3. Deposit Phase
	var Deposits []*big.Int
	var DepositCiphertext []elgamal.HomomorphicCipherText
	var DepositCommitment []curves.Point
	var A_1_1 []curves.Point
	var A_2_1 []curves.Point
	var Z_1_1 []*big.Int
	var Z_2_1 []*big.Int
	var As_1 []curves.Point
	var DepositProof []*bulletproof.RangeProof
	var DepositSig [][]byte
	Deposit_Gen_Time := 0
	Deposit_Verify_Time := 0
	for i := 0; i < n; i++ {
		deposit_i, err := crand.Int(crand.Reader, maxFund)
		if err != nil {
			panic(err)
		}
		depositCiphertext, depositCommitment, a_1, a_2, z_1, z_2, A, depositProof, depositSig, deposit_gen_time, deposit_verify_time := Deposit(l, g, h, PK[i], Sig_SK[i], R[i], deposit_i)

		Deposits = append(Deposits, deposit_i)
		DepositCiphertext = append(DepositCiphertext, depositCiphertext)
		DepositCommitment = append(DepositCommitment, depositCommitment)
		A_1_1 = append(A_1_1, a_1)
		A_2_1 = append(A_2_1, a_2)
		Z_1_1 = append(Z_1_1, z_1)
		Z_2_1 = append(Z_2_1, z_2)
		As_1 = append(As_1, A)
		DepositProof = append(DepositProof, depositProof)
		DepositSig = append(DepositSig, depositSig)

		Deposit_Gen_Time += int(deposit_gen_time)
		Deposit_Verify_Time += int(deposit_verify_time)
	}

	depositLen := 0
	for i := 0; i < n; i++ {
		DepositCiphertextByte, err := DepositCiphertext[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		depositLen += len(DepositCiphertextByte)
		depositLen += len(DepositCommitment[i].ToAffineCompressed())
		depositLen += len(A_1_1[i].ToAffineCompressed())
		depositLen += len(A_2_1[i].ToAffineCompressed())
		depositLen += len(Z_1_1[i].Bytes())
		depositLen += len(Z_2_1[i].Bytes())
		depositLen += len(As_1[i].ToAffineCompressed())
		depositLen += len(DepositProof[i].MarshalBinary())
		depositLen += len(DepositSig[i])

		if i == 0 {
			fmt.Println("[3]Deposit Phase: DepositCiphertext is", hex.EncodeToString(DepositCiphertextByte))
			fmt.Println("[3]Deposit Phase: DepositCommitment is", hex.EncodeToString(DepositCommitment[i].ToAffineCompressed()))
			fmt.Println("[3]Deposit Phase: A_1_1 is", hex.EncodeToString(A_1_1[i].ToAffineCompressed()))
			fmt.Println("[3]Deposit Phase: A_2_1 is", hex.EncodeToString(A_2_1[i].ToAffineCompressed()))
			fmt.Println("[3]Deposit Phase: Z_1_1 is", Z_1_1[i].String())
			fmt.Println("[3]Deposit Phase: Z_2_1 is", Z_2_1[i].String())
			fmt.Println("[3]Deposit Phase: As_1 is", hex.EncodeToString(As_1[i].ToAffineCompressed()))
			fmt.Println("[3]Deposit Phase: DepositProof is", hex.EncodeToString(DepositProof[i].MarshalBinary()))
			fmt.Println("[3]Deposit Phase: DepositSig is", hex.EncodeToString(DepositSig[i]))
		}

	}

	fmt.Printf("[3]Deposit Phase: Length of one message is %v bytes\n", depositLen/n)
	fmt.Println("[3]Deposit Phase: Time of generating messages is", Deposit_Gen_Time/n, "ms")
	fmt.Println("[3]Deposit Phase: Time of verifying messages is", Deposit_Verify_Time/n, "ms")

	// 4. Bid Phase
	var Bids []*big.Int
	var BidCommitment []curves.Point
	var BidProof []*bulletproof.RangeProof
	var DifferenceProof []*bulletproof.RangeProof
	var BidSig [][]byte
	Bid_Gen_Time := 0
	Bid_Verify_Time := 0
	for i := 0; i < n; i++ {
		bid_i, err := crand.Int(crand.Reader, Deposits[i])
		if err != nil {
			panic(err)
		}
		bidCommitment, bidProof, differenceProof, bidSig, bid_gen_time, bid_verify_time := Bid(l, g, h, PK[i], DepositCommitment[i], Sig_SK[i], R[i], Deposits[i], bid_i)

		Bids = append(Bids, bid_i)
		BidCommitment = append(BidCommitment, bidCommitment)
		BidProof = append(BidProof, bidProof)
		DifferenceProof = append(DifferenceProof, differenceProof)
		BidSig = append(BidSig, bidSig)
		Bid_Gen_Time += int(bid_gen_time)
		Bid_Verify_Time += int(bid_verify_time)
	}

	bidLen := 0
	for i := 0; i < n; i++ {
		bidLen += len(BidCommitment[i].ToAffineCompressed())
		bidLen += len(BidProof[i].MarshalBinary())
		bidLen += len(DifferenceProof[i].MarshalBinary())
		bidLen += len(BidSig[i])

		if i == 0 {
			fmt.Println("[4]Bid Phase: BidCommitment is", hex.EncodeToString(BidCommitment[i].ToAffineCompressed()))
			fmt.Println("[4]Bid Phase: BidProof is", hex.EncodeToString(BidProof[i].MarshalBinary()))
			fmt.Println("[4]Bid Phase: DifferenceProof is", hex.EncodeToString(DifferenceProof[i].MarshalBinary()))
			fmt.Println("[4]Bid Phase: BidSig is", hex.EncodeToString(BidSig[i]))
		}
	}
	fmt.Printf("[4]Bid Phase: Length of one message is %v bytes\n", bidLen/n)
	fmt.Println("[4]Bid Phase: Time of generating messages is", Bid_Gen_Time/n, "ms")
	fmt.Println("[4]Bid Phase: Time of verifying messages is", Bid_Verify_Time/n, "ms")

	// 5. Open Phase
	var BidCiphertext []elgamal.HomomorphicCipherText
	var OpenSig [][]byte
	var A_1_2 []curves.Point
	var A_2_2 []curves.Point
	var Z_1_2 []*big.Int
	var Z_2_2 []*big.Int
	var As []curves.Point
	Open_Gen_Time := 0
	Open_Verify_Time := 0
	for i := 0; i < n; i++ {
		bidCiphertext, a_1, a_2, z_1, z_2, A, openSig, opem_gen_time, open_verify_time := Open(l, g, h, PK[i], BidCommitment[i], Sig_SK[i], R[i], Bids[i])
		BidCiphertext = append(BidCiphertext, bidCiphertext)
		A_1_2 = append(A_1_2, a_1)
		A_2_2 = append(A_2_2, a_2)
		Z_1_2 = append(Z_1_2, z_1)
		Z_2_2 = append(Z_2_2, z_2)
		As = append(As, A)
		OpenSig = append(OpenSig, openSig)
		Open_Gen_Time += int(opem_gen_time)
		Open_Verify_Time += int(open_verify_time)
	}

	openLen := 0
	for i := 0; i < n; i++ {
		OpenCiphertextByte, err := BidCiphertext[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		openLen += len(OpenCiphertextByte)
		openLen += len(A_1_2[i].ToAffineCompressed())
		openLen += len(A_2_2[i].ToAffineCompressed())
		openLen += len(Z_1_2[i].Bytes())
		openLen += len(Z_2_2[i].Bytes())
		openLen += len(As[i].ToAffineCompressed())
		openLen += len(OpenSig[i])

		if i == 0 {
			fmt.Println("[5]Open Phase: BidCiphertext is", hex.EncodeToString(OpenCiphertextByte))
			fmt.Println("[5]Open Phase: A_1_2 is", hex.EncodeToString(A_1_2[i].ToAffineCompressed()))
			fmt.Println("[5]Open Phase: A_2_2 is", hex.EncodeToString(A_2_2[i].ToAffineCompressed()))
			fmt.Println("[5]Open Phase: Z_1_2 is", Z_1_2[i].String())
			fmt.Println("[5]Open Phase: Z_2_2 is", Z_2_2[i].String())
			fmt.Println("[5]Open Phase: As is", hex.EncodeToString(As[i].ToAffineCompressed()))
			fmt.Println("[5]Open Phase: OpenSig is", hex.EncodeToString(OpenSig[i]))

		}
	}
	fmt.Printf("[5]Open Phase: Length of one message is %v bytes\n", openLen/n)
	fmt.Println("[5]Open Phase: Time of generating messages is", Open_Gen_Time/n, "ms")
	fmt.Println("[5]Open Phase: Time of verifying messages is", Open_Verify_Time/n, "ms")

	// 6. Award Phase
	winningBid, winningProof, award_gen_time, award_verify_time := Award(n, l, maxFund, g, h, PK, R, Bids, BidCiphertext)

	awardLen := 0
	awardLen += len(winningProof.MarshalBinary())
	awardLen += len(BidCommitment[winningBid].ToAffineCompressed())

	fmt.Println("[6]Award Phase: WinningBid is", hex.EncodeToString(BidCommitment[winningBid].ToAffineCompressed()))
	fmt.Println("[6]Award Phase: WinningProof is", hex.EncodeToString(winningProof.MarshalBinary()))

	fmt.Printf("[6]Award Phase: Length of one message is %v bytes\n", awardLen)
	fmt.Println("[6]Award Phase: Time of generating one message is", int(award_gen_time), "ms")
	fmt.Println("[6]Award Phase: Time of verifying one message is", int(award_verify_time), "ms")

	// Summary
	fmt.Println("***********************************************************************")
	fmt.Println("For one bidder")

	fmt.Printf("[2]Register Phase: Length of one message is %v bytes\n", registerLen/n)
	fmt.Printf("[3]Deposit Phase: Length of one message is %v bytes\n", depositLen/n)
	fmt.Printf("[4]Bid Phase: Length of one message is %v bytes\n", bidLen/n)
	fmt.Printf("[5]Open Phase: Length of one message is %v bytes\n", openLen/n)

	fmt.Printf("[2]Register Phase: Time of generating messages is %v ms\n", int(register_gen_time)/n)
	fmt.Printf("[3]Deposit Phase: Time of generating messages is %v ms\n", Deposit_Gen_Time/n)
	fmt.Printf("[4]Bid Phase: Time of generating messages is %v ms\n", Bid_Gen_Time/n)
	fmt.Printf("[5]Open Phase: Time of generating messages is %v ms\n", Open_Gen_Time/n)

	fmt.Println("[2]Register Phase: Time of verifying messages is", int(register_verify_time)/n, "ms")
	fmt.Printf("[3]Deposit Phase: Time of verifying messages is %v ms\n", Deposit_Verify_Time/n)
	fmt.Printf("[4]Bid Phase: Time of verifying messages is %v ms\n", Bid_Verify_Time/n)
	fmt.Printf("[5]Open Phase: Time of verifying messages is %v ms\n", Open_Verify_Time/n)
	fmt.Printf("[6]Award Phase: Time of verifying one message is %v ms\n", int(award_verify_time))

	fmt.Println("***********************************************************************")
	fmt.Println("For the auctioneer")
	fmt.Printf("[7]Award Phase: Length of one message is %v bytes\n", awardLen)

	fmt.Printf("[*]Verify Phase: Time of verifying all messages is %v ms\n", int(register_verify_time)+Deposit_Verify_Time+Bid_Verify_Time+Open_Verify_Time)
	fmt.Printf("[7]Award Phase: Time of generating one message is %v ms\n", int(award_gen_time))
}
