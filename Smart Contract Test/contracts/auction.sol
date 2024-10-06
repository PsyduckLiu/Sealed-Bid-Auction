// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract Auction{
    // Register Phase
    string PK;
    string PK_proofs_g_w;
    string PK_proofs_s;

    function submitRegister(string memory pk, string memory pk_proofs_g_w, string memory s) public {
        PK = pk;
        PK_proofs_g_w = pk_proofs_g_w;
        PK_proofs_s = s;
    }

    // Deposit Phase
    string DepositCiphertext;
    string DepositCommitment;
    string A_1_1;
    string A_2_1;
    string Z_1_1;
    string Z_2_1;
    string As_1;
    string DepositProof;
    string DepositSig;

    function submitDeposit(string memory depositCiphertext, string memory depositCommitment, string memory a_1_1, string memory a_2_1, string memory z_1_1, string memory z_2_1, string memory as_1, string memory depositProof, string memory depositSig) public {
        DepositCiphertext = depositCiphertext;
        DepositCommitment = depositCommitment;
        A_1_1 = a_1_1;
        A_2_1 = a_2_1;
        Z_1_1 = z_1_1;
        Z_2_1 = z_2_1;
        As_1 = as_1;
        DepositProof = depositProof;
        DepositSig = depositSig;
    }

    // Bid Phase
    string BidCommitment;
    string BidProof;
    string DifferenceProof;
    string BidSig;

    function submitBid(string memory bidCommitment, string memory  bidProof, string memory differenceProof, string memory bidSig) public {
        BidCommitment = bidCommitment;
        BidProof = bidProof;
        DifferenceProof = differenceProof;
        BidSig = bidSig;
    }

    // Open Phase
    string BidCiphertext;
    string A_1_2;
    string A_2_2;
    string Z_1_2;
    string Z_2_2;
    string As_2;
    string OpenSig;

    function submitOpen(string memory bidCiphertext, string memory a_1_2, string memory a_2_2, string memory z_1_2, string memory z_2_2, string memory as_2, string memory openSig) public {
        BidCiphertext = bidCiphertext;
        A_1_2 = a_1_2;
        A_2_2 = a_2_2;
        Z_1_2 = z_1_2;
        Z_2_2 = z_2_2;
        As_2 = as_2;
        OpenSig = openSig;
    }

    // Award Phase
    string WinningBid;
    string WinningProof;

    function submitAward(string memory winningBid, string memory winningProof) public {
        WinningBid = winningBid;
        WinningProof = winningProof;
    }


}