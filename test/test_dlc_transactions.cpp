// Copyright 2019 CryptoGarage

#include "gtest/gtest.h"

#include "cfdcore/cfdcore_amount.h"

#include "dlc/dlc_transactions.h"

using cfd::Amount;
using cfd::core::Address;
using cfd::core::Pubkey;
using cfd::core::ScriptUtil;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::TxOut;

using dlc::DlcManager;

TEST(DlcManager, CreateFundTransactionTest) {
  // Arrange
  auto local_pubkey = Pubkey(
      "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
  auto remote_pubkey = Pubkey(
      "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe");
  std::vector<Txid> local_txids = {
      Txid("1234567890123456789012345678901234567890123456789012345678901234"),
      Txid("1234567890123456789012345678901234567890123456789012345678901234"),
  };
  std::vector<Txid> remote_txids = {
      Txid("1234567890123456789012345678901234567890123456789012345678901236"),
      Txid("1234567890123456789012345678901234567890123456789012345678901237"),
  };
  auto local_change_address =
      Address("bcrt1qn0fdlugwca99xfvug4nq875mchxxcxlygdan9x");
  auto remote_change_address =
      Address("bcrt1qqn5pejfcah0w8vcyltkcj7l0yt0mf2xnvq8pw2");
  auto local_amount = Amount::CreateBySatoshiAmount(10000);
  auto remote_amount = Amount::CreateBySatoshiAmount(20000);
  std::vector<TxIn> local_inputs = {TxIn(local_txids[0], 0, 0),
                                    TxIn(local_txids[1], 1, 0)};
  std::vector<TxIn> remote_inputs = {TxIn(remote_txids[0], 0, 0),
                                     TxIn(remote_txids[1], 0, 0)};
  TxOut local_change_output =
      TxOut(Amount::CreateBySatoshiAmount(2000), local_change_address);
  TxOut remote_change_output =
      TxOut(Amount::CreateBySatoshiAmount(5000), remote_change_address);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
      local_pubkey, remote_pubkey, local_amount, remote_amount, local_inputs,
      local_change_output, remote_inputs, remote_change_output);

  // Assert
  for (auto it = local_inputs.cbegin(); it != local_inputs.cend(); ++it) {
    EXPECT_NO_THROW(fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  for (auto it = remote_inputs.cbegin(); it != remote_inputs.cend(); ++it) {
    EXPECT_NO_THROW(fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  EXPECT_EQ(local_amount + remote_amount,
            fund_tx.GetTransaction().GetTxOut(0).GetValue());
}

TEST(DlcManager, CreateCetTest) {
  // Arrange
  auto local_pubkey = Pubkey(
      "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
  auto remote_pubkey = Pubkey(
      "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe");
  auto oracle_pubkey = Pubkey(
      "021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647");
  auto oracle_r_point = Pubkey(
      "021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647");
  std::string message("Hello");
  auto local_payout = Amount::CreateBySatoshiAmount(12345678);
  auto remote_payout = Amount::CreateBySatoshiAmount(87654321);
  auto fund_tx_id =
      Txid("1234567890123456789012345678901234567890123456789012345678901234");
  // Act
  auto cet = DlcManager::CreateCet(local_pubkey, oracle_pubkey, oracle_r_point,
                                   message, 1000, remote_pubkey, remote_pubkey,
                                   local_payout, remote_payout, fund_tx_id, 0);

  // Assert
  EXPECT_EQ(fund_tx_id.GetHex(),
            cet.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  EXPECT_EQ(0, cet.GetTransaction().GetTxIn(0).GetVout());
  EXPECT_EQ(local_payout, cet.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_TRUE(
      cet.GetTransaction().GetTxOut(0).GetLockingScript().IsP2wshScript());
  EXPECT_EQ(remote_payout, cet.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_TRUE(
      cet.GetTransaction().GetTxOut(1).GetLockingScript().IsP2wpkhScript());
}

TEST(DlcManager, CreateRefundTransaction) {
  // Arrange
  auto local_pubkey = Pubkey(
      "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
  auto remote_pubkey = Pubkey(
      "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe");
  auto local_amount = Amount::CreateBySatoshiAmount(2000);
  auto remote_amount = Amount::CreateBySatoshiAmount(3000);
  auto fund_tx_id =
      Txid("1234567890123456789012345678901234567890123456789012345678901234");
  auto expected_local_script =
      ScriptUtil::CreateP2wpkhLockingScript(local_pubkey);
  auto expected_remote_script =
      ScriptUtil::CreateP2wpkhLockingScript(remote_pubkey);
  // Act
  auto refund_tx = DlcManager::CreateRefundTransaction(
      local_pubkey, remote_pubkey, local_amount, remote_amount, 1000,
      fund_tx_id, 0);
  // Assert
  EXPECT_EQ(expected_local_script.GetHex(),
            refund_tx.GetTransaction().GetTxOut(0).GetLockingScript().GetHex());
  EXPECT_EQ(local_amount, refund_tx.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_EQ(expected_remote_script.GetHex(),
            refund_tx.GetTransaction().GetTxOut(1).GetLockingScript().GetHex());
  EXPECT_EQ(remote_amount, refund_tx.GetTransaction().GetTxOut(1).GetValue());
}

TEST(DlcManager, CreateClosingTransaction) {
  // Arrange
  auto dest_pubkey = Pubkey(
      "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
  auto amount = Amount::CreateBySatoshiAmount(40000);
  auto cet_id =
      Txid("1234567890123456789012345678901234567890123456789012345678901234");
  // Act
  auto closing_tx =
      DlcManager::CreateClosingTransaction(dest_pubkey, amount, cet_id, 0);

  // Assert
  ASSERT_EQ(amount, closing_tx.GetTransaction().GetTxOut(0).GetValue());
  ASSERT_EQ(cet_id.GetHex(),
            closing_tx.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  ASSERT_EQ(0, closing_tx.GetTransaction().GetTxIn(0).GetVout());
}

TEST(DlcManager, CreateCetRedeemScript) {
  // Arrange
  auto local_pubkey = Pubkey(
      "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
  auto remote_pubkey = Pubkey(
      "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe");
  auto oracle_pubkey = Pubkey(
      "021362bdf255b304dcd29bfdb6b5c63c68ef7df60e2b1fc156716efe077b794647");

  // Act/Assert
  EXPECT_NO_THROW(DlcManager::CreateCetRedeemScript(local_pubkey, oracle_pubkey,
                                                    1000, remote_pubkey));
}
