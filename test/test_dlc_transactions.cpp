// Copyright 2019 CryptoGarage

#include "gtest/gtest.h"

#include "cfdcore/cfdcore_amount.h"

#include "cfd/cfd_transaction.h"

#include "dlc/dlc_transactions.h"
#include "dlc/dlc_util.h"
#include "dlc/dlc_exception.h"
#include "wally_crypto.h"  // NOLINT

using cfd::Amount;
using cfd::core::Address;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CryptoUtil;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::NetType;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::ScriptUtil;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::TxOut;
using cfd::core::WitnessVersion;

using cfd::dlc::DlcException;
using cfd::dlc::DlcManager;
using cfd::dlc::DlcOutcome;
using cfd::dlc::DlcUtil;

const Privkey ORACLE_PRIVKEY(
    "ded9a76a0a77399e1c2676324118a0386004633f16245ad30d172b15c1f9e2d3");
const Pubkey ORACLE_PUBKEY = ORACLE_PRIVKEY.GeneratePubkey();
const Privkey ORACLE_K_VALUE(
    "be3cc8de25c50e25f69e2f88d151e3f63e99c3a44fed2bdd2e3ee70fe141c5c3");
const std::vector<Pubkey> ORACLE_R_POINTS = {
    DlcUtil::GetSchnorrPublicNonce(ORACLE_K_VALUE)};
const ByteData ORACLE_SIGNATURE(
    "8a820c2a94e3f85362c457b80cff914b13fbbd67df49df24181f3b916331a2e6");
const Privkey LOCAL_FUND_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000001");
const Pubkey LOCAL_FUND_PUBKEY = LOCAL_FUND_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_FUND_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000002");
const Pubkey REMOTE_FUND_PUBKEY = REMOTE_FUND_PRIVKEY.GeneratePubkey();
const Privkey LOCAL_SWEEP_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000003");
const Pubkey LOCAL_SWEEP_PUBKEY = LOCAL_SWEEP_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_SWEEP_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000004");
const Pubkey REMOTE_SWEEP_PUBKEY = REMOTE_SWEEP_PRIVKEY.GeneratePubkey();
const Privkey LOCAL_INPUT_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000005");
const Pubkey LOCAL_INPUT_PUBKEY = LOCAL_INPUT_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_INPUT_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000006");
const Pubkey REMOTE_INPUT_PUBKEY = REMOTE_INPUT_PRIVKEY.GeneratePubkey();
const Amount LOCAL_INPUT_AMOUNT = Amount::CreateByCoinAmount(50);
const Amount REMOTE_INPUT_AMOUNT = Amount::CreateByCoinAmount(50);
const Amount LOCAL_COLLATERAL_AMOUNT = Amount::CreateBySatoshiAmount(100000000);
const Amount REMOTE_COLLATERAL_AMOUNT =
    Amount::CreateBySatoshiAmount(100000000);
const Amount FUND_OUTPUT = Amount::CreateBySatoshiAmount(200000312);
const Amount WIN_AMOUNT = Amount::CreateBySatoshiAmount(199900000);
const Amount LOSE_AMOUNT = Amount::CreateBySatoshiAmount(100000);
const std::vector<std::string> WIN_MESSAGES = {"WIN"};
const std::vector<std::string> LOSE_MESSAGES = {"LOSE"};
const std::vector<TxIn> LOCAL_INPUTS = {TxIn(
    Txid("83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"), 0,
    0)};
const std::vector<TxIn> REMOTE_INPUTS = {TxIn(
    Txid("bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"), 0,
    0)};
const Address LOCAL_CHANGE_ADDRESS(
    "bcrt1qlgmznucxpdkp5k3ktsct7eh6qrc4tju7ktjukn");
const Address REMOTE_CHANGE_ADDRESS(
    "bcrt1qvh2dvgjctwh4z5w7sc93u7h4sug0yrdz2lgpqf");
const Address LOCAL_FINAL_ADDRESS(
    NetType::kRegtest, WitnessVersion::kVersion0,
    Privkey("0000000000000000000000000000000000000000000000000000000000000007")
        .GeneratePubkey());
const Address REMOTE_FINAL_ADDRESS(
    NetType::kRegtest, WitnessVersion::kVersion0,
    Privkey("0000000000000000000000000000000000000000000000000000000000000008")
        .GeneratePubkey());
const uint32_t MATURITY_TIME = 1579072156;
const ByteData FUND_TX_HEX(
    "020000000001024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b6d"
    "26830000000000ffffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523"
    "ef072fa292bc0000000000ffffffff0338c3eb0b000000002200209b984c7bae3efddc3a3f"
    "0a20ff81bfe89ed1fe07ff13e562149ee654bed845dbe70f102401000000160014fa3629f3"
    "060b6c1a5a365c30bf66fa00f155cb9ee70f10240100000016001465d4d622585baf5151de"
    "860b1e7af58710f20da20247304402207108de1563ae311f8d4217e1c0c7463386c1a135be"
    "6af88cbe8d89a3a08d65090220195a2b0140fb9ba83f20cf45ad6ea088bb0c6860c0d4995f"
    "1cf1353739ca65a90121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8"
    "d569b240efe4024730440220048716eaee918aebcb1bfcfaf7564e78293a7bb0164d9a7844"
    "e42fceb5ae393c022022817d033c9db19c5bdcadd49b7587a810b6fc2264158a59665aba8a"
    "b298455b012103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a146029"
    "755600000000");
const Txid FUND_TX_ID(
    "f4f1a5d41ce0133e4cb43a230a25fc75eed8a207b24865f715b8b9902d94b064");

const ByteData CET_HEX(
    "0200000000010164b0942d90b9b815f76548b207a2d8ee75fc250a233ab44c3e13e01cd4a5"
    "f1f40000000000feffffff02da3bea0b00000000220020a8df06fb6408f8502af80f09cd9a"
    "9084603568c2338eda1a30b8e9bf62b679aea0860100000000001600149652d86bedf43ad2"
    "64362e6e6eba6eb764508127040047304402204986d1ffb0ff379dbd42a7c1606822c135f9"
    "e4b9f0af1309a9d383f9778b80d2022078861c7cdd24a59e50cf17753bcdfec1eed8708f21"
    "588d1090c38b2766a098510147304402207b3460f1e7f5af3738467715f621774282eba8fa"
    "1752c859338c095dd952764d022013b3ba4b2a3ec489715b2c10974c4395cb49e7ba7acae7"
    "f0125549a53f68679d014752210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28"
    "d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac"
    "09b95c709ee552ae9cba1e5e");

const Txid CET_ID(
    "b76358e12874e7448a479ffcb178f9775ece2d83262ac2c17c381e5777b65cd6");
const ByteData CLOSING_HEX(
    "02000000000101d65cb677571e387cc1c22a26832dce5e77f978b1fc9f478a44e77428e158"
    "63b70000000000ffffffff017837ea0b000000001600145dedfbf9ea599dd4e3ca6a80b333"
    "c472fd0b3f690347304402207452592666a8465e86eb6e3766e534c79e6ce064a7648e9cce"
    "519454cf8f6ea10220123c46a022c2bb1f03e68826b45cfa7c7af07223c0b46f1e7c6c90d6"
    "b570fbc70101014c632102e07cca3429680d949f968ea585d3e04f5b536fc46a0caf901083"
    "28fd663a86de670164b2752102e493dbf1c10d80f3581e4904930b1404cc6c13900ee07584"
    "74fa94abe8c4cd1368ac00000000");
uint32_t DELAY = 100;

const ByteData REFUND_HEX(
    "0200000000010164b0942d90b9b815f76548b207a2d8ee75fc250a233ab44c3e13e01cd4a5"
    "f1f40000000000feffffff0248e1f505000000001600145dedfbf9ea599dd4e3ca6a80b333"
    "c472fd0b3f6948e1f505000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
    "04004730440220504d529dd7bdebe730f8d9e77630028b63a4a7fbfe7fd218dda8d60aef9b"
    "c3560220539489f1d2c2e36fd3fe3985312f4b6c1981d26957da31eea71f29e348c23c0f01"
    "47304402201f7a50bb8fcfdb4798afeb3bf53469acf349ff8a624af4263655bc71e02020e0"
    "022014a7ac5db59af778d3120c6e0d705a5b4e7e171f2a62bcee94a4759ed6bd22d6014752"
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
    "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae6400000"
    "0");

TEST(DlcManager, FundTransactionTest) {
  // Arrange
  auto change = Amount::CreateBySatoshiAmount(4899999719);
  TxOut local_change_output = TxOut(change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(change, REMOTE_CHANGE_ADDRESS);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
      LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS,
      local_change_output, REMOTE_INPUTS, remote_change_output);
  auto local_utxo_txid = LOCAL_INPUTS[0].GetTxid();
  auto local_utxo_vout = LOCAL_INPUTS[0].GetVout();
  auto remote_utxo_txid = REMOTE_INPUTS[0].GetTxid();
  auto remote_utxo_vout = REMOTE_INPUTS[0].GetVout();
  DlcManager::SignFundingTransactionInput(&fund_tx, LOCAL_INPUT_PRIVKEY,
                                          local_utxo_txid, local_utxo_vout,
                                          LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundingTransactionInput(&fund_tx, REMOTE_INPUT_PRIVKEY,
                                          remote_utxo_txid, remote_utxo_vout,
                                          REMOTE_INPUT_AMOUNT);
  auto local_signature = DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, LOCAL_INPUT_PRIVKEY, local_utxo_txid, local_utxo_vout,
      LOCAL_INPUT_AMOUNT);
  auto remote_signature = DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, REMOTE_INPUT_PRIVKEY, remote_utxo_txid, remote_utxo_vout,
      REMOTE_INPUT_AMOUNT);

  // Assert
  for (auto it = LOCAL_INPUTS.cbegin(); it != LOCAL_INPUTS.cend(); ++it) {
    EXPECT_NO_THROW(fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  for (auto it = REMOTE_INPUTS.cbegin(); it != REMOTE_INPUTS.cend(); ++it) {
    EXPECT_NO_THROW(fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  EXPECT_EQ(FUND_OUTPUT, fund_tx.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_EQ(change, fund_tx.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_EQ(change, fund_tx.GetTransaction().GetTxOut(2).GetValue());
  EXPECT_EQ(FUND_TX_HEX.GetHex(), fund_tx.GetTransaction().GetHex());
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
      fund_tx, local_signature, LOCAL_INPUT_PUBKEY, local_utxo_txid,
      local_utxo_vout, LOCAL_INPUT_AMOUNT));
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
      fund_tx, remote_signature, REMOTE_INPUT_PRIVKEY.GeneratePubkey(),
      remote_utxo_txid, remote_utxo_vout, REMOTE_INPUT_AMOUNT));
  auto oracle_sign =
      DlcUtil::SchnorrSign(ORACLE_PRIVKEY, ORACLE_K_VALUE, WIN_MESSAGES[0]);
  std::cerr << oracle_sign.GetHex() << std::endl;
  std::cerr << fund_tx.GetTransaction().GetTxid().GetHex() << std::endl;
}

TEST(DlcManager, CetTest) {
  // Arrange
  auto local_payout = Amount::CreateBySatoshiAmount(199900000);
  auto closing_fee = Amount::CreateBySatoshiAmount(122);
  auto remote_payout = Amount::CreateBySatoshiAmount(100000);
  // Act
  auto cet = DlcManager::CreateCet(
      LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
      REMOTE_FINAL_ADDRESS, ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES, DELAY,
      WIN_AMOUNT + closing_fee, LOSE_AMOUNT, MATURITY_TIME, FUND_TX_ID, 0);
  auto local_signature = DlcManager::GetRawCetSignature(
      cet, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_signature = DlcManager::GetRawCetSignature(
      cet, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToCet(&cet, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
                                 {local_signature, remote_signature},
                                 FUND_TX_ID, 0);

  // Assert
  EXPECT_EQ(FUND_TX_ID.GetHex(),
            cet.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  EXPECT_EQ(0, cet.GetTransaction().GetTxIn(0).GetVout());
  EXPECT_EQ(local_payout + closing_fee,
            cet.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_TRUE(
      cet.GetTransaction().GetTxOut(0).GetLockingScript().IsP2wshScript());
  EXPECT_EQ(remote_payout, cet.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_TRUE(
      cet.GetTransaction().GetTxOut(1).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(CET_HEX.GetHex(), cet.GetHex());
  EXPECT_TRUE(DlcManager::VerifyCetSignature(
      cet, local_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT,
      FUND_TX_ID));
  EXPECT_TRUE(DlcManager::VerifyCetSignature(
      cet, remote_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT,
      FUND_TX_ID, 0, true));
}

TEST(DlcManager, CetBadMaturityTest) {
  // Arrange
  auto closing_fee = Amount::CreateBySatoshiAmount(122);

  // Act/Assert

  ASSERT_THROW(
      DlcManager::CreateCet(
          LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
          REMOTE_FINAL_ADDRESS, ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES,
          DELAY, WIN_AMOUNT + closing_fee, LOSE_AMOUNT, 50, FUND_TX_ID, 0),
      DlcException);
}

TEST(DlcManager, RefundTransactionTest) {
  // Arrange
  // Act
  auto refund_tx = DlcManager::CreateRefundTransaction(
      LOCAL_FINAL_ADDRESS, REMOTE_FINAL_ADDRESS,
      Amount::CreateBySatoshiAmount(100000072),
      Amount::CreateBySatoshiAmount(100000072), 100, FUND_TX_ID, 0);

  auto local_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_signature, remote_signature}, FUND_TX_ID, 0);

  // Assert
  EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(DlcManager::VerifyRefundTxSignature(
      refund_tx, local_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, false, FUND_TX_ID, 0));
  EXPECT_TRUE(DlcManager::VerifyRefundTxSignature(
      refund_tx, remote_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, true, FUND_TX_ID, 0));
}

TEST(DlcManager, ClosingTransactionTest) {
  // Arrange
  auto input_amount = Amount::CreateBySatoshiAmount(199900122);
  auto output_amount = Amount::CreateBySatoshiAmount(199899000);
  // Act
  auto closing_tx = DlcManager::CreateClosingTransaction(
      LOCAL_FINAL_ADDRESS, output_amount, CET_ID, 0);
  DlcManager::SignClosingTransactionInput(
      &closing_tx, LOCAL_FUND_PRIVKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
      ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES, DELAY, {ORACLE_SIGNATURE},
      input_amount, CET_ID, 0);

  auto local_closing_signature = DlcManager::GetRawClosingTransactionSignature(
      closing_tx, LOCAL_FUND_PRIVKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
      ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES, DELAY, {ORACLE_SIGNATURE},
      input_amount, CET_ID, 0);
  auto oracle_message_key =
      DlcUtil::GetCommittedKey(ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES);
  bool is_signature_valid = closing_tx.VerifyInputSignature(
      local_closing_signature,
      DlcUtil::GetCombinedKey(ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES,
                              LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY),
      CET_ID, 0,
      DlcManager::CreateCetRedeemScript(LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY,
                                        REMOTE_SWEEP_PUBKEY, ORACLE_PUBKEY,
                                        ORACLE_R_POINTS, WIN_MESSAGES, DELAY),
      SigHashType(), input_amount, WitnessVersion::kVersion0);
  // Assert
  ASSERT_EQ(output_amount, closing_tx.GetTransaction().GetTxOut(0).GetValue());
  ASSERT_EQ(CET_ID.GetHex(),
            closing_tx.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  ASSERT_EQ(0, closing_tx.GetTransaction().GetTxIn(0).GetVout());
  ASSERT_EQ(CLOSING_HEX.GetHex(), closing_tx.GetHex());
  ASSERT_TRUE(is_signature_valid);
}

TEST(DlcManager, PenaltyTransactionTest) {
  // Arrange
  auto input_amount = Amount::CreateBySatoshiAmount(199900122);
  auto output_amount = Amount::CreateBySatoshiAmount(199899000);
  // Act
  auto penalty_tx = DlcManager::CreatePenaltyTransaction(
      REMOTE_FINAL_ADDRESS, output_amount, CET_ID, 0);
  DlcManager::SignPenaltyTransactionInput(
      &penalty_tx, REMOTE_SWEEP_PRIVKEY, LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY,
      ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES, DELAY, input_amount, CET_ID,
      0);

  auto remote_penalty_signature = DlcManager::GetRawPenaltyTransactionSignature(
      penalty_tx, REMOTE_SWEEP_PRIVKEY, LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY,
      ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES, DELAY, input_amount, CET_ID,
      0);
  bool is_signature_valid = penalty_tx.VerifyInputSignature(
      remote_penalty_signature, REMOTE_SWEEP_PUBKEY, CET_ID, 0,
      DlcManager::CreateCetRedeemScript(LOCAL_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY,
                                        REMOTE_SWEEP_PUBKEY, ORACLE_PUBKEY,
                                        ORACLE_R_POINTS, WIN_MESSAGES, DELAY),
      SigHashType(), input_amount, WitnessVersion::kVersion0);

  // Assert
  ASSERT_EQ(output_amount, penalty_tx.GetTransaction().GetTxOut(0).GetValue());
  ASSERT_EQ(CET_ID.GetHex(),
            penalty_tx.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  ASSERT_EQ(0, penalty_tx.GetTransaction().GetTxIn(0).GetVout());
  ASSERT_TRUE(is_signature_valid);
}

TEST(DlcManager, MutualClosingTransactionTest) {
  // Arrange
  // Act
  auto mutual_closing_tx = DlcManager::CreateMutualClosingTransaction(
      LOCAL_FINAL_ADDRESS, REMOTE_FINAL_ADDRESS,
      Amount::CreateBySatoshiAmount(100000072),
      Amount::CreateBySatoshiAmount(100000072), FUND_TX_ID, 0);
  auto local_signature = DlcManager::GetRawMutualClosingTxSignature(
      mutual_closing_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_signature = DlcManager::GetRawMutualClosingTxSignature(
      mutual_closing_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToMutualClosingTx(
      &mutual_closing_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_signature, remote_signature}, FUND_TX_ID, 0);

  // Assert
  //   EXPECT_EQ(REFUND_HEX.GetHex(), mutual_closing_tx.GetHex());
  EXPECT_TRUE(DlcManager::VerifyMutualClosingTxSignature(
      mutual_closing_tx, local_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, false));
  EXPECT_TRUE(DlcManager::VerifyMutualClosingTxSignature(
      mutual_closing_tx, remote_signature, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, FUND_TX_ID, 0, FUND_OUTPUT, true));
}

TEST(DlcManager, CreateDlcTransactions) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_MESSAGES, WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_MESSAGES, LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
      LOCAL_CHANGE_ADDRESS, REMOTE_CHANGE_ADDRESS, LOCAL_FINAL_ADDRESS,
      REMOTE_FINAL_ADDRESS, LOCAL_INPUT_AMOUNT, LOCAL_COLLATERAL_AMOUNT,
      REMOTE_INPUT_AMOUNT, REMOTE_COLLATERAL_AMOUNT, DELAY, LOCAL_INPUTS,
      REMOTE_INPUTS, 1, MATURITY_TIME);
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundingTransactionInput(&fund_tx, LOCAL_INPUT_PRIVKEY,
                                          LOCAL_INPUTS[0].GetTxid(), 0,
                                          LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundingTransactionInput(&fund_tx, REMOTE_INPUT_PRIVKEY,
                                          REMOTE_INPUTS[0].GetTxid(), 0,
                                          REMOTE_INPUT_AMOUNT);
  auto local_fund_signature =
      DlcManager::GetRawFundingTransactionInputSignature(
          fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
          LOCAL_INPUT_AMOUNT);

  bool is_local_fund_signature_valid = DlcManager::VerifyFundTxSignature(
      fund_tx, local_fund_signature, LOCAL_INPUT_PUBKEY,
      LOCAL_INPUTS[0].GetTxid(), 0, LOCAL_INPUT_AMOUNT);

  auto remote_fund_signature =
      DlcManager::GetRawFundingTransactionInputSignature(
          fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
          REMOTE_INPUT_AMOUNT);

  bool is_remote_fund_signature_valid = DlcManager::VerifyFundTxSignature(
      fund_tx, remote_fund_signature, REMOTE_INPUT_PUBKEY,
      REMOTE_INPUTS[0].GetTxid(), 0, REMOTE_INPUT_AMOUNT);

  auto refund_tx = dlc_transactions.refund_transaction;

  auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);

  auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);

  DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_refund_signature, remote_refund_signature}, FUND_TX_ID, 0);

  bool is_local_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
      refund_tx, local_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, false, FUND_TX_ID);

  bool is_remote_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
      refund_tx, remote_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, true, FUND_TX_ID);

  auto cet0 = dlc_transactions.cets[0];
  auto local_cet0_signature = DlcManager::GetRawCetSignature(
      cet0, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_cet0_signature = DlcManager::GetRawCetSignature(
      cet0, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToCet(&cet0, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
                                 {local_cet0_signature, remote_cet0_signature},
                                 FUND_TX_ID, 0);
  bool is_local_cet0_signature_valid = DlcManager::VerifyCetSignature(
      cet0, local_cet0_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID);
  bool is_remote_cet0_signature_valid = DlcManager::VerifyCetSignature(
      cet0, remote_cet0_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0, true);

  EXPECT_EQ(FUND_TX_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_TRUE(is_local_fund_signature_valid);
  EXPECT_TRUE(is_remote_fund_signature_valid);
  EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(is_local_refund_signature_valid);
  EXPECT_TRUE(is_remote_refund_signature_valid);
  EXPECT_EQ(CET_HEX.GetHex(), cet0.GetHex());
  EXPECT_TRUE(is_local_cet0_signature_valid);
  EXPECT_TRUE(is_remote_cet0_signature_valid);
}

TEST(DlcManager, CreateCetTransactionNotEnoughInputTest) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_MESSAGES, WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_MESSAGES, LOSE_AMOUNT, WIN_AMOUNT}};

  // Act/Assert
  ASSERT_THROW(DlcManager::CreateDlcTransactions(
                   outcomes, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PUBKEY,
                   REMOTE_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
                   LOCAL_CHANGE_ADDRESS, REMOTE_CHANGE_ADDRESS,
                   LOCAL_FINAL_ADDRESS, REMOTE_FINAL_ADDRESS,
                   Amount::CreateBySatoshiAmount(1000), LOCAL_COLLATERAL_AMOUNT,
                   REMOTE_INPUT_AMOUNT, REMOTE_COLLATERAL_AMOUNT, DELAY,
                   LOCAL_INPUTS, REMOTE_INPUTS, 1, MATURITY_TIME),
               DlcException);
  ASSERT_THROW(
      DlcManager::CreateDlcTransactions(
          outcomes, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PUBKEY,
          REMOTE_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
          LOCAL_CHANGE_ADDRESS, REMOTE_CHANGE_ADDRESS, LOCAL_FINAL_ADDRESS,
          REMOTE_FINAL_ADDRESS, LOCAL_INPUT_AMOUNT, LOCAL_COLLATERAL_AMOUNT,
          Amount::CreateBySatoshiAmount(1000), REMOTE_COLLATERAL_AMOUNT, DELAY,
          LOCAL_INPUTS, REMOTE_INPUTS, 1, MATURITY_TIME),
      DlcException);
}
