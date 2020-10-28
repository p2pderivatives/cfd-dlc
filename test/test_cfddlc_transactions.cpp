// Copyright 2019 CryptoGarage

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_ecdsa_adaptor.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfddlc/cfddlc_transactions.h"
#include "gtest/gtest.h"
#include "wally_crypto.h"  // NOLINT

using cfd::Amount;
using cfd::core::AdaptorUtil;
using cfd::core::Address;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::CryptoUtil;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::HashUtil;
using cfd::core::NetType;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::SchnorrSignature;
using cfd::core::SchnorrUtil;
using cfd::core::ScriptUtil;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::TxOut;
using cfd::core::WitnessVersion;

using cfd::dlc::DlcManager;
using cfd::dlc::DlcOutcome;
using cfd::dlc::PartyParams;
using cfd::dlc::TxInputInfo;

const std::vector<std::string> WIN_MESSAGES = {"WIN", "MORE"};
const std::vector<std::string> LOSE_MESSAGES = {"LOSE", "LESS"};
const std::vector<ByteData256> WIN_MESSAGES_HASH = {
    HashUtil::Sha256(WIN_MESSAGES[0]), HashUtil::Sha256(WIN_MESSAGES[1])};
const std::vector<ByteData256> LOSE_MESSAGES_HASH = {
    HashUtil::Sha256(LOSE_MESSAGES[0]), HashUtil::Sha256(LOSE_MESSAGES[1])};
const std::vector<std::vector<ByteData256>> MESSAGES_HASH = {
    WIN_MESSAGES_HASH, LOSE_MESSAGES_HASH};
const Privkey ORACLE_PRIVKEY(
    "ded9a76a0a77399e1c2676324118a0386004633f16245ad30d172b15c1f9e2d3");
const SchnorrPubkey ORACLE_PUBKEY = SchnorrPubkey::FromPrivkey(ORACLE_PRIVKEY);
const std::vector<Privkey> ORACLE_K_VALUES = {
    Privkey("be3cc8de25c50e25f69e2f88d151e3f63e99c3a44fed2bdd2e3ee70fe141c5c3"),
    Privkey(
        "9e1bc6dc95ce931903cc2df67640cf6cca94ddd96aab0b847780d644e46cfae3")};
const std::vector<SchnorrPubkey> ORACLE_R_POINTS = {
    SchnorrPubkey::FromPrivkey(ORACLE_K_VALUES[0]),
    SchnorrPubkey::FromPrivkey(ORACLE_K_VALUES[1]),
};
const std::vector<SchnorrSignature> ORACLE_SIGNATURES = {
    SchnorrUtil::SignWithNonce(WIN_MESSAGES_HASH[0], ORACLE_PRIVKEY,
                               ORACLE_K_VALUES[0]),
    SchnorrUtil::SignWithNonce(WIN_MESSAGES_HASH[1], ORACLE_PRIVKEY,
                               ORACLE_K_VALUES[1])};
const Privkey LOCAL_FUND_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000001");
const Pubkey LOCAL_FUND_PUBKEY = LOCAL_FUND_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_FUND_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000002");
const Pubkey REMOTE_FUND_PUBKEY = REMOTE_FUND_PRIVKEY.GeneratePubkey();
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
const Amount FUND_OUTPUT = Amount::CreateBySatoshiAmount(200000170);
const Amount WIN_AMOUNT = Amount::CreateBySatoshiAmount(199900000);
const Amount LOSE_AMOUNT = Amount::CreateBySatoshiAmount(100000);
const std::vector<TxInputInfo> LOCAL_INPUTS_INFO = {TxInputInfo{
    TxIn(
        Txid(
            "83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"),
        0, 0),
    108}};
const std::vector<TxInputInfo> REMOTE_INPUTS_INFO = {TxInputInfo{
    TxIn(
        Txid(
            "bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"),
        0, 0),
    108}};
const std::vector<TxIn> LOCAL_INPUTS = {TxIn(
    Txid("83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"), 0,
    0)};
const std::vector<TxIn> REMOTE_INPUTS = {
    TxIn(
        Txid(
            "bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"),
        0, 0),
};
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

const PartyParams LOCAL_PARAMS = {LOCAL_FUND_PUBKEY,
                                  LOCAL_CHANGE_ADDRESS.GetLockingScript(),
                                  LOCAL_FINAL_ADDRESS.GetLockingScript(),
                                  LOCAL_INPUTS_INFO,
                                  LOCAL_INPUT_AMOUNT,
                                  LOCAL_COLLATERAL_AMOUNT};

const PartyParams REMOTE_PARAMS = {REMOTE_FUND_PUBKEY,
                                   REMOTE_CHANGE_ADDRESS.GetLockingScript(),
                                   REMOTE_FINAL_ADDRESS.GetLockingScript(),
                                   REMOTE_INPUTS_INFO,
                                   REMOTE_INPUT_AMOUNT,
                                   REMOTE_COLLATERAL_AMOUNT};
const ByteData FUND_TX_HEX(
    "020000000001024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b6d"
    "26830000000000ffffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523"
    "ef072fa292bc0000000000ffffffff03aac2eb0b000000002200209b984c7bae3efddc3a3f"
    "0a20ff81bfe89ed1fe07ff13e562149ee654bed845db2d10102401000000160014fa3629f3"
    "060b6c1a5a365c30bf66fa00f155cb9e2d1010240100000016001465d4d622585baf5151de"
    "860b1e7af58710f20da20247304402206d7181ec4d126c5e6bbf5ae65ee0297610f4f0d28a"
    "03ba6d782e651b136a6bd502200458622a92e2df148f90df85a2ebc402dd3aef43a10821c1"
    "6e8739426ba808a00121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8"
    "d569b240efe402473044022007e59c38bc05ac886b52f29147af2dd9f5a2f15188b02c0fc7"
    "7c2c42aa81bb7b022079da7f996b92ad4c5323c3e403c36dca967c7a3787cf7ac32b419f07"
    "5cbfdd1d012103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a146029"
    "755600000000");
const ByteData FUND_TX_WITH_PREMIUM_HEX(
    "02000000024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b6d2683"
    "0000000000ffffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523ef07"
    "2fa292bc0000000000ffffffff04aac2eb0b000000002200209b984c7bae3efddc3a3f0a20"
    "ff81bfe89ed1fe07ff13e562149ee654bed845db6e890e2401000000160014fa3629f3060b"
    "6c1a5a365c30bf66fa00f155cb9e2d1010240100000016001465d4d622585baf5151de860b"
    "1e7af58710f20da2a0860100000000001600143104041af39ddcb0976f9ab6522001f096af"
    "e2ce00000000");
const Txid FUND_TX_ID(
    "c371cfe829d31c1d18f6f638047d44e5e2617d659ebdd43b83b04da32e864692");

const ByteData CET_HEX(
    "02000000019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf71c3"
    "0000000000ffffffff02603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333c472"
    "fd0b3f69a0860100000000001600149652d86bedf43ad264362e6e6eba6eb7645081270000"
    "0000");

const ByteData CET_HEX_SIGNED(
    "020000000001019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf"
    "71c30000000000ffffffff02603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333"
    "c472fd0b3f69a0860100000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
    "0400473044022006560a7c24ce8688620cb1002b822c187858fba43607b286f09b9c02443b"
    "98f002207f8b1b6b120c0f4717f9f8c2cb739a400f94987dd48577ac4c4624c1477b969801"
    "473044022036d971f3da54303facb5fbf8dc7e9eef452cd94723eb6dc52f7aeee454791a00"
    "02204cf335114c47bae5e6dc2e00f566d1e37ec6fe25350fe797d48bff2573eeb548014752"
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
    "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae0000000"
    "0");

uint32_t REFUND_LOCKTIME = 100;

const ByteData REFUND_HEX(
    "020000000001019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf"
    "71c30000000000feffffff0200e1f505000000001600145dedfbf9ea599dd4e3ca6a80b333"
    "c472fd0b3f6900e1f505000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
    "040047304402204d7d24af8714835eead1143e5f589675c9e3b68d911ed5cbaaaa207586da"
    "c8e7022059a1febe7e12864a9ac59167510ffddfeed0f75920f611263e90b2068df52dbe01"
    "4730440220325b227c84d65a29d6f932f149af7fd6849237bc9d5dec09771d68f75dacb85e"
    "02202b8b0074f0804850ae4bdca21d139681d971117a669aae3385fb72acaa2feaee014752"
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
    "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae6400000"
    "0");

const Address PREMIUM_DEST("bcrt1qxyzqgxhnnhwtp9m0n2m9ygqp7zt2lckwvxx4jq");
const Amount OPTION_PREMIUM = Amount::CreateBySatoshiAmount(100000);

TEST(DlcManager, FundTransactionTest) {
  // Arrange
  auto change = Amount::CreateBySatoshiAmount(4899999789);
  TxOut local_change_output = TxOut(change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(change, REMOTE_CHANGE_ADDRESS);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
      LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS,
      local_change_output, REMOTE_INPUTS, remote_change_output);
  auto fund_tx2 = DlcManager::CreateFundTransaction(
      LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS,
      local_change_output, REMOTE_INPUTS, remote_change_output);
  auto local_utxo_txid = LOCAL_INPUTS[0].GetTxid();
  auto local_utxo_vout = LOCAL_INPUTS[0].GetVout();
  auto remote_utxo_txid = REMOTE_INPUTS[0].GetTxid();
  auto remote_utxo_vout = REMOTE_INPUTS[0].GetVout();
  DlcManager::SignFundTransactionInput(&fund_tx, LOCAL_INPUT_PRIVKEY,
                                       local_utxo_txid, local_utxo_vout,
                                       LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(&fund_tx, REMOTE_INPUT_PRIVKEY,
                                       remote_utxo_txid, remote_utxo_vout,
                                       REMOTE_INPUT_AMOUNT);
  auto local_signature = DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, LOCAL_INPUT_PRIVKEY, local_utxo_txid, local_utxo_vout,
      LOCAL_INPUT_AMOUNT);
  auto remote_signature = DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, REMOTE_INPUT_PRIVKEY, remote_utxo_txid, remote_utxo_vout,
      REMOTE_INPUT_AMOUNT);
  DlcManager::AddSignatureToFundTransaction(
      &fund_tx2, local_signature, LOCAL_INPUT_PUBKEY, LOCAL_INPUTS[0].GetTxid(),
      LOCAL_INPUTS[0].GetVout());
  DlcManager::AddSignatureToFundTransaction(
      &fund_tx2, remote_signature, REMOTE_INPUT_PUBKEY,
      REMOTE_INPUTS[0].GetTxid(), REMOTE_INPUTS[0].GetVout());

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
  EXPECT_EQ(fund_tx.GetHex(), fund_tx2.GetHex());
}

TEST(DlcManager, CetTest) {
  // Arrange
  auto local_payout = Amount::CreateBySatoshiAmount(199900000);
  auto remote_payout = Amount::CreateBySatoshiAmount(100000);
  TxOut local_output(local_payout, LOCAL_FINAL_ADDRESS);
  TxOut remote_output(remote_payout, REMOTE_FINAL_ADDRESS);
  // Act
  auto cet =
      DlcManager::CreateCet(local_output, remote_output, FUND_TX_ID, 0, 0);

  auto fund_script = DlcManager::CreateFundTxLockingScript(LOCAL_FUND_PUBKEY,
                                                           REMOTE_FUND_PUBKEY);
  auto local_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
      cet, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
      FUND_OUTPUT, {WIN_MESSAGES_HASH[0]});
  auto remote_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
      cet, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, REMOTE_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]});

  // Assert
  EXPECT_EQ(FUND_TX_ID.GetHex(),
            cet.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  EXPECT_EQ(0, cet.GetTransaction().GetTxIn(0).GetVout());
  EXPECT_EQ(local_payout, cet.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_TRUE(
      cet.GetTransaction().GetTxOut(0).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(remote_payout, cet.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_TRUE(
      cet.GetTransaction().GetTxOut(1).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(CET_HEX.GetHex(), cet.GetHex());
  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
      local_adaptor_pair, cet, LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]}));
  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
      remote_adaptor_pair, cet, REMOTE_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]}));

  DlcManager::SignCet(&cet, local_adaptor_pair.signature,
                      {ORACLE_SIGNATURES[0]}, REMOTE_FUND_PRIVKEY, fund_script,
                      FUND_TX_ID, 0, FUND_OUTPUT);
  EXPECT_EQ(cet.GetHex(), CET_HEX_SIGNED.GetHex());
}

TEST(DlcManager, RefundTransactionTest) {
  // Arrange
  // Act
  auto refund_tx = DlcManager::CreateRefundTransaction(
      LOCAL_FINAL_ADDRESS.GetLockingScript(),
      REMOTE_FINAL_ADDRESS.GetLockingScript(),
      Amount::CreateBySatoshiAmount(100000000),
      Amount::CreateBySatoshiAmount(100000000), 100, FUND_TX_ID, 0);

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

TEST(DlcManager, CreateDlcTransactions) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1);
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundTransactionInput(&fund_tx, LOCAL_INPUT_PRIVKEY,
                                       LOCAL_INPUTS[0].GetTxid(), 0,
                                       LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(&fund_tx, REMOTE_INPUT_PRIVKEY,
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

  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();

  auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, fund_tx_id, 0);

  auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, fund_tx_id, 0);

  DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_refund_signature, remote_refund_signature}, fund_tx_id, 0);

  bool is_local_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
      refund_tx, local_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, false, fund_tx_id);

  bool is_remote_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
      refund_tx, remote_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, true, fund_tx_id);

  auto cets = dlc_transactions.cets;
  auto nb_cet = cets.size();

  auto fund_script = DlcManager::CreateFundTxLockingScript(LOCAL_FUND_PUBKEY,
                                                           REMOTE_FUND_PUBKEY);

  bool all_valid_cet_signatures = true;
  for (size_t i = 0; i < nb_cet; i++) {
    auto local_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
        cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
        fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
        local_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
        {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    auto remote_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
        cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
        fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
        remote_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
        {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
  }

  auto local_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  bool all_valid_cet_pair_batch = DlcManager::VerifyCetAdaptorSignatures(
      cets, local_cet_adaptor_pairs,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
      ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);
  auto remote_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  all_valid_cet_pair_batch &= DlcManager::VerifyCetAdaptorSignatures(
      cets, remote_cet_adaptor_pairs,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
      ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);

  EXPECT_EQ(dlc_transactions.cets.size(), outcomes.size());
  EXPECT_EQ(FUND_TX_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_TRUE(is_local_fund_signature_valid);
  EXPECT_TRUE(is_remote_fund_signature_valid);
  EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(is_local_refund_signature_valid);
  EXPECT_TRUE(is_remote_refund_signature_valid);
  EXPECT_TRUE(all_valid_cet_signatures);
  EXPECT_TRUE(all_valid_cet_pair_batch);
}

TEST(DlcManager, CreateCetTransactionNotEnoughInputTest) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_AMOUNT, WIN_AMOUNT}};

  auto local_params_short = LOCAL_PARAMS;
  local_params_short.input_amount = Amount::CreateBySatoshiAmount(1000);
  auto remote_params_short = LOCAL_PARAMS;
  remote_params_short.input_amount = Amount::CreateBySatoshiAmount(1000);
  // Act/Assert
  ASSERT_THROW(
      auto dlc_transactions = DlcManager::CreateDlcTransactions(
          outcomes, local_params_short, REMOTE_PARAMS, REFUND_LOCKTIME, 1),
      CfdException);
  ASSERT_THROW(
      auto dlc_transactions = DlcManager::CreateDlcTransactions(
          outcomes, remote_params_short, REMOTE_PARAMS, REFUND_LOCKTIME, 1),
      CfdException);
}

TEST(DlcManager, FundTransactionWithPremiumTest) {
  // Arrange
  auto local_change = Amount::CreateBySatoshiAmount(4899899758);
  auto remote_change = Amount::CreateBySatoshiAmount(4899999789);
  TxOut local_change_output = TxOut(local_change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(remote_change, REMOTE_CHANGE_ADDRESS);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
      LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS,
      local_change_output, REMOTE_INPUTS, remote_change_output, PREMIUM_DEST,
      OPTION_PREMIUM);

  EXPECT_EQ(FUND_TX_WITH_PREMIUM_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_EQ(FUND_OUTPUT, fund_tx.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_EQ(local_change, fund_tx.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_EQ(remote_change, fund_tx.GetTransaction().GetTxOut(2).GetValue());
  EXPECT_EQ(OPTION_PREMIUM,
            fund_tx.GetTransaction().GetTxOut(3).GetValue().GetSatoshiValue());
}

TEST(DlcManager, CreateDlcTransactionsWithPremium) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
      OPTION_PREMIUM);
  auto fund_tx = dlc_transactions.fund_transaction;

  // Assert
  EXPECT_EQ(FUND_TX_WITH_PREMIUM_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_EQ(4, fund_tx.GetTransaction().GetTxOutCount());
  EXPECT_GT((LOCAL_INPUT_AMOUNT - LOCAL_COLLATERAL_AMOUNT - OPTION_PREMIUM)
                .GetSatoshiValue(),
            fund_tx.GetTransaction().GetTxOut(1).GetValue().GetSatoshiValue());
  EXPECT_EQ(OPTION_PREMIUM.GetSatoshiValue(),
            fund_tx.GetTransaction().GetTxOut(3).GetValue().GetSatoshiValue());
}

TEST(DlcManager, CreateDlcTransactionsWithPremiumEmptyDestAddressFails) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act/Assert
  EXPECT_THROW(DlcManager::CreateDlcTransactions(outcomes, LOCAL_PARAMS,
                                                 REMOTE_PARAMS, REFUND_LOCKTIME,
                                                 1, Address(), OPTION_PREMIUM),
               CfdException);
}

TEST(DlcManager, AdaptorSigTest) {
  std::vector<DlcOutcome> payouts = {{WIN_AMOUNT, LOSE_AMOUNT},
                                     {LOSE_AMOUNT, WIN_AMOUNT}};
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      payouts, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
      OPTION_PREMIUM);
  auto fund_transaction = dlc_transactions.fund_transaction;
  auto cets = dlc_transactions.cets;
  auto cet0 = cets[0];
  auto lock_script = DlcManager::CreateFundTxLockingScript(LOCAL_FUND_PUBKEY,
                                                           REMOTE_FUND_PUBKEY);

  auto fund_amount = fund_transaction.GetTransaction().GetTxOut(0).GetValue();
  auto fund_txid = fund_transaction.GetTransaction().GetTxid();

  auto adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      lock_script, fund_amount,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
      adaptor_pairs[1], cets[1], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, lock_script, fund_amount, {LOSE_MESSAGES_HASH[0]}));

  auto adapted_sig = AdaptorUtil::Adapt(adaptor_pairs[0].signature,
                                        ORACLE_SIGNATURES[0].GetPrivkey());

  auto is_valid = cet0.VerifyInputSignature(
      adapted_sig, LOCAL_FUND_PUBKEY, fund_txid, 0, lock_script, SigHashType(),
      fund_amount, WitnessVersion::kVersion0);
  EXPECT_TRUE(is_valid);
}

TEST(DlcManager, AdaptorSigMultipleNonces) {
  std::vector<DlcOutcome> outcomes = {{WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_AMOUNT, WIN_AMOUNT}};
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
      OPTION_PREMIUM);
  auto fund_transaction = dlc_transactions.fund_transaction;
  auto cets = dlc_transactions.cets;
  auto cet0 = cets[0];
  auto lock_script = DlcManager::CreateFundTxLockingScript(LOCAL_FUND_PUBKEY,
                                                           REMOTE_FUND_PUBKEY);

  auto fund_amount = fund_transaction.GetTransaction().GetTxOut(0).GetValue();
  auto fund_txid = fund_transaction.GetTransaction().GetTxid();

  auto adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PRIVKEY, lock_script,
      fund_amount, {WIN_MESSAGES_HASH, LOSE_MESSAGES_HASH});

  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
      adaptor_pairs[1], cets[1], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      ORACLE_R_POINTS, lock_script, fund_amount, LOSE_MESSAGES_HASH));

  auto adaptor_secret = ORACLE_SIGNATURES[0].GetPrivkey();
  adaptor_secret = adaptor_secret.CreateTweakAdd(
      ByteData256(ORACLE_SIGNATURES[1].GetPrivkey().GetData()));
  auto adapted_sig =
      AdaptorUtil::Adapt(adaptor_pairs[0].signature, adaptor_secret);

  auto is_valid = cet0.VerifyInputSignature(
      adapted_sig, LOCAL_FUND_PUBKEY, fund_txid, 0, lock_script, SigHashType(),
      fund_amount, WitnessVersion::kVersion0);
  EXPECT_TRUE(is_valid);
}
