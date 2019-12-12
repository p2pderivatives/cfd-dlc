// Copyright 2019 CryptoGarage

#include "gtest/gtest.h"

#include "cfdcore/cfdcore_amount.h"

#include "cfd/cfd_transaction.h"

#include "dlc/dlc_transactions.h"
#include "dlc/dlc_util.h"
#include "wally_crypto.h"  // NOLINT

using cfd::Amount;
using cfd::core::Address;
using cfd::core::ByteData;
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

using cfd::dlc::DlcManager;
using cfd::dlc::DlcOutcome;
using cfd::dlc::DlcUtil;

const Privkey ORACLE_PRIVKEY(
    "ded9a76a0a77399e1c2676324118a0386004633f16245ad30d172b15c1f9e2d3");
const Pubkey ORACLE_PUBKEY = ORACLE_PRIVKEY.GeneratePubkey();
const Privkey ORACLE_K_VALUE(
    "be3cc8de25c50e25f69e2f88d151e3f63e99c3a44fed2bdd2e3ee70fe141c5c3");
const std::vector<Pubkey> ORACLE_R_POINTS = {ORACLE_K_VALUE.GeneratePubkey()};
const ByteData ORACLE_SIGNATURE(
    "575ec7dfcd3a2390fc30fb60c18406968521e6522ebcae0c2f33a3420a91959b");
const ExtPrivkey LOCAL_EXT_PRIVKEY(
    "tprv8ZgxMBicQKsPei29DBNcLvgRKSWAMAKp54HPLys4ddLxGkiCUz6Buw5KW4B1RE2mV1qH"
    "vuKwXXJXGf3DNmyZ2uAkBSfUXxDmuMoUptAuicq");
const ExtPubkey LOCAL_EXT_PUBKEY = LOCAL_EXT_PRIVKEY.GetExtPubkey();
const ExtPrivkey REMOTE_EXT_PRIVKEY(
    "tprv8ZgxMBicQKsPeJyDu6aa46FFkCgcMe3EjaudpzBkAjaSsDzeBuHpqZwv2Md9ExBQTZQD"
    "u1B2FdX9LYVTjGrrZ534gMan5zh9d7gsKPnWLL4");
const ExtPubkey REMOTE_EXT_PUBKEY = REMOTE_EXT_PRIVKEY.GetExtPubkey();
const ExtPrivkey LOCAL_INPUT_PRIVKEY = LOCAL_EXT_PRIVKEY.DerivePrivkey(10);
const ExtPrivkey REMOTE_INPUT_PRIVKEY = REMOTE_EXT_PRIVKEY.DerivePrivkey(10);
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
const uint32_t MATURITY_TIME = 1579072156;
const ByteData FUND_TX_HEX(
    "020000000001024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b"
    "6d26830000000000feffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33a"
    "c523ef072fa292bc0000000000feffffff0338c3eb0b0000000022002080973eb7a96314"
    "20d0c7911af62b84956993c1a63c7c378fd98bfb1a4ac30411960f102401000000160014"
    "fa3629f3060b6c1a5a365c30bf66fa00f155cb9e960f10240100000016001465d4d62258"
    "5baf5151de860b1e7af58710f20da20247304402203a3ff745186124f2fa0bda856d3859"
    "dabb3069c8b798e98b9c4e73905fa263720220652a6fa88505a7618d22c45f547927e824"
    "79947cbe36b0ad608ad20312c8e8f0012103454f8dd592f5e0ffc85261f0c6b67976141c"
    "2ed26ecb80aa0cfa1d47b2becfff0247304402205716ba33ccd65ed72f87106f7a1e6705"
    "b21658c9a441dc8d9f8a2e3350f9c372022023f4fcb8cb8c1af1c11d8bac62f47d1891d9"
    "c122bfda40ea595e0d29eb6695d2012102654b96976211c56352b1061adb823f49932fbb"
    "ff1917ec032114f24d60280b0164000000");
const Txid FUND_TX_ID(
    "22ffd89f1739ed6c7cb71007a6c3019e675416d44506ed923c98938de87a8649");

const ByteData CET_HEX(
    "0200000000010149867ae88d93983c92ed0645d41654679e01c3a60710b77c6ced39179fd8"
    "ff220000000000feffffff02da3bea0b00000000220020b1fc17fc23e5a14f053e4954881f"
    "111cc6ecb3cc768279a5de1705e66db95180a086010000000000160014d0188dab2ea2071b"
    "cb3b09aca1b987320266a7660400473044022057de12a30e021602a8f02cb01608704e4ad2"
    "267d697b4189c5bba5a91a8b90f202205c528c8176832086486cf452527f47cd6b5c2290f2"
    "fb2c1151da6aebaa8d89c801473044022035a309c0d9df37289936a720872cbfe98090d3a4"
    "7aa8412f2b0523ab1d59e81d022031cc144a3345df5b5489c780bf18470fbfa598a5826b76"
    "641c6f0dcef0a1e40a01475221038f3757e078a9a9752ec76a3e25d143f39ea992e880bb62"
    "8ae5c93e890d08a229210266a3b6ee97e4119996920cb44dd5a6e8fa52a0d1bcbd73cf8ac6"
    "809cf494979f52ae9cba1e5e");
const Txid CET_ID(
    "b76358e12874e7448a479ffcb178f9775ece2d83262ac2c17c381e5777b65cd6");
const ByteData CLOSING_HEX(
    "02000000000101d65cb677571e387cc1c22a26832dce5e77f978b1fc9f478a44e77428e158"
    "63b70000000000ffffffff017837ea0b00000000160014beef5ee9db2684d098c057db222f"
    "a035f337f17d034730440220403129143a6b03ea7b8336bf2e38f0843bcd1816a6e35c712e"
    "2610e908fe51f502203956c312777076506e622393c3a0e5bdee4e23b338b4cbf073a879df"
    "d56850f80101014c6321036b93d7c303328552dd1c3abb9de0819f21d3bd20b37928920d7c"
    "93766b54805d670164b27521037cb71589aab115577976c1dbfa085f84b133c2083cbe9d49"
    "02e8f12a7583cbb668ac00000000");
uint32_t DELAY = 100;

const ByteData REFUND_HEX(
    "0200000000010149867ae88d93983c92ed0645d41654679e01c3a60710b77c6ced39179fd8"
    "ff220000000000feffffff0248e1f50500000000160014902295f77909b9db97bfe1a8a56c"
    "7c43acd8ac3848e1f50500000000160014eb903815f985bbcd5dbcda2723e1de6b5ec7c878"
    "040047304402206f04af8e35f3f6bb4e0e92976998d6e928b5bdc12eb13dd48639dcbbd0b1"
    "929a0220020646c5b43f1032d72d5efa2aaf6955f965247d70e22fd41c64e51070bca62c01"
    "4730440220185a33e0ded50865c18b4839e39183651b972115b1b440db17a4f395da796577"
    "02206a6afe3643b69d98fd46f7aa4d64aca57d8c2f07e0fe14be9f1151c8b6939dee014752"
    "21038f3757e078a9a9752ec76a3e25d143f39ea992e880bb628ae5c93e890d08a229210266"
    "a3b6ee97e4119996920cb44dd5a6e8fa52a0d1bcbd73cf8ac6809cf494979f52ae6400000"
    "0");

TEST(DlcManager, FundTransactionTest) {
  // Arrange
  auto change = Amount::CreateBySatoshiAmount(4899999638);
  TxOut local_change_output = TxOut(change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(change, REMOTE_CHANGE_ADDRESS);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
      LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS,
      local_change_output, REMOTE_INPUTS, remote_change_output, 100);
  auto local_utxo_txid = LOCAL_INPUTS[0].GetTxid();
  auto local_utxo_vout = LOCAL_INPUTS[0].GetVout();
  auto remote_utxo_txid = REMOTE_INPUTS[0].GetTxid();
  auto remote_utxo_vout = REMOTE_INPUTS[0].GetVout();
  DlcManager::SignFundingTransactionInput(
      &fund_tx, LOCAL_INPUT_PRIVKEY.GetPrivkey(), local_utxo_txid,
      local_utxo_vout, LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundingTransactionInput(
      &fund_tx, REMOTE_INPUT_PRIVKEY.GetPrivkey(), remote_utxo_txid,
      remote_utxo_vout, REMOTE_INPUT_AMOUNT);
  auto local_signature = DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, LOCAL_INPUT_PRIVKEY.GetPrivkey(), local_utxo_txid,
      local_utxo_vout, LOCAL_INPUT_AMOUNT);
  auto remote_signature = DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, REMOTE_INPUT_PRIVKEY.GetPrivkey(), remote_utxo_txid,
      remote_utxo_vout, REMOTE_INPUT_AMOUNT);

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
      fund_tx, local_signature,
      LOCAL_INPUT_PRIVKEY.GetPrivkey().GeneratePubkey(), local_utxo_txid,
      local_utxo_vout, LOCAL_INPUT_AMOUNT));
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
      fund_tx, remote_signature,
      REMOTE_INPUT_PRIVKEY.GetPrivkey().GeneratePubkey(), remote_utxo_txid,
      remote_utxo_vout, REMOTE_INPUT_AMOUNT));
}

TEST(DlcManager, CetTest) {
  // Arrange
  auto local_payout = Amount::CreateBySatoshiAmount(199900000);
  auto closing_fee = Amount::CreateBySatoshiAmount(122);
  auto remote_payout = Amount::CreateBySatoshiAmount(100000);
  // Act
  auto cet = DlcManager::CreateCet(
      LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY, 1, ORACLE_PUBKEY, ORACLE_R_POINTS,
      WIN_MESSAGES, DELAY, local_payout, closing_fee, remote_payout, FUND_TX_ID,
      0, MATURITY_TIME, NetType::kRegtest);
  auto local_signature = DlcManager::GetRawCetSignature(
      cet, LOCAL_EXT_PRIVKEY, FUND_TX_ID, 0, LOCAL_EXT_PUBKEY,
      REMOTE_EXT_PUBKEY, FUND_OUTPUT);
  auto remote_signature = DlcManager::GetRawCetSignature(
      cet, REMOTE_EXT_PRIVKEY, FUND_TX_ID, 0, LOCAL_EXT_PUBKEY,
      REMOTE_EXT_PUBKEY, FUND_OUTPUT);
  DlcManager::AddSignaturesToCet(&cet, FUND_TX_ID, 0, LOCAL_EXT_PUBKEY,
                                 REMOTE_EXT_PUBKEY,
                                 {local_signature, remote_signature});

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
      cet, local_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY, FUND_TX_ID, 0,
      FUND_OUTPUT, false));
  EXPECT_TRUE(DlcManager::VerifyCetSignature(
      cet, remote_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY, FUND_TX_ID, 0,
      FUND_OUTPUT, true));
}

TEST(DlcManager, RefundTransactionTest) {
  // Arrange
  // Act
  auto refund_tx = DlcManager::CreateRefundTransaction(
      LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      Amount::CreateBySatoshiAmount(100000072),
      Amount::CreateBySatoshiAmount(100000072), 100, FUND_TX_ID, 0,
      NetType::kRegtest);
  auto local_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_EXT_PRIVKEY, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT);
  auto remote_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_EXT_PRIVKEY, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT);
  DlcManager::AddSignaturesToRefundTx(&refund_tx, LOCAL_EXT_PUBKEY,
                                      REMOTE_EXT_PUBKEY, FUND_TX_ID, 0,
                                      {local_signature, remote_signature});

  // Assert
  EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(DlcManager::VerifyRefundTxSignature(
      refund_tx, local_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, false));
  EXPECT_TRUE(DlcManager::VerifyRefundTxSignature(
      refund_tx, remote_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, true));
}

TEST(DlcManager, ClosingTransactionTest) {
  // Arrange
  auto input_amount = Amount::CreateBySatoshiAmount(199900122);
  auto output_amount = Amount::CreateBySatoshiAmount(199899000);
  // Act
  auto closing_tx = DlcManager::CreateClosingTransaction(
      LOCAL_EXT_PUBKEY, output_amount, CET_ID, 0, 0, NetType::kRegtest);
  DlcManager::SignClosingTransactionInput(
      &closing_tx, LOCAL_EXT_PRIVKEY, REMOTE_EXT_PUBKEY, 1, ORACLE_PUBKEY,
      ORACLE_R_POINTS, WIN_MESSAGES, DELAY, ORACLE_SIGNATURE, CET_ID, 0,
      input_amount);

  auto local_closing_signature = DlcManager::GetRawClosingTransactionSignature(
      closing_tx, LOCAL_EXT_PRIVKEY, REMOTE_EXT_PUBKEY, 1, ORACLE_PUBKEY,
      ORACLE_R_POINTS, WIN_MESSAGES, DELAY, ORACLE_SIGNATURE, CET_ID, 0,
      input_amount);
  auto oracle_message_key =
      DlcUtil::GetCommittedKey(ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES);
  bool is_signature_valid = closing_tx.VerifyInputSignature(
      local_closing_signature,
      Pubkey::CombinePubkey(DlcManager::DeriveCetPubkey(LOCAL_EXT_PUBKEY, 1, 0),
                            oracle_message_key),
      CET_ID, 0,
      DlcManager::CreateCetRedeemScript(LOCAL_EXT_PUBKEY, 1, ORACLE_PUBKEY,
                                        ORACLE_R_POINTS, WIN_MESSAGES, DELAY,
                                        REMOTE_EXT_PUBKEY),
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
      REMOTE_EXT_PUBKEY, output_amount, CET_ID, 0, 0, NetType::kRegtest);
  DlcManager::SignClosingTransactionInput(
      &penalty_tx, LOCAL_EXT_PRIVKEY, REMOTE_EXT_PUBKEY, 1, ORACLE_PUBKEY,
      ORACLE_R_POINTS, WIN_MESSAGES, DELAY, ORACLE_SIGNATURE, CET_ID, 0,
      input_amount);

  auto local_closing_signature = DlcManager::GetRawClosingTransactionSignature(
      penalty_tx, LOCAL_EXT_PRIVKEY, REMOTE_EXT_PUBKEY, 1, ORACLE_PUBKEY,
      ORACLE_R_POINTS, WIN_MESSAGES, DELAY, ORACLE_SIGNATURE, CET_ID, 0,
      input_amount);
  auto oracle_message_key =
      DlcUtil::GetCommittedKey(ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES);
  bool is_signature_valid = penalty_tx.VerifyInputSignature(
      local_closing_signature,
      Pubkey::CombinePubkey(DlcManager::DeriveCetPubkey(LOCAL_EXT_PUBKEY, 1, 0),
                            oracle_message_key),
      CET_ID, 0,
      DlcManager::CreateCetRedeemScript(LOCAL_EXT_PUBKEY, 1, ORACLE_PUBKEY,
                                        ORACLE_R_POINTS, WIN_MESSAGES, DELAY,
                                        REMOTE_EXT_PUBKEY),
      SigHashType(), input_amount, WitnessVersion::kVersion0);
  // Assert
  ASSERT_EQ(output_amount, penalty_tx.GetTransaction().GetTxOut(0).GetValue());
  ASSERT_EQ(CET_ID.GetHex(),
            penalty_tx.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  ASSERT_EQ(0, penalty_tx.GetTransaction().GetTxIn(0).GetVout());
  //   ASSERT_EQ(CLOSING_HEX.GetHex(), penalty_tx.GetHex());
  ASSERT_TRUE(is_signature_valid);
}

TEST(DlcManager, MutualClosingTransactionTest) {
  // Arrange
  // Act
  auto mutual_closing_tx = DlcManager::CreateMutualClosingTransaction(
      LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      Amount::CreateBySatoshiAmount(100000072),
      Amount::CreateBySatoshiAmount(100000072), FUND_TX_ID, 0,
      NetType::kRegtest, 0);
  auto local_signature = DlcManager::GetRawMutualClosingTxSignature(
      mutual_closing_tx, LOCAL_EXT_PRIVKEY, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT);
  auto remote_signature = DlcManager::GetRawMutualClosingTxSignature(
      mutual_closing_tx, REMOTE_EXT_PRIVKEY, LOCAL_EXT_PUBKEY,
      REMOTE_EXT_PUBKEY, FUND_TX_ID, 0, FUND_OUTPUT);
  DlcManager::AddSignaturesToMutualClosingTx(
      &mutual_closing_tx, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY, FUND_TX_ID, 0,
      {local_signature, remote_signature});

  // Assert
  //   EXPECT_EQ(REFUND_HEX.GetHex(), mutual_closing_tx.GetHex());
  EXPECT_TRUE(DlcManager::VerifyMutualClosingTxSignature(
      mutual_closing_tx, local_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, false));
  EXPECT_TRUE(DlcManager::VerifyMutualClosingTxSignature(
      mutual_closing_tx, remote_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, true));
}

TEST(DlcManager, CreateDlcTransactions) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {{WIN_MESSAGES, WIN_AMOUNT, LOSE_AMOUNT},
                                      {LOSE_MESSAGES, LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_EXT_PUBKEY,
      REMOTE_EXT_PUBKEY, LOCAL_INPUT_AMOUNT, LOCAL_COLLATERAL_AMOUNT,
      REMOTE_INPUT_AMOUNT, REMOTE_COLLATERAL_AMOUNT, DELAY, LOCAL_INPUTS,
      LOCAL_CHANGE_ADDRESS, REMOTE_INPUTS, REMOTE_CHANGE_ADDRESS, 1,
      MATURITY_TIME, 100, NetType::kRegtest);
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundingTransactionInput(
      &fund_tx, LOCAL_INPUT_PRIVKEY.GetPrivkey(), LOCAL_INPUTS[0].GetTxid(), 0,
      LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundingTransactionInput(
      &fund_tx, REMOTE_INPUT_PRIVKEY.GetPrivkey(), REMOTE_INPUTS[0].GetTxid(),
      0, REMOTE_INPUT_AMOUNT);
  auto local_fund_signature =
      DlcManager::GetRawFundingTransactionInputSignature(
          fund_tx, LOCAL_INPUT_PRIVKEY.GetPrivkey(), LOCAL_INPUTS[0].GetTxid(),
          0, LOCAL_INPUT_AMOUNT);

  bool is_local_fund_signature_valid = DlcManager::VerifyFundTxSignature(
      fund_tx, local_fund_signature,
      LOCAL_INPUT_PRIVKEY.GetPrivkey().GeneratePubkey(),
      LOCAL_INPUTS[0].GetTxid(), 0, LOCAL_INPUT_AMOUNT);

  auto remote_fund_signature =
      DlcManager::GetRawFundingTransactionInputSignature(
          fund_tx, REMOTE_INPUT_PRIVKEY.GetPrivkey(),
          REMOTE_INPUTS[0].GetTxid(), 0, REMOTE_INPUT_AMOUNT);

  bool is_remote_fund_signature_valid = DlcManager::VerifyFundTxSignature(
      fund_tx, remote_fund_signature,
      REMOTE_INPUT_PRIVKEY.GetPrivkey().GeneratePubkey(),
      REMOTE_INPUTS[0].GetTxid(), 0, REMOTE_INPUT_AMOUNT);

  auto refund_tx = dlc_transactions.refund_transaction;

  auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_EXT_PRIVKEY, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT);

  auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_EXT_PRIVKEY, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT);
  DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY, FUND_TX_ID, 0,
      {local_refund_signature, remote_refund_signature});

  bool is_local_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
      refund_tx, local_refund_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, false);

  bool is_remote_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
      refund_tx, remote_refund_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, true);

  auto cet0 = dlc_transactions.cets[0];
  auto local_cet0_signature = DlcManager::GetRawCetSignature(
      cet0, LOCAL_EXT_PRIVKEY, FUND_TX_ID, 0, LOCAL_EXT_PUBKEY,
      REMOTE_EXT_PUBKEY, FUND_OUTPUT);
  auto remote_cet0_signature = DlcManager::GetRawCetSignature(
      cet0, REMOTE_EXT_PRIVKEY, FUND_TX_ID, 0, LOCAL_EXT_PUBKEY,
      REMOTE_EXT_PUBKEY, FUND_OUTPUT);
  DlcManager::AddSignaturesToCet(&cet0, FUND_TX_ID, 0, LOCAL_EXT_PUBKEY,
                                 REMOTE_EXT_PUBKEY,
                                 {local_cet0_signature, remote_cet0_signature});
  bool is_local_cet0_signature_valid = DlcManager::VerifyCetSignature(
      cet0, local_cet0_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, false);
  bool is_remote_cet0_signature_valid = DlcManager::VerifyCetSignature(
      cet0, remote_cet0_signature, LOCAL_EXT_PUBKEY, REMOTE_EXT_PUBKEY,
      FUND_TX_ID, 0, FUND_OUTPUT, true);

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
