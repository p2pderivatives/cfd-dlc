// Copyright 2019 CryptoGarage

#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfddlc/cfddlc_util.h"
#include "gtest/gtest.h"

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::CryptoUtil;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SigHashType;
using cfd::core::SignatureUtil;

using cfd::dlc::DlcUtil;

TEST(DlcUtil, SchnorrSign) {
  // Arrange
  ByteData256 data(
      "0000000000000000000000000000000000000000000000000000000000000000");
  std::string str_data("test");
  Privkey privkey(
      "0000000000000000000000000000000000000000000000000000000000000001");
  Pubkey pubkey(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  Privkey nonce(
      "0000000000000000000000000000000000000000000000000000000000000002");
  Privkey bipSchnorrNonce(
      "58e8f2a1f78f0a591feb75aebecaaa81076e4290894b1c445cc32953604db089");

  // Act
  auto sig1 = DlcUtil::SchnorrSign(privkey, nonce, data);
  auto sig2 = DlcUtil::SchnorrSign(privkey, nonce, data);
  auto sig3 = DlcUtil::SchnorrSign(privkey, bipSchnorrNonce, data);
  auto sig4 = DlcUtil::SchnorrSign(privkey, nonce, str_data);
  bool is_valid = DlcUtil::SchnorrVerify(
      pubkey, bipSchnorrNonce.GeneratePubkey(), sig3, data);
  bool is_valid_str =
      DlcUtil::SchnorrVerify(pubkey, nonce.GeneratePubkey(), sig4, str_data);

  // Assert
  EXPECT_EQ(sig1.GetHex(), sig2.GetHex());
  EXPECT_NE(sig1.GetHex(), sig3.GetHex());
  EXPECT_EQ("7031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05",
            sig3.GetHex());
  EXPECT_TRUE(is_valid);
  EXPECT_TRUE(is_valid_str);
}

TEST(DlcUtil, Combine) {
  // Arrange
  Privkey oracle_privkey(
      "0000000000000000000000000000000000000000000000000000000000000001");
  Pubkey oracle_pubkey = oracle_privkey.GeneratePubkey();
  Privkey oracle_k_value(
      "0000000000000000000000000000000000000000000000000000000000000002");
  std::vector<Pubkey> oracle_r_points = {oracle_k_value.GeneratePubkey()};
  std::string message = "WIN";
  Privkey local_fund_privkey(
      "0000000000000000000000000000000000000000000000000000000000000003");
  Pubkey local_fund_pubkey = local_fund_privkey.GeneratePubkey();
  Privkey local_sweep_privkey(
      "0000000000000000000000000000000000000000000000000000000000000004");
  Pubkey local_sweep_pubkey = local_sweep_privkey.GeneratePubkey();

  // Act
  auto signature =
      DlcUtil::SchnorrSign(oracle_privkey, oracle_k_value, message);

  auto combined_pubkey =
      DlcUtil::GetCombinedKey(oracle_pubkey, oracle_r_points, {message},
                              local_fund_pubkey, local_sweep_pubkey);

  auto tweak_priv = DlcUtil::GetTweakedPrivkey(
      {signature.GetData()}, local_fund_privkey, local_sweep_pubkey);

  // Assert
  EXPECT_EQ(tweak_priv.GeneratePubkey().GetHex(), combined_pubkey.GetHex());
  EXPECT_TRUE(DlcUtil::SchnorrVerify(oracle_pubkey, oracle_r_points[0],
                                     signature, message));
}

TEST(DlcUtil, CombineMultipleMessages) {
  // Arrange
  Privkey oracle_privkey(
      "0000000000000000000000000000000000000000000000000000000000000001");
  Pubkey oracle_pubkey = oracle_privkey.GeneratePubkey();
  std::vector<Privkey> oracle_k_values = {
      Privkey(
          "0000000000000000000000000000000000000000000000000000000000000002"),
      Privkey(
          "0000000000000000000000000000000000000000000000000000000000000003"),
      Privkey(
          "0000000000000000000000000000000000000000000000000000000000000004")};
  std::vector<Pubkey> oracle_r_points;
  std::vector<std::string> messages = {"W", "I", "N"};
  Privkey local_fund_privkey(
      "0000000000000000000000000000000000000000000000000000000000000005");
  Pubkey local_fund_pubkey = local_fund_privkey.GeneratePubkey();
  Privkey local_sweep_privkey(
      "0000000000000000000000000000000000000000000000000000000000000006");
  Pubkey local_sweep_pubkey = local_sweep_privkey.GeneratePubkey();

  for (auto kval : oracle_k_values) {
    oracle_r_points.push_back(DlcUtil::GetSchnorrPublicNonce(kval));
  }

  // Act
  std::vector<ByteData> signatures;
  for (size_t i = 0; i < messages.size(); ++i) {
    auto sig =
        DlcUtil::SchnorrSign(oracle_privkey, oracle_k_values[i], messages[i]);
    signatures.push_back(sig.GetData());
  }

  auto combined_pubkey =
      DlcUtil::GetCombinedKey(oracle_pubkey, oracle_r_points, messages,
                              local_fund_pubkey, local_sweep_pubkey);

  auto tweak_priv = DlcUtil::GetTweakedPrivkey(signatures, local_fund_privkey,
                                               local_sweep_pubkey);

  // Assert
  EXPECT_EQ(tweak_priv.GeneratePubkey().GetHex(), combined_pubkey.GetHex());
}

TEST(DlcUtil, GetCommittedKeyBadInputLengths) {
  // Arrange
  Privkey oracle_privkey(
      "0000000000000000000000000000000000000000000000000000000000000001");
  Pubkey oracle_pubkey = oracle_privkey.GeneratePubkey();
  Privkey oracle_k_value(
      "0000000000000000000000000000000000000000000000000000000000000002");
  std::vector<Pubkey> oracle_r_points = {oracle_k_value.GeneratePubkey()};
  std::string message = "WIN";
  Privkey local_fund_privkey(
      "0000000000000000000000000000000000000000000000000000000000000003");
  Pubkey local_fund_pubkey = local_fund_privkey.GeneratePubkey();
  Privkey local_sweep_privkey(
      "0000000000000000000000000000000000000000000000000000000000000004");
  Pubkey local_sweep_pubkey = local_sweep_privkey.GeneratePubkey();

  // Act/Assert
  ASSERT_THROW(DlcUtil::GetCommittedKey(oracle_pubkey, oracle_r_points,
                                        {message, message}),
               CfdException);
}

TEST(DlcUtil, GetSchnorrPublicNonce) {
  // Arrange
  Privkey nonce(
      "0000000000000000000000000000000000000000000000000000000000000002");
  Privkey nonce2(
      "0000000000000000000000000000000000000000000000000000000000000003");

  // Act
  auto pubNonce = DlcUtil::GetSchnorrPublicNonce(nonce);
  auto pubNonce2 = DlcUtil::GetSchnorrPublicNonce(nonce2);

  // Assert
  ASSERT_EQ(nonce.GeneratePubkey().GetHex(), pubNonce.GetHex());
  ASSERT_NE(nonce2.GeneratePubkey().GetHex(), pubNonce2.GetHex());
}
