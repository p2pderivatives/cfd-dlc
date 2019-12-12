// Copyright 2019 CryptoGarage

#include <iostream>

#include "cfdcore/cfdcore_util.h"
#include "dlc/dlc_exception.h"
#include "dlc/dlc_util.h"

namespace cfd {
namespace dlc {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::HashUtil;
using cfd::core::Pubkey;

/* Caller is responsible for thread safety */
static secp256k1_context* global_ctx = NULL;

const secp256k1_context* secp_ctx(void) {
  const uint32_t flags = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN;

  if (!global_ctx) global_ctx = secp256k1_context_create(flags);

  return global_ctx;
}

ByteData DlcUtil::SchnorrSign(const Privkey& oracle_key, const Privkey& k_value,
                              const std::string& message) {
  // h(R,m)
  auto message_hash =
      GetConcatenatedMessageHash(k_value.GeneratePubkey(), message);
  // h(R,m) * v
  auto tweaked_key = GetTweakMulPrivateKey(oracle_key, message_hash.GetData());
  // - h(R,m) * v
  auto negated_tweaked_key = NegatePrivateKey(tweaked_key);
  // k - h(R, m) * v
  auto result = GetTweakAddPrivateKey(k_value, negated_tweaked_key.GetData());
  return result.GetData();
}

Pubkey DlcUtil::GetCommittedKey(const Pubkey& oracle_pub_key,
                                const std::vector<Pubkey>& oracle_r_points,
                                const std::vector<std::string>& messages) {
  if (oracle_r_points.size() != messages.size()) {
    throw DlcException(
        "Number of R points and number of messages should be equal.");
  }

  std::vector<secp256k1_pubkey> pubkey_list(oracle_r_points.size());
  std::vector<secp256k1_pubkey*> pointer_list(oracle_r_points.size());

  for (int i = 0; (size_t)i < oracle_r_points.size(); i++) {
    auto pubkey =
        GetSecpCommittedKey(oracle_pub_key, oracle_r_points[i], messages[i]);
    pubkey_list[i] = pubkey;
    pointer_list[i] = &pubkey_list[i];
  }

  secp256k1_pubkey combined_key;
  int ret = secp256k1_ec_pubkey_combine(
      secp_ctx(), &combined_key, pointer_list.data(), pubkey_list.size());

  if (ret != 1) {
    throw DlcException("Secp256k1 pubkey combine Error");
  }

  auto serialized_combined_data =
      GetSerializedSecPubkeyData(combined_key, true);
  return Pubkey(serialized_combined_data);
}

secp256k1_pubkey DlcUtil::GetSecpCommittedKey(const Pubkey& oracle_pub_key,
                                              const Pubkey& oracle_r_point,
                                              const std::string& message) {
  // Get message hash `h(R,m)`
  auto message_hash = GetConcatenatedMessageHash(oracle_r_point, message);
  auto ctx = secp_ctx();
  int ret = 0;
  auto oracle_pubkey_parse = ParsePubkey(oracle_pub_key);

  // Tweak the oracle public key to get V * h (R, m)
  ret = secp256k1_ec_pubkey_tweak_mul(ctx, &oracle_pubkey_parse,
                                      message_hash.GetBytes().data());

  if (ret != 1) {
    throw DlcException("Secp256k1 pubkey tweak error");
  }

  // Negate to get - V * h (R, m)
  ret = secp256k1_ec_pubkey_negate(ctx, &oracle_pubkey_parse);
  if (ret != 1) {
    throw DlcException("Secp256k1 pubkey negate error");
  }

  auto oracle_r_point_parse = ParsePubkey(oracle_r_point);
  secp256k1_pubkey* inputs[2] = {&oracle_r_point_parse, &oracle_pubkey_parse};

  secp256k1_pubkey result;
  ret = secp256k1_ec_pubkey_combine(ctx, &result, inputs, 2);
  if (ret != 1) {
    throw DlcException("Secp256k1 combine error");
  }

  return result;
}

Pubkey DlcUtil::GetCommittedKey(const Pubkey& oracle_pub_key,
                                const Pubkey& oracle_r_point,
                                const std::string& message) {
  auto result = GetSecpCommittedKey(oracle_pub_key, oracle_r_point, message);
  auto serialized_result_data = GetSerializedSecPubkeyData(result, true);
  return Pubkey(serialized_result_data);
}

secp256k1_pubkey DlcUtil::ParsePubkey(const Pubkey& pubkey) {
  auto pubkey_bytes = pubkey.GetData().GetBytes();
  auto ctx = secp_ctx();
  secp256k1_pubkey result;
  int ret = secp256k1_ec_pubkey_parse(ctx, &result, pubkey_bytes.data(),
                                      pubkey_bytes.size());
  if (ret != 1) {
    throw DlcException("Secp256k1 pubkey parse error");
  }

  return result;
}

ByteData DlcUtil::GetSerializedPubkeyData(const Pubkey& pubkey,
                                          bool compressed) {
  auto pubkey_parse = ParsePubkey(pubkey);
  return GetSerializedSecPubkeyData(pubkey_parse, compressed);
}

ByteData DlcUtil::GetSerializedSecPubkeyData(const secp256k1_pubkey& pubkey,
                                             bool compressed) {
  auto ctx = secp_ctx();
  std::vector<uint8_t> result_bytes(65);
  size_t result_bytes_size = result_bytes.size();
  int ret = secp256k1_ec_pubkey_serialize(
      ctx, result_bytes.data(), &result_bytes_size, &pubkey,
      compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  if (ret != 1 || (!compressed && result_bytes_size != 65) ||
      (compressed && result_bytes_size != 33)) {
    throw DlcException("Secp256k1 serialize exception");
  }

  if (compressed) {
    result_bytes.resize(result_bytes_size);
  }

  return ByteData(result_bytes);
}

ByteData256 DlcUtil::GetConcatenatedMessageHash(const Pubkey& oracle_r_point,
                                                const std::string& message) {
  std::vector<uint8_t> message_data_bytes(message.begin(), message.end());
  auto oracle_r_point_data = GetSerializedPubkeyData(oracle_r_point, false);

  auto oracle_r_point_bytes = oracle_r_point_data.GetBytes();
  oracle_r_point_bytes.insert(oracle_r_point_bytes.end(),
                              message_data_bytes.begin(),
                              message_data_bytes.end());
  return HashUtil::Sha256(oracle_r_point_bytes);
}

Privkey DlcUtil::GetTweakMulPrivateKey(const Privkey& privkey,
                                       const ByteData tweak) {
  std::vector<uint8_t> privkey_bytes = privkey.GetData().GetBytes();
  int result = secp256k1_ec_privkey_tweak_mul(secp_ctx(), privkey_bytes.data(),
                                              tweak.GetBytes().data());
  if (!result) {
    throw DlcException("Error tweaking private key.");
  }

  return Privkey(ByteData(privkey_bytes));
}

Privkey DlcUtil::NegatePrivateKey(const Privkey& privkey) {
  std::vector<uint8_t> privkey_bytes = privkey.GetData().GetBytes();
  int result = secp256k1_ec_privkey_negate(secp_ctx(), privkey_bytes.data());
  if (!result) {
    throw DlcException("Error tweaking private key.");
  }

  return Privkey(ByteData(privkey_bytes));
}

Privkey DlcUtil::GetTweakAddPrivateKey(const Privkey& privkey,
                                       const ByteData& tweak) {
  std::vector<uint8_t> privkey_bytes = privkey.GetData().GetBytes();
  int result = secp256k1_ec_privkey_tweak_add(secp_ctx(), privkey_bytes.data(),
                                              tweak.GetBytes().data());
  if (!result) {
    throw DlcException("Error tweaking private key.");
  }

  return Privkey(ByteData(privkey_bytes));
}

}  // namespace dlc
}  // namespace cfd
