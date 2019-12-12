// Copyright 2019 CryptoGarage

#include <cstring>

#include "cfdcore/cfdcore_util.h"
#include "dlc/dlc_exception.h"
#include "dlc/dlc_util.h"
#include "secp256k1_schnorrsig.h"  // NOLINT

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

int ConstantNonceFunction(unsigned char* nonce32, const unsigned char* msg32,
                          const unsigned char* key32,
                          const unsigned char* algo16, void* data,
                          unsigned int counter) {
  memcpy(nonce32, (const unsigned char*)data, 32);
  return 1;
}

const secp256k1_nonce_function ConstantNonce = ConstantNonceFunction;

ByteData256 DlcUtil::SchnorrSign(const Privkey& oracle_key,
                                 const Privkey& k_value,
                                 const std::string& message) {
  std::vector<uint8_t> message_bytes(message.begin(), message.end());
  auto hashed_message = HashUtil::Sha256(message_bytes);
  return SchnorrSign(oracle_key, k_value, hashed_message);
}

ByteData256 DlcUtil::SchnorrSign(const Privkey& oracle_key,
                                 const Privkey& k_value,
                                 const ByteData256& message) {
  secp256k1_schnorrsig sig;
  int ret = secp256k1_schnorrsig_sign(
      secp_ctx(), &sig, nullptr, message.GetBytes().data(),
      oracle_key.GetData().GetBytes().data(), ConstantNonce,
      k_value.GetData().GetBytes().data());
  if (ret != 1) {
    throw DlcException("Secp256k1 schnorr sign error.");
  }

  std::vector<uint8_t> r_value;
  r_value.assign(sig.data, sig.data + 32);

  std::vector<uint8_t> result;
  result.assign(sig.data + 32, sig.data + 64);
  return ByteData256(result);
}

bool DlcUtil::SchnorrVerify(const Pubkey& pubkey, const Pubkey& nonce,
                            const ByteData256& signature,
                            const std::string& message) {
  std::vector<uint8_t> message_bytes(message.begin(), message.end());
  auto hashed_message = HashUtil::Sha256(message_bytes);
  return SchnorrVerify(pubkey, nonce, signature, hashed_message);
}

bool DlcUtil::SchnorrVerify(const Pubkey& pubkey, const Pubkey& nonce,
                            const ByteData256& signature,
                            const ByteData256& message) {
  auto secp_pubkey = ParsePubkey(pubkey);
  secp256k1_schnorrsig sig;
  memcpy(sig.data, nonce.GetData().GetBytes().data() + 1, 32);
  memcpy(sig.data + 32, signature.GetBytes().data(), 32);
  return secp256k1_schnorrsig_verify(
             secp_ctx(), &sig, message.GetBytes().data(), &secp_pubkey) == 1;
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

Pubkey DlcUtil::GetCombinedKey(const Pubkey& oracle_pubkey,
                               const std::vector<Pubkey>& oracle_r_points,
                               const std::vector<std::string> messages,
                               const Pubkey& local_fund_pubkey,
                               const Pubkey& local_sweep_pubkey) {
  auto committed_key =
      DlcUtil::GetCommittedKey(oracle_pubkey, oracle_r_points, messages);
  Pubkey combine_pubkey =
      Pubkey::CombinePubkey(local_fund_pubkey, committed_key);
  auto hash = HashUtil::Sha256(local_sweep_pubkey.GetData());
  auto hashPub = Privkey(hash).GeneratePubkey();
  return Pubkey::CombinePubkey(combine_pubkey, hashPub);
}

Privkey DlcUtil::GetTweakedPrivkey(const std::vector<ByteData>& oracle_sigs,
                                   const Privkey& local_fund_privkey,
                                   const Pubkey& local_sweep_pubkey) {
  Privkey tweaked_key = local_fund_privkey;
  for (auto signature : oracle_sigs) {
    tweaked_key = DlcUtil::GetTweakAddPrivateKey(tweaked_key, signature);
  }

  auto hash = HashUtil::Sha256(local_sweep_pubkey);
  return GetTweakAddPrivateKey(tweaked_key, hash.GetData());
}

secp256k1_pubkey DlcUtil::GetSecpCommittedKey(const Pubkey& oracle_pub_key,
                                              const Pubkey& oracle_r_point,
                                              const std::string& message) {
  std::vector<uint8_t> message_bytes(message.begin(), message.end());
  auto message_hash = HashUtil::Sha256(message_bytes);
  auto pk = ParsePubkey(oracle_pub_key);
  auto rp = ParsePubkey(oracle_r_point);
  secp256k1_pubkey result;
  int ret = secp256k1_schnorrsig_sig_pubkey(
      secp_ctx(), &result, &rp, message_hash.GetBytes().data(), &pk);

  if (ret != 1) {
    throw DlcException("Secp256k1 sig pubkey error.");
  }
  auto serialized = GetSerializedSecPubkeyData(result, true);

  return result;
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
    result_bytes.shrink_to_fit();
  }

  return ByteData(result_bytes);
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

Pubkey DlcUtil::GetSchnorrPublicNonce(const Privkey& nonce) {
  secp256k1_schnorrnonce schnorrnonce;
  auto nonce_bytes = nonce.GetData().GetBytes();
  memcpy(schnorrnonce.data, nonce_bytes.data(), 32);
  secp256k1_pubkey pubnonce;
  secp256k1_schnorrsig_get_public_nonce(secp_ctx(), &pubnonce, &schnorrnonce);
  auto data = GetSerializedSecPubkeyData(pubnonce, true);
  return Pubkey(data);
}

}  // namespace dlc
}  // namespace cfd
