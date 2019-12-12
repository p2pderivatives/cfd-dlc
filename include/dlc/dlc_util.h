// Copyright 2019 CryptoGarage

#ifndef DLC_DLC_UTIL_H_
#define DLC_DLC_UTIL_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_key.h"
#include "secp256k1.h"  // NOLINT

namespace cfd {
namespace dlc {

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Privkey;
using cfd::core::Pubkey;

class DlcUtil {
 public:
  static Pubkey GetCommittedKey(const Pubkey& oracle_pub_key,
                                const Pubkey& oracle_r_point,
                                const std::string& message);
  static Pubkey GetCommittedKey(const Pubkey& oracle_pub_key,
                                const std::vector<Pubkey>& oracle_r_points,
                                const std::vector<std::string>& messages);
  static ByteData GetSerializedPubkeyData(const Pubkey& pubkey,
                                          bool compressed);
  static ByteData256 GetConcatenatedMessageHash(const Pubkey& oracle_r_point,
                                                const std::string& message);

  /**
   * @brief Tweak a private key using an oracle signature.
   *
   * @param privkey the private key to tweak.
   * @param oracle_sig the oracle signature.
   * @return Privkey the tweaked private key.
   */
  static Privkey GetTweakMulPrivateKey(const Privkey& privkey,
                                       const ByteData tweak);
  static Privkey GetTweakAddPrivateKey(const Privkey& privkey,
                                       const ByteData& tweak);
  static ByteData SchnorrSign(const Privkey& oracle_privkey,
                              const Privkey& k_value,
                              const std::string& message);

 private:
  static secp256k1_pubkey ParsePubkey(const Pubkey& pubkey);
  static ByteData GetSerializedSecPubkeyData(const secp256k1_pubkey& pubkey,
                                             bool compressed);
  static secp256k1_pubkey GetSecpCommittedKey(const Pubkey& oracle_pubkey,
                                              const Pubkey& oracle_r_point,
                                              const std::string& message);

  static Privkey NegatePrivateKey(const Privkey& privkey);
};
}  // namespace dlc
}  // namespace cfd

#endif  // DLC_DLC_UTIL_H_
