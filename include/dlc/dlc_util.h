// Copyright 2019 CryptoGarage

#ifndef DLC_DLC_UTIL_H_
#define DLC_DLC_UTIL_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_key.h"
#include "secp256k1.h"  // NOLINT

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
  static Privkey GetTweakedPrivateKey(const Privkey& privkey,
                                      const ByteData256 oracle_sig);

 private:
  static secp256k1_pubkey ParsePubkey(const Pubkey& pubkey);
  static ByteData GetSerializedSecPubkeyData(const secp256k1_pubkey& pubkey,
                                             bool compressed);
};

}  // namespace dlc

#endif  // DLC_DLC_UTIL_H_
