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
                                const std::vector<Pubkey>& oracle_r_points,
                                const std::vector<std::string>& messages);

  static Pubkey GetCombinedKey(const Pubkey& oracle_pubkey,
                               const std::vector<Pubkey>& oracle_r_points,
                               const std::vector<std::string> messages,
                               const Pubkey& local_fund_pubkey,
                               const Pubkey& local_sweep_pubkey);

  static Privkey GetTweakedPrivkey(const std::vector<ByteData>& oracle_sig,
                                   const Privkey& local_fund_privkey,
                                   const Pubkey& local_sweep_pubkey);

  /**
   * @brief Tweak a private key using an oracle signature.
   *
   * @param privkey the private key to tweak.
   * @param oracle_sig the oracle signature.
   * @return Privkey the tweaked private key.
   */
  static Privkey GetTweakAddPrivateKey(const Privkey& privkey,
                                       const ByteData& tweak);
  static Pubkey GetTweakAddPublicKey(const Pubkey& pubkey,
                                     const ByteData& tweak);
  static ByteData256 SchnorrSign(const Privkey& oracle_privkey,
                                 const Privkey& k_value,
                                 const std::string& message);
  static ByteData256 SchnorrSign(const Privkey& oracle_privkey,
                                 const Privkey& k_value,
                                 const ByteData256& message);
  static bool SchnorrVerify(const Pubkey& pubkey, const Pubkey& nonce,
                            const ByteData256& signature,
                            const std::string& message);
  static bool SchnorrVerify(const Pubkey& pubkey, const Pubkey& nonce,
                            const ByteData256& signature,
                            const ByteData256& message);

  static Pubkey GetSchnorrPublicNonce(const Privkey& nonce);

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
