// Copyright 2019 CryptoGarage

#include "cfddlc/cfddlc_transactions.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>
#include <tuple>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "secp256k1.h"  // NOLINT

namespace cfd {
namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::core::Address;
using cfd::core::AddressType;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::CryptoUtil;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::HashUtil;
using cfd::core::NetType;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrUtil;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::ScriptUtil;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::SignatureUtil;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::TxOut;
using cfd::core::WitnessVersion;

static const uint32_t TX_VERSION = 2;

static const uint64_t DUST_LIMIT = 1000;

const uint32_t FUND_TX_BASE_WEIGHT = 214;
const uint32_t CET_BASE_WEIGHT = 500;

bool orderTxInputInfo(const TxInputInfo& a, const TxInputInfo& b) {
  return a.serialId < b.serialId;
}

TransactionController DlcManager::CreateCet(
    const TxOut& offer_output, const uint64_t offer_payout_serial_id,
    const TxOut& accept_output, const uint64_t accept_payout_serial_id,
    const Txid& fund_tx_id, const uint32_t fund_vout, uint32_t lock_time) {
  auto cet_tx = TransactionController(TX_VERSION, lock_time);
  const auto [first_output, second_output] =
      offer_payout_serial_id < accept_payout_serial_id
          ? std::make_tuple(offer_output, accept_output)
          : std::make_tuple(accept_output, offer_output);
  if (!IsDustOutput(first_output)) {
    cet_tx.AddTxOut(first_output.GetLockingScript(), first_output.GetValue());
  }
  if (!IsDustOutput(second_output)) {
    cet_tx.AddTxOut(second_output.GetLockingScript(), second_output.GetValue());
  }
  cet_tx.AddTxIn(fund_tx_id, fund_vout);
  return cet_tx;
}

std::vector<TransactionController> DlcManager::CreateCets(
    const Txid& fund_tx_id, const uint32_t fund_vout,
    const Script& offer_final_script_pubkey,
    const uint64_t offer_payout_serial_id,
    const Script& accept_final_script_pubkey,
    const uint64_t accept_payout_serial_id,
    const std::vector<DlcOutcome> outcomes, uint32_t lock_time) {
  std::vector<TransactionController> cets;
  cets.reserve(outcomes.size());

  for (auto outcome : outcomes) {
    TxOut offer_output(outcome.local_payout, offer_final_script_pubkey);
    TxOut accept_output(outcome.remote_payout, accept_final_script_pubkey);
    cets.push_back(CreateCet(offer_output, offer_payout_serial_id,
                             accept_output, accept_payout_serial_id, fund_tx_id,
                             fund_vout, lock_time));
  }

  return cets;
}

static std::vector<Pubkey> GetOrderedPubkeys(const Pubkey& a, const Pubkey& b) {
  return a.GetHex() < b.GetHex() ? std::vector<Pubkey>{a, b}
                                 : std::vector<Pubkey>{b, a};
}

Script DlcManager::CreateFundTxLockingScript(const Pubkey& local_fund_pubkey,
                                             const Pubkey& remote_fund_pubkey) {
  auto pubkeys = GetOrderedPubkeys(local_fund_pubkey, remote_fund_pubkey);
  return ScriptUtil::CreateMultisigRedeemScript(2, pubkeys);
}

TransactionController DlcManager::CreateFundTransaction(
    const PartyParams& offer_params, const PartyParams& accept_params,
    const uint32_t fee_rate, const uint64_t fund_output_serial_id,
    const Address& option_dest, const Amount& option_premium,
    const uint64_t lock_time) {
  auto transaction = TransactionController(TX_VERSION, lock_time);
  TxOut offer_change_output;
  auto total_collateral = offer_params.collateral + accept_params.collateral;
  uint64_t local_fund_fee;
  uint64_t local_cet_fee;
  std::tie(offer_change_output, local_fund_fee, local_cet_fee) =
      GetChangeOutputAndFees(offer_params, fee_rate, option_premium,
                             option_dest);

  TxOut accept_change_output;
  uint64_t remote_fund_fee;
  uint64_t remote_cet_fee;
  std::tie(accept_change_output, remote_fund_fee, remote_cet_fee) =
      GetChangeOutputAndFees(accept_params, fee_rate);

  auto fund_output_value = offer_params.input_amount +
                           accept_params.input_amount -
                           offer_change_output.GetValue().GetSatoshiValue() -
                           accept_change_output.GetValue().GetSatoshiValue() -
                           local_fund_fee - remote_fund_fee - option_premium;

  if (total_collateral + local_cet_fee + remote_cet_fee != fund_output_value) {
    throw CfdException(CfdError::kCfdInternalError,
                       "Fee computation doesn't match.");
  }

  std::vector<TxInputInfo> all_input_infos(offer_params.inputs_info);
  copy(accept_params.inputs_info.begin(), accept_params.inputs_info.end(),
       back_inserter(all_input_infos));

  std::sort(all_input_infos.begin(), all_input_infos.end(), orderTxInputInfo);

  std::vector<TxIn> inputs;

  for (auto input_info : all_input_infos) {
    inputs.push_back(input_info.input);
  }

  auto multi_sig_script = CreateFundTxLockingScript(offer_params.fund_pubkey,
                                                    accept_params.fund_pubkey);
  auto wit_script = ScriptUtil::CreateP2wshLockingScript(multi_sig_script);

  std::vector<std::tuple<Script, Amount, uint64_t>> outputs;
  outputs.push_back(
      std::make_tuple(wit_script, fund_output_value, fund_output_serial_id));

  for (auto it = inputs.cbegin(); it != inputs.end(); ++it) {
    transaction.AddTxIn(it->GetTxid(), it->GetVout(), it->GetUnlockingScript());
  }

  if (!IsDustOutput(offer_change_output)) {
    outputs.push_back(std::make_tuple(offer_change_output.GetLockingScript(),
                                      offer_change_output.GetValue(),
                                      offer_params.change_serial_id));
  }

  if (!IsDustOutput(accept_change_output)) {
    outputs.push_back(std::make_tuple(accept_change_output.GetLockingScript(),
                                      accept_change_output.GetValue(),
                                      accept_params.change_serial_id));
  }

  std::sort(outputs.begin(), outputs.end(),
            [](const std::tuple<Script, Amount, uint64_t> a,
               const std::tuple<Script, Amount, uint64_t> b) {
              return std::get<2>(a) < std::get<2>(b);
            });

  for (auto const& [script, amount, id] : outputs) {
    transaction.AddTxOut(script, amount);
  }

  if (option_premium > 0) {
    TxOut option_out(option_premium, option_dest);
    if (!IsDustOutput(option_out)) {
      transaction.AddTxOut(option_out.GetLockingScript(),
                           option_out.GetValue());
    }
  }

  return transaction;
}

TransactionController DlcManager::CreateRefundTransaction(
    const Script& local_final_script_pubkey,
    const Script& remote_final_script_pubkey, const Amount& local_amount,
    const Amount& remote_amount, uint32_t lock_time, const Txid& fund_tx_id,
    uint32_t fund_vout) {
  auto transaction_controller = TransactionController(TX_VERSION, lock_time);
  transaction_controller.AddTxIn(fund_tx_id, fund_vout);
  transaction_controller.AddTxOut(local_final_script_pubkey, local_amount);
  transaction_controller.AddTxOut(remote_final_script_pubkey, remote_amount);
  return transaction_controller;
}

void DlcManager::SignFundTransactionInput(
    TransactionController* fund_transaction, const Privkey& privkey,
    const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value) {
  auto raw_signature = GetRawFundingTransactionInputSignature(
      *fund_transaction, privkey, prev_tx_id, prev_tx_vout, value);
  auto hash_type = SigHashType(SigHashAlgorithm::kSigHashAll);
  auto signature = CryptoUtil::ConvertSignatureToDer(raw_signature, hash_type);
  fund_transaction->AddWitnessStack(
      prev_tx_id, prev_tx_vout, signature.GetHex(), privkey.GeneratePubkey());
}

void DlcManager::AddSignatureToFundTransaction(
    TransactionController* fund_transaction, const ByteData& signature,
    const Pubkey& pubkey, const Txid& prev_tx_id, uint32_t prev_tx_vout) {
  auto der_signature =
      CryptoUtil::ConvertSignatureToDer(signature, SigHashType());
  fund_transaction->AddWitnessStack(prev_tx_id, prev_tx_vout,
                                    der_signature.GetHex(), pubkey);
}

bool DlcManager::VerifyFundTxSignature(const TransactionController& fund_tx,
                                       const ByteData& signature,
                                       const Pubkey& pubkey, const Txid& txid,
                                       uint32_t vout,
                                       const Amount& input_amount) {
  return fund_tx.VerifyInputSignature(
      signature, pubkey, txid, vout, SigHashType(SigHashAlgorithm::kSigHashAll),
      input_amount, WitnessVersion::kVersion0);
}

AdaptorSignature DlcManager::CreateCetAdaptorSignature(
    const TransactionController& cet, const SchnorrPubkey& oracle_pubkey,
    const std::vector<SchnorrPubkey>& oracle_r_values,
    const Privkey& funding_sk, const Script& funding_script_pubkey,
    const Amount& total_collateral, const std::vector<ByteData256>& msgs) {
  auto adaptor_point =
      ComputeAdaptorPoint(msgs, oracle_r_values, oracle_pubkey);

  auto sig_hash = cet.GetTransaction().GetSignatureHash(
      0, funding_script_pubkey.GetData(), SigHashType(), total_collateral,
      WitnessVersion::kVersion0);
  return AdaptorSignature::Encrypt(sig_hash, funding_sk, adaptor_point);
}

std::vector<AdaptorSignature> DlcManager::CreateCetAdaptorSignatures(
    const std::vector<TransactionController>& cets,
    const SchnorrPubkey& oracle_pubkey,
    const std::vector<SchnorrPubkey>& oracle_r_value, const Privkey& funding_sk,
    const Script& funding_script_pubkey, const Amount& total_collateral,
    const std::vector<std::vector<ByteData256>>& msgs) {
  size_t nb = cets.size();
  if (nb != msgs.size()) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Number of cets differ from number of messages");
  }

  std::vector<AdaptorSignature> sigs;
  for (size_t i = 0; i < nb; i++) {
    sigs.push_back(CreateCetAdaptorSignature(
        cets[i], oracle_pubkey, oracle_r_value, funding_sk,
        funding_script_pubkey, total_collateral, msgs[i]));
  }

  return sigs;
}

bool DlcManager::VerifyCetAdaptorSignature(
    const AdaptorSignature& adaptor_signature, const TransactionController& cet,
    const Pubkey& pubkey, const SchnorrPubkey& oracle_pubkey,
    const std::vector<SchnorrPubkey>& oracle_r_values,
    const Script& funding_script_pubkey, const Amount& total_collateral,
    const std::vector<ByteData256>& msgs) {
  auto adaptor_point =
      ComputeAdaptorPoint(msgs, oracle_r_values, oracle_pubkey);
  auto sig_hash = cet.GetTransaction().GetSignatureHash(
      0, funding_script_pubkey.GetData(), SigHashType(), total_collateral,
      WitnessVersion::kVersion0);
  return adaptor_signature.Verify(sig_hash, pubkey, adaptor_point);
}

bool DlcManager::VerifyCetAdaptorSignatures(
    const std::vector<TransactionController>& cets,
    const std::vector<AdaptorSignature>& adaptor_signatures,
    const std::vector<std::vector<ByteData256>>& msgs, const Pubkey& pubkey,
    const SchnorrPubkey& oracle_pubkey,
    const std::vector<SchnorrPubkey>& oracle_r_values,
    const Script& funding_script_pubkey, const Amount& total_collateral) {
  auto nb = cets.size();
  if (nb != adaptor_signatures.size() || nb != msgs.size()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Number of transactions, signatures and messages differs.");
  }

  bool all_valid = true;

  for (size_t i = 0; i < nb && all_valid; i++) {
    all_valid &= VerifyCetAdaptorSignature(
        adaptor_signatures[i], cets[i], pubkey, oracle_pubkey, oracle_r_values,
        funding_script_pubkey, total_collateral, msgs[i]);
  }

  return all_valid;
}

void DlcManager::SignCet(TransactionController* cet,
                         const AdaptorSignature& adaptor_sig,
                         const std::vector<SchnorrSignature>& oracle_signatures,
                         const Privkey funding_sk,
                         const Script& funding_script_pubkey,
                         const Txid& fund_tx_id, uint32_t fund_vout,
                         const Amount& fund_amount) {
  if (oracle_signatures.size() < 1) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "No oracle signature provided.");
  }

  auto adaptor_secret = oracle_signatures[0].GetPrivkey();

  for (size_t i = 1; i < oracle_signatures.size(); i++) {
    adaptor_secret = adaptor_secret.CreateTweakAdd(
        ByteData256(oracle_signatures[i].GetPrivkey().GetData()));
  }

  auto adapted_sig = adaptor_sig.Decrypt(adaptor_secret);
  auto sig_hash = cet->GetTransaction().GetSignatureHash(
      0, funding_script_pubkey.GetData(), SigHashType(), fund_amount,
      WitnessVersion::kVersion0);
  auto own_sig = SignatureUtil::CalculateEcSignature(sig_hash, funding_sk);
  auto pubkeys =
      ScriptUtil::ExtractPubkeysFromMultisigScript(funding_script_pubkey);
  auto own_pubkey_hex = funding_sk.GetPubkey().GetHex();
  if (own_pubkey_hex == pubkeys[0].GetHex()) {
    AddSignaturesForMultiSigInput(cet, fund_tx_id, fund_vout,
                                  funding_script_pubkey,
                                  {own_sig, adapted_sig});
  } else if (own_pubkey_hex == pubkeys[1].GetHex()) {
    AddSignaturesForMultiSigInput(cet, fund_tx_id, fund_vout,
                                  funding_script_pubkey,
                                  {adapted_sig, own_sig});
  } else {
    throw new CfdException(CfdError::kCfdIllegalArgumentError,
                           "Public key not part of the multi sig script.");
  }
}

ByteData DlcManager::GetRawFundingTransactionInputSignature(
    const TransactionController& funding_transaction, const Privkey& privkey,
    const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value) {
  auto hash_type = SigHashType();
  auto sig_hash_str = funding_transaction.CreateSignatureHash(
      prev_tx_id, prev_tx_vout, privkey.GeneratePubkey(), hash_type, value,
      WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  return SignatureUtil::CalculateEcSignature(sig_hash, privkey);
}

void DlcManager::AddSignaturesForMultiSigInput(
    TransactionController* transaction, const Txid& prev_tx_id,
    uint32_t prev_tx_vout, const Script& multisig_script,
    const std::vector<ByteData>& signatures) {
  std::vector<std::string> signatures_str;
  signatures_str.resize(signatures.size() + 1);

  std::transform(signatures.begin(), signatures.end(),
                 signatures_str.begin() + 1, [](ByteData data) -> std::string {
                   auto hash_type = SigHashType(SigHashAlgorithm::kSigHashAll);
                   return CryptoUtil::ConvertSignatureToDer(data.GetHex(),
                                                            hash_type)
                       .GetHex();
                 });
  transaction->AddWitnessStack(prev_tx_id, prev_tx_vout, signatures_str,
                               multisig_script);
}

void DlcManager::AddSignaturesToRefundTx(
    TransactionController* refund_tx, const Script& fund_lockscript,
    const std::vector<ByteData>& signatures, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout) {
  AddSignaturesForMultiSigInput(refund_tx, fund_tx_id, fund_tx_vout,
                                fund_lockscript, signatures);
}

void DlcManager::AddSignaturesToRefundTx(
    TransactionController* refund_tx, const Pubkey& local_pubkey,
    const Pubkey& remote_pubkey, const std::vector<ByteData>& signatures,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToRefundTx(refund_tx, script, signatures, fund_tx_id,
                          fund_tx_vout);
}

ByteData DlcManager::GetRawTxWitSigAllSignature(
    const TransactionController& transaction, const Privkey& privkey,
    const Txid& prev_tx_id, uint32_t prev_tx_vout, const Script& lockscript,
    const Amount& amount) {
  auto sig_hash_str = transaction.CreateSignatureHash(
      prev_tx_id, prev_tx_vout, lockscript, SigHashType(), amount,
      WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  return SignatureUtil::CalculateEcSignature(sig_hash, privkey);
}

bool DlcManager::VerifyRefundTxSignature(
    const TransactionController& refund_tx, const ByteData& signature,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& input_amount, bool verify_remote, const Txid& fund_txid,
    uint32_t fund_vout) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyRefundTxSignature(refund_tx, signature, pubkey, lock_script,
                                 input_amount, fund_txid, fund_vout);
}

bool DlcManager::VerifyRefundTxSignature(
    const TransactionController& refund_tx, const ByteData& signature,
    const Pubkey& pubkey, const Script& lock_script, const Amount& input_amount,
    const Txid& fund_txid, uint32_t fund_vout) {
  return refund_tx.VerifyInputSignature(
      signature, pubkey, fund_txid, fund_vout, lock_script, SigHashType(),
      input_amount, WitnessVersion::kVersion0);
}

ByteData DlcManager::GetRawRefundTxSignature(
    const TransactionController& refund_tx, const Privkey& privkey,
    const Script& fund_lockscript, const Amount& input_amount,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout) {
  return GetRawTxWitSigAllSignature(refund_tx, privkey, fund_tx_id,
                                    fund_tx_vout, fund_lockscript,
                                    input_amount);
}

ByteData DlcManager::GetRawRefundTxSignature(
    const TransactionController& refund_tx, const Privkey& privkey,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& input_amount, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawRefundTxSignature(refund_tx, privkey, script, input_amount,
                                 fund_tx_id, fund_tx_vout);
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome>& outcomes, const PartyParams& offer_params,
    const PartyParams& accept_params, uint64_t refund_locktime,
    uint32_t fee_rate, uint64_t fund_output_serial_id,
    const Address& option_dest, const Amount& option_premium,
    uint64_t fund_lock_time, uint64_t cet_lock_time) {
  auto total_collateral = offer_params.collateral + accept_params.collateral;
  for (auto outcome : outcomes) {
    if (outcome.local_payout + outcome.remote_payout != total_collateral) {
      throw CfdException(CfdError::kCfdIllegalArgumentError,
                         "Sum of outcomes not equal to total collateral.");
    }
  }

  auto fund_tx = CreateFundTransaction(offer_params, accept_params, fee_rate,
                                       fund_output_serial_id, option_dest,
                                       option_premium, fund_lock_time);

  auto funding_script_pubkey = CreateFundTxLockingScript(
      offer_params.fund_pubkey, accept_params.fund_pubkey);
  auto wit_script = ScriptUtil::CreateP2wshLockingScript(funding_script_pubkey);
  // the given lock time.
  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();
  uint32_t fund_vout = fund_tx.GetTransaction().GetTxOutIndex(wit_script);

  auto cets = CreateCets(
      fund_tx_id, fund_vout, offer_params.final_script_pubkey,
      offer_params.final_serial_id, accept_params.final_script_pubkey,
      accept_params.final_serial_id, outcomes, cet_lock_time);

  auto refund_tx = CreateRefundTransaction(
      offer_params.final_script_pubkey, accept_params.final_script_pubkey,
      offer_params.collateral, accept_params.collateral, refund_locktime,
      fund_tx_id, fund_vout);

  return {fund_tx, cets, refund_tx, funding_script_pubkey};
}

uint32_t DlcManager::GetTotalInputVSize(const std::vector<TxIn>& inputs) {
  uint32_t total_size = 0;
  for (auto it = inputs.begin(); it != inputs.end(); ++it) {
    uint32_t witness_size;
    uint32_t full_size = it->EstimateTxInSize(AddressType::kP2wpkhAddress,
                                              Script(), &witness_size);
    total_size += AbstractTransaction::GetVsizeFromSize(
        full_size - witness_size, witness_size);
  }

  return total_size;
}

bool DlcManager::IsDustOutput(const TxOut& output) {
  return output.GetValue() < DUST_LIMIT;
}

static uint32_t GetInputsWeight(const std::vector<TxInputInfo>& inputs_info) {
  uint32_t total = 0;
  for (auto input_info : inputs_info) {
    auto script = input_info.input.GetUnlockingScript();
    auto script_size = script.IsEmpty() ? 0 : script.GetData().GetDataSize();
    total += 164 + 4 * script_size + input_info.max_witness_length;
  }

  return total;
}

std::tuple<TxOut, uint64_t, uint64_t> DlcManager::GetChangeOutputAndFees(
    const PartyParams& params, uint64_t fee_rate, Amount option_premium,
    Address option_dest) {
  auto inputs_size = GetInputsWeight(params.inputs_info);
  auto change_size = params.change_script_pubkey.GetData().GetDataSize();
  double fund_weight =
      (FUND_TX_BASE_WEIGHT / 2 + inputs_size + change_size * 4 + 36);
  if (option_premium.GetSatoshiValue() > 0) {
    if (option_dest.GetAddress() == "") {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "An destination address for the premium is required when the option "
          "premium amount is greater than zero.");
    }
    fund_weight +=
        36 + option_dest.GetLockingScript().GetData().GetDataSize() * 4;
  }
  auto fund_fee = ceil(fund_weight / 4) * fee_rate;
  double cet_weight = (CET_BASE_WEIGHT / 2 +
                       params.final_script_pubkey.GetData().GetDataSize() * 4);
  auto cet_fee = ceil(cet_weight / 4) * fee_rate;
  auto fund_out = params.collateral + fund_fee + cet_fee;
  if (params.input_amount < (fund_out + option_premium)) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Input amount smaller than required for collateral, "
                       "fees and option premium.");
  }

  TxOut change_output(params.input_amount - fund_out - option_premium,
                      params.change_script_pubkey);

  return std::make_tuple(change_output, fund_fee, cet_fee);
}

Pubkey DlcManager::ComputeAdaptorPoint(
    const std::vector<ByteData256>& msgs,
    const std::vector<SchnorrPubkey>& r_values, const SchnorrPubkey& pubkey) {
  if (r_values.size() != msgs.size()) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Number of r values and messages must match.");
  }

  std::vector<Pubkey> sigpoints;

  for (size_t i = 0; i < r_values.size(); i++) {
    sigpoints.push_back(
        SchnorrUtil::ComputeSigPoint(msgs[i], r_values[i], pubkey));
  }

  return sigpoints.size() > 1 ? Pubkey::CombinePubkey(sigpoints) : sigpoints[0];
}
}  // namespace dlc
}  // namespace cfd
