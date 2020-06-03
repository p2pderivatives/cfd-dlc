// Copyright 2019 CryptoGarage

#include "cfddlc/cfddlc_transactions.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "cfddlc/cfddlc_util.h"
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
static const uint32_t MIN_MATURITY_TIME = 500000000;
static const uint32_t APPROXIMATE_CET_VBYTES = 190;
static const uint32_t APPROXIMATE_CLOSING_VBYTES = 122;
static const uint32_t APPROXIMATE_REFUND_VBYTES = 168;
static const int WITNESS_SCALE_FACTOR = 4;

TransactionController DlcManager::CreateCet(
    const Script& cet_script, const Address& remote_final_address,
    const Amount& local_payout, const Amount& remote_payout,
    uint32_t maturity_time, uint32_t fee_rate, const Txid& fund_txid,
    uint32_t fund_vout) {
  if (maturity_time < MIN_MATURITY_TIME) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Maturity time must be greater than 500000000");
  }

  auto cet_tx = TransactionController(TX_VERSION, maturity_time);
  auto lock_script = ScriptUtil::CreateP2wshLockingScript(cet_script);
  if (!IsDustOutput(TxOut(local_payout, lock_script), fee_rate,
                    APPROXIMATE_CLOSING_VBYTES)) {
    cet_tx.AddTxOut(lock_script, local_payout);
  }
  if (!IsDustOutput(TxOut(remote_payout, remote_final_address), fee_rate)) {
    cet_tx.AddTxOut(remote_final_address, remote_payout);
  }
  cet_tx.AddTxIn(fund_txid, fund_vout);
  return cet_tx;
}

TransactionController DlcManager::CreateCet(
    const Pubkey& local_fund_pubkey, const Pubkey& local_sweep_pubkey,
    const Pubkey& remote_sweep_pubkey, const Address& remote_final_address,
    const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint64_t csv_delay,
    const Amount& local_payout, const Amount& remote_payout,
    uint32_t maturity_time, uint32_t fee_rate, const Txid& fund_tx_id,
    uint32_t fund_vout) {
  auto cet_script = CreateCetRedeemScript(local_fund_pubkey, local_sweep_pubkey,
                                          remote_sweep_pubkey, oracle_pubkey,
                                          oracle_r_points, messages, csv_delay);
  return CreateCet(cet_script, remote_final_address, local_payout,
                   remote_payout, maturity_time, fee_rate, fund_tx_id,
                   fund_vout);
}

Script DlcManager::CreateFundTxLockingScript(const Pubkey& local_fund_pubkey,
                                             const Pubkey& remote_fund_pubkey) {
  return ScriptUtil::CreateMultisigRedeemScript(
      2, {local_fund_pubkey, remote_fund_pubkey});
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
    const Amount& output_amount, const std::vector<TxIn>& local_inputs,
    const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
    const TxOut& remote_change_output, const uint32_t fee_rate) {
  auto transaction = TransactionController(TX_VERSION, 0);
  auto multi_sig_script =
      CreateFundTxLockingScript(local_fund_pubkey, remote_fund_pubkey);
  auto wit_script = ScriptUtil::CreateP2wshLockingScript(multi_sig_script);
  transaction.AddTxOut(wit_script, output_amount);

  std::vector<TxIn> inputs;
  inputs.reserve(local_inputs.size() + remote_inputs.size());
  inputs.insert(inputs.end(), local_inputs.begin(), local_inputs.end());
  inputs.insert(inputs.end(), remote_inputs.begin(), remote_inputs.end());

  for (auto it = inputs.cbegin(); it != inputs.end(); ++it) {
    transaction.AddTxIn(it->GetTxid(), it->GetVout());
  }

  if (!IsDustOutput(local_change_output, fee_rate)) {
    transaction.AddTxOut(local_change_output.GetLockingScript(),
                         local_change_output.GetValue());
  }

  if (!IsDustOutput(remote_change_output, fee_rate)) {
    transaction.AddTxOut(remote_change_output.GetLockingScript(),
                         remote_change_output.GetValue());
  }

  return transaction;
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
    const Amount& local_input_amount, const Amount& local_collateral_amount,
    const Amount& remote_input_amount, const Amount& remote_collateral_amount,
    const std::vector<TxIn>& local_inputs, const Address& local_change_address,
    const std::vector<TxIn>& remote_inputs,
    const Address& remote_change_address, uint32_t fee_rate) {
  auto total_fee =
      (APPROXIMATE_CET_VBYTES + APPROXIMATE_CLOSING_VBYTES) * fee_rate;
  auto total_fee_amount = Amount::CreateBySatoshiAmount(total_fee);
  auto fund_output_amount =
      local_collateral_amount + remote_collateral_amount + total_fee_amount;

  auto local_change = local_input_amount.GetSatoshiValue() -
                      local_collateral_amount.GetSatoshiValue() - total_fee / 2;
  auto remote_change = remote_input_amount.GetSatoshiValue() -
                       remote_collateral_amount.GetSatoshiValue() -
                       total_fee / 2;
  if (local_change < 0) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Not enough fund for local input.");
  }

  if (remote_change < 0) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Not enough fund for remote input.");
  }

  auto local_change_amount = Amount::CreateBySatoshiAmount(local_change);
  auto remote_change_amount = Amount::CreateBySatoshiAmount(remote_change);

  TxOut local_change_output(local_change_amount, local_change_address);
  TxOut remote_change_output(remote_change_amount, remote_change_address);

  auto fund_tx = CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, fund_output_amount, local_inputs,
      local_change_output, remote_inputs, remote_change_output, fee_rate);
  uint32_t common_size = fund_tx.GetSizeIgnoreTxIn();
  uint32_t local_input_size = GetTotalInputVSize(local_inputs);
  uint32_t remote_input_size = GetTotalInputVSize(remote_inputs);
  auto local_fund_fee = (common_size / 2 + local_input_size) * fee_rate;
  auto remote_fund_fee = (common_size / 2 + remote_input_size) * fee_rate;

  local_change = local_change - local_fund_fee;
  remote_change = remote_change - remote_fund_fee;

  if (local_change < 0) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Not enough fund for local input.");
  }

  if (remote_change < 0) {
    throw CfdException(CfdError::kCfdIllegalArgumentError,
                       "Not enough fund for remote input.");
  }

  local_change_amount = Amount::CreateBySatoshiAmount(local_change);
  remote_change_amount = Amount::CreateBySatoshiAmount(remote_change);

  local_change_output = TxOut(local_change_amount, local_change_address);
  remote_change_output = TxOut(remote_change_amount, remote_change_address);

  return CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, fund_output_amount, local_inputs,
      local_change_output, remote_inputs, remote_change_output, fee_rate);
}

TransactionController DlcManager::CreateRefundTransaction(
    const Address& local_out_address, const Address& remote_out_address,
    const Amount& local_amount, const Amount& remote_amount, uint32_t lock_time,
    const Txid& fund_tx_id, uint32_t fund_vout) {
  auto transaction_controller = TransactionController(TX_VERSION, lock_time);
  transaction_controller.AddTxIn(fund_tx_id, fund_vout);
  transaction_controller.AddTxOut(local_out_address, local_amount);
  transaction_controller.AddTxOut(remote_out_address, remote_amount);
  return transaction_controller;
}

TransactionController DlcManager::CreateMutualClosingTransaction(
    const Address& local_out_address, const Address& remote_out_address,
    const Amount& local_amount, const Amount& remote_amount, uint32_t fee_rate,
    const Txid& fund_tx_id, uint32_t fund_vout) {
  auto transaction_controller = TransactionController(TX_VERSION, 0);
  transaction_controller.AddTxIn(fund_tx_id, fund_vout);
  if (!IsDustOutput(TxOut(local_amount, local_out_address), fee_rate)) {
    transaction_controller.AddTxOut(local_out_address, local_amount);
  }

  if (!IsDustOutput(TxOut(remote_amount, remote_out_address), fee_rate)) {
    transaction_controller.AddTxOut(remote_out_address, remote_amount);
  }

  return transaction_controller;
}

ByteData DlcManager::GetRawMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const Privkey& privkey,
    const Script& fund_lockscript, const Amount& input_amount,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout) {
  return GetRawTxWitSigAllSignature(mutual_closing_tx, privkey, fund_tx_id,
                                    fund_tx_vout, fund_lockscript,
                                    input_amount);
}

ByteData DlcManager::GetRawMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const Privkey& privkey,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& input_amount, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawMutualClosingTxSignature(mutual_closing_tx, privkey, script,
                                        input_amount, fund_tx_id, fund_tx_vout);
}

void DlcManager::AddSignaturesToMutualClosingTx(
    TransactionController* mutual_closing_tx, const Script& fund_lockscript,
    const std::vector<ByteData>& signatures, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout) {
  AddSignaturesForMultiSigInput(mutual_closing_tx, fund_tx_id, fund_tx_vout,
                                fund_lockscript, signatures);
}

void DlcManager::AddSignaturesToMutualClosingTx(
    TransactionController* mutual_closing_tx, const Pubkey& local_pubkey,
    const Pubkey& remote_pubkey, const std::vector<ByteData>& signatures,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToMutualClosingTx(mutual_closing_tx, script, signatures,
                                 fund_tx_id, fund_tx_vout);
}

bool DlcManager::VerifyMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const ByteData& signature,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& input_amount, const Txid& fund_txid, uint32_t fund_vout,
    bool verify_remote) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyMutualClosingTxSignature(mutual_closing_tx, signature, pubkey,
                                        lock_script, input_amount, fund_txid,
                                        fund_vout);
}

bool DlcManager::VerifyMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const ByteData& signature,
    const Pubkey& pubkey, const Script& lock_script, const Amount& input_amount,
    const Txid& fund_txid, uint32_t fund_vout) {
  return mutual_closing_tx.VerifyInputSignature(
      signature, pubkey, fund_txid, fund_vout, lock_script, SigHashType(),
      input_amount, WitnessVersion::kVersion0);
}

TransactionController DlcManager::CreateClosingTransaction(
    const Address& address, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout) {
  auto closing_tx = TransactionController(TX_VERSION, 0);
  closing_tx.AddTxIn(cet_id, cet_vout);
  closing_tx.AddTxOut(address, amount);
  return closing_tx;
}

void DlcManager::SignClosingTransactionInput(
    TransactionController* closing_transaction, const Privkey& local_privkey,
    const Pubkey& local_sweep_pubkey, const std::vector<ByteData>& oracle_sigs,
    const Script& cet_script, const Amount& value, const Txid& cet_tx_id,
    uint32_t cet_vout) {
  auto raw_signature = GetRawClosingTransactionSignature(
      *closing_transaction, local_privkey, local_sweep_pubkey, oracle_sigs,
      cet_script, value, cet_tx_id, cet_vout);
  auto signature =
      CryptoUtil::ConvertSignatureToDer(raw_signature, SigHashType());
  std::vector<std::string> signed_params;
  signed_params.push_back(signature.GetHex());
  signed_params.push_back("01");
  closing_transaction->AddWitnessStack(cet_tx_id, cet_vout, signed_params,
                                       cet_script);
}

void DlcManager::SignClosingTransactionInput(
    TransactionController* closing_transaction,
    const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
    const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t csv_delay,
    const std::vector<ByteData>& oracle_sigs, const Amount& value,
    const Txid& cet_tx_id, uint32_t cet_vout) {
  auto cet_script = CreateCetRedeemScript(
      local_fund_privkey.GeneratePubkey(), local_sweep_pubkey,
      remote_sweep_pubkey, oracle_pubkey, oracle_r_points, messages, csv_delay);
  return SignClosingTransactionInput(closing_transaction, local_fund_privkey,
                                     local_sweep_pubkey, oracle_sigs,
                                     cet_script, value, cet_tx_id, cet_vout);
}

ByteData DlcManager::GetRawClosingTransactionSignature(
    const TransactionController& closing_transaction,
    const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
    const std::vector<ByteData>& oracle_sig, const Script& cet_script,
    const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout) {
  auto hash_type = SigHashType();
  auto sig_hash_str = closing_transaction.CreateSignatureHash(
      cet_tx_id, cet_vout, cet_script, hash_type, value,
      WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  auto tweaked_key = DlcUtil::GetTweakedPrivkey(oracle_sig, local_fund_privkey,
                                                local_sweep_pubkey);
  return SignatureUtil::CalculateEcSignature(sig_hash, tweaked_key);
}

ByteData DlcManager::GetRawClosingTransactionSignature(
    const TransactionController& closing_transaction,
    const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
    const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t csv_delay,
    const std::vector<ByteData>& oracle_sigs, const Amount& value,
    const Txid& cet_tx_id, uint32_t cet_vout) {
  auto cet_script = CreateCetRedeemScript(
      local_fund_privkey.GeneratePubkey(), local_sweep_pubkey,
      remote_sweep_pubkey, oracle_pubkey, oracle_r_points, messages, csv_delay);
  return GetRawClosingTransactionSignature(
      closing_transaction, local_fund_privkey, local_sweep_pubkey, oracle_sigs,
      cet_script, value, cet_tx_id, cet_vout);
}

TransactionController DlcManager::CreatePenaltyTransaction(
    const Address& address, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout) {
  auto penalty_tx = TransactionController(TX_VERSION, 0);
  penalty_tx.AddTxIn(cet_id, cet_vout);
  penalty_tx.AddTxOut(address, amount);
  return penalty_tx;
}

ByteData DlcManager::GetRawPenaltyTransactionSignature(
    const TransactionController& penalty_transaction, const Privkey& privkey,
    const Script& cet_script, const Amount& value, const Txid& cet_tx_id,
    uint32_t cet_vout) {
  auto hash_type = SigHashType();
  auto sig_hash_str = penalty_transaction.CreateSignatureHash(
      cet_tx_id, cet_vout, cet_script, hash_type, value,
      WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  return SignatureUtil::CalculateEcSignature(sig_hash, privkey);
}

ByteData DlcManager::GetRawPenaltyTransactionSignature(
    const TransactionController& penalty_transaction,
    const Privkey& remote_sweep_privkey, const Pubkey& local_fund_pubkey,
    const Pubkey& local_sweep_pubkey, const Pubkey& oracle_public_key,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout) {
  auto cet_script = CreateCetRedeemScript(local_fund_pubkey, local_sweep_pubkey,
                                          remote_sweep_privkey.GeneratePubkey(),
                                          oracle_public_key, oracle_r_points,
                                          messages, delay);

  return GetRawPenaltyTransactionSignature(penalty_transaction,
                                           remote_sweep_privkey, cet_script,
                                           value, cet_tx_id, cet_vout);
}

void DlcManager::SignPenaltyTransactionInput(
    TransactionController* penalty_transaction, const Privkey& privkey,
    const Script& cet_script, const Amount& value, const Txid& cet_tx_id,
    uint32_t cet_vout) {
  auto raw_signature = GetRawPenaltyTransactionSignature(
      *penalty_transaction, privkey, cet_script, value, cet_tx_id, cet_vout);
  auto signature =
      CryptoUtil::ConvertSignatureToDer(raw_signature, SigHashType());
  std::vector<std::string> signed_params;
  signed_params.push_back(signature.GetHex());
  signed_params.push_back("00");
  penalty_transaction->AddWitnessStack(cet_tx_id, cet_vout, signed_params,
                                       cet_script);
}

void DlcManager::SignPenaltyTransactionInput(
    TransactionController* penalty_transaction,
    const Privkey& remote_sweep_privkey, const Pubkey& local_fund_pubkey,
    const Pubkey& local_sweep_pubkey, const Pubkey& oracle_public_key,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout) {
  auto cet_script = CreateCetRedeemScript(local_fund_pubkey, local_sweep_pubkey,
                                          remote_sweep_privkey.GeneratePubkey(),
                                          oracle_public_key, oracle_r_points,
                                          messages, delay);
  return SignPenaltyTransactionInput(penalty_transaction, remote_sweep_privkey,
                                     cet_script, value, cet_tx_id, cet_vout);
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

bool DlcManager::VerifyCetSignature(const TransactionController& cet,
                                    const ByteData& signature,
                                    const Pubkey& local_pubkey,
                                    const Pubkey& remote_pubkey,
                                    const Amount& input_amount,
                                    const Txid& fund_txid, uint32_t fund_vout,
                                    bool verify_remote) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyCetSignature(cet, signature, pubkey, lock_script, input_amount,
                            fund_txid, fund_vout);
}

bool DlcManager::VerifyCetSignatures(
    const std::vector<TransactionController>& cets,
    const std::vector<ByteData>& signatures, const Pubkey& local_pubkey,
    const Pubkey& remote_pubkey, const Amount& input_amount,
    const Txid& fund_txid, uint32_t fund_vout, bool verify_remote) {
  bool all_valid = true;

  if (cets.size() != signatures.size()) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Number of transactions and number of signatures was different.");
  }

  for (size_t i = 0; i < cets.size() && all_valid; i++) {
    all_valid &=
        VerifyCetSignature(cets[i], signatures[i], local_pubkey, remote_pubkey,
                           input_amount, fund_txid, fund_vout, verify_remote);
  }

  return all_valid;
}

bool DlcManager::VerifyCetSignature(const TransactionController& cet,
                                    const ByteData& signature,
                                    const Pubkey& pubkey,
                                    const Script& lock_script,
                                    const Amount& input_amount,
                                    const Txid& fund_txid, uint32_t fund_vout) {
  return cet.VerifyInputSignature(signature, pubkey, fund_txid, fund_vout,
                                  lock_script, SigHashType(), input_amount,
                                  WitnessVersion::kVersion0);
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

void DlcManager::AddSignaturesToCet(TransactionController* cet,
                                    const Script& fund_lockscript,
                                    const std::vector<ByteData>& signatures,
                                    const Txid& fund_tx_id,
                                    uint32_t fund_tx_vout) {
  AddSignaturesForMultiSigInput(cet, fund_tx_id, fund_tx_vout, fund_lockscript,
                                signatures);
}

void DlcManager::AddSignaturesToCet(TransactionController* cet,
                                    const Pubkey& local_pubkey,
                                    const Pubkey& remote_pubkey,
                                    const std::vector<ByteData>& signatures,
                                    const Txid& fund_tx_id,
                                    uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToCet(cet, script, signatures, fund_tx_id, fund_tx_vout);
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

std::vector<ByteData> DlcManager::GetRawCetSignatures(
    const std::vector<TransactionController>& cets, const Privkey& privkey,
    const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
    const Amount& fund_amount, const Txid& fund_tx_id, uint32_t fund_tx_vout) {
  std::vector<ByteData> signatures;
  signatures.reserve(cets.size());
  for (auto cet : cets) {
    auto signature =
        GetRawCetSignature(cet, privkey, local_fund_pubkey, remote_fund_pubkey,
                           fund_amount, fund_tx_id, fund_tx_vout);
    signatures.push_back(signature);
  }

  return signatures;
}

ByteData DlcManager::GetRawCetSignature(const TransactionController& cet,
                                        const Privkey& privkey,
                                        const Script& fund_tx_lockscript,
                                        const Amount& fund_amount,
                                        const Txid& fund_tx_id,
                                        uint32_t fund_tx_vout) {
  return GetRawTxWitSigAllSignature(cet, privkey, fund_tx_id, fund_tx_vout,
                                    fund_tx_lockscript, fund_amount);
}

ByteData DlcManager::GetRawCetSignature(
    const TransactionController& cet, const Privkey& privkey,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& fund_amount, const Txid& fund_tx_id, uint32_t fund_tx_vout) {
  auto redeem_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawCetSignature(cet, privkey, redeem_script, fund_amount,
                            fund_tx_id, fund_tx_vout);
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
    const std::vector<DlcOutcome>& outcomes, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points, const Pubkey& local_fund_pubkey,
    const Pubkey& remote_fund_pubkey, const Pubkey& local_sweep_pubkey,
    const Pubkey& remote_sweep_pubkey, const Address& local_change_address,
    const Address& remote_change_address, const Address& local_final_address,
    const Address& remote_final_address, const Amount& local_input_amount,
    const Amount& local_collateral_amount, const Amount& remote_input_amount,
    const Amount& remote_collateral_amount, uint64_t refund_locktime,
    uint64_t csv_delay, const std::vector<TxIn>& local_inputs,
    const std::vector<TxIn>& remote_inputs, uint32_t fee_rate,
    uint32_t maturity_time) {
  auto fund_tx = CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, local_input_amount,
      local_collateral_amount, remote_input_amount, remote_collateral_amount,
      local_inputs, local_change_address, remote_inputs, remote_change_address,
      fee_rate);
  auto nb_outcomes = outcomes.size();

  std::vector<TransactionController> local_cets;
  local_cets.reserve(nb_outcomes);
  std::vector<TransactionController> remote_cets;
  remote_cets.reserve(nb_outcomes);
  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();
  auto closing_fee =
      Amount::CreateBySatoshiAmount(fee_rate * APPROXIMATE_CLOSING_VBYTES);
  for (int i = 0; (size_t)i < nb_outcomes; i++) {
    auto local_cet = CreateCet(
        local_fund_pubkey, local_sweep_pubkey, remote_sweep_pubkey,
        remote_final_address, oracle_pubkey, oracle_r_points,
        outcomes[i].messages, csv_delay, outcomes[i].local_payout + closing_fee,
        outcomes[i].remote_payout, maturity_time, fee_rate, fund_tx_id, 0);
    local_cets.push_back(local_cet);
    auto remote_cet = CreateCet(
        remote_fund_pubkey, remote_sweep_pubkey, local_sweep_pubkey,
        local_final_address, oracle_pubkey, oracle_r_points,
        outcomes[i].messages, csv_delay,
        outcomes[i].remote_payout + closing_fee, outcomes[i].local_payout,
        maturity_time, fee_rate, fund_tx_id, 0);
    remote_cets.push_back(remote_cet);
  }

  auto fee_back_per_party =
      ((APPROXIMATE_CLOSING_VBYTES + APPROXIMATE_CET_VBYTES -
        APPROXIMATE_REFUND_VBYTES) *
       fee_rate) /
      2;
  auto refund_tx =
      CreateRefundTransaction(local_final_address, remote_final_address,
                              local_collateral_amount + fee_back_per_party,
                              remote_collateral_amount + fee_back_per_party,
                              refund_locktime, fund_tx_id, 0);
  return {fund_tx, local_cets, remote_cets, refund_tx};
}

Script DlcManager::CreateCetRedeemScript(
    const Pubkey& local_fund_pubkey, const Pubkey& local_sweep_pubkey,
    const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string> messages, uint64_t csv_delay) {
  auto combine_pubkey =
      DlcUtil::GetCombinedKey(oracle_pubkey, oracle_r_points, messages,
                              local_fund_pubkey, local_sweep_pubkey);

  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_IF);
  builder.AppendData(combine_pubkey);
  builder.AppendOperator(ScriptOperator::OP_ELSE);
  builder.AppendData(csv_delay);
  builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
  builder.AppendOperator(ScriptOperator::OP_DROP);
  builder.AppendData(remote_sweep_pubkey);
  builder.AppendOperator(ScriptOperator::OP_ENDIF);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  if (!ScriptUtil::IsValidRedeemScript(script)) {
    throw CfdException(CfdError::kCfdIllegalStateError,
                       "CETxLockingScript size is over maximum size.");
  }
  return script;
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

bool DlcManager::IsDustOutput(const TxOut& output, uint32_t fee_rate,
                              uint32_t extra_size) {
  TxOutReference txout_ref(output);
  size_t nSize = txout_ref.GetSerializeSize();
  int witnessversion = 0;
  std::vector<unsigned char> witnessprogram;

  if (txout_ref.GetLockingScript().IsWitnessProgram()) {
    // sum the sizes of the parts of a transaction input
    // with 75% segwit discount applied to the script size.
    nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
  } else {
    nSize += (32 + 4 + 1 + 107 + 4);  // the 148 mentioned above
  }

  nSize += extra_size;

  return output.GetValue().GetSatoshiValue() < nSize * fee_rate;
}
}  // namespace dlc
}  // namespace cfd
