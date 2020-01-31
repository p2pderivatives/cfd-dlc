// Copyright 2019 CryptoGarage

#include <algorithm>
#include <cstring>
// TODO(tibo): remove
#include <iostream>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "secp256k1.h"  // NOLINT

#include "dlc/dlc_exception.h"
#include "dlc/dlc_transactions.h"
#include "dlc/dlc_util.h"

namespace cfd {
namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::core::Address;
using cfd::core::AddressType;
using cfd::core::ByteData;
using cfd::core::ByteData256;
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

const uint32_t TX_VERSION = 2;
const int32_t CHANGE_DELTA = 5000;
const uint32_t MIN_MATURITY_TIME = 500000000;
const uint32_t APPROXIMATE_CET_VBYTES = 190;
const uint32_t APPROXIMATE_CLOSING_VBYTES = 122;
const uint32_t APPROXIMATE_REFUND_VBYTES = 168;

TransactionController DlcManager::CreateCet(
    const Script& cet_script, const Address& remote_payout_address,
    const Amount& local_payout, const Amount& closing_fee,
    const Amount& remote_payout, const Txid& fund_txid, uint32_t fund_vout,
    uint32_t maturity_time) {
  if (maturity_time < MIN_MATURITY_TIME) {
    throw DlcException("Maturity time must be greater than 500000000");
  }

  auto cet_tx = TransactionController(TX_VERSION, maturity_time);
  auto lock_script = ScriptUtil::CreateP2wshLockingScript(cet_script);
  cet_tx.AddTxOut(lock_script, local_payout + closing_fee);
  cet_tx.AddTxOut(remote_payout_address, remote_payout);
  cet_tx.AddTxIn(fund_txid, fund_vout);
  return cet_tx;
}

TransactionController DlcManager::CreateCet(
    const Pubkey& local_pubkey, const Pubkey& remote_payout_pubkey,
    const Pubkey& remote_penalty_pubkey, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint64_t delay,
    const Amount& local_payout, const Amount& closing_fee,
    const Amount& remote_payout, const Txid& fund_tx_id, uint32_t fund_vout,
    uint32_t maturity_time, NetType net_type) {
  if (maturity_time < MIN_MATURITY_TIME) {
    throw DlcException("Maturity time must be greater than 500000000");
  }

  Address remote_payout_address(net_type, WitnessVersion::kVersion0,
                                remote_payout_pubkey);
  auto cet_script =
      CreateCetRedeemScript(local_pubkey, oracle_pubkey, oracle_r_points,
                            messages, delay, remote_penalty_pubkey);
  return CreateCet(cet_script, remote_payout_address, local_payout, closing_fee,
                   remote_payout, fund_tx_id, fund_vout, maturity_time);
}

TransactionController DlcManager::CreateCet(
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    uint32_t event_index, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint64_t delay,
    const Amount& local_payout, const Amount& closing_fee,
    const Amount& remote_payout, const Txid& fund_tx_id, uint32_t fund_vout,
    uint32_t maturity_time, NetType net_type) {
  if (maturity_time < MIN_MATURITY_TIME) {
    throw DlcException("Maturity time must be greater than 500000000");
  }
  auto local_pubkey = DeriveCetPubkey(local_ext_pubkey, event_index, 0);
  auto remote_pubkey_penalty =
      DeriveCetPubkey(remote_ext_pubkey, event_index, 1);
  auto remote_pubkey_payout =
      DeriveCetPubkey(remote_ext_pubkey, event_index, 2);
  return CreateCet(local_pubkey, remote_pubkey_payout, remote_pubkey_penalty,
                   oracle_pubkey, oracle_r_points, messages, delay,
                   local_payout, closing_fee, remote_payout, fund_tx_id,
                   fund_vout, maturity_time, net_type);
}

Script DlcManager::CreateFundTxLockingScript(
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return CreateFundTxLockingScript(local_pubkey, remote_pubkey);
}

Script DlcManager::CreateFundTxLockingScript(const Pubkey& local_pubkey,
                                             const Pubkey& remote_pubkey) {
  return ScriptUtil::CreateMultisigRedeemScript(2,
                                                {local_pubkey, remote_pubkey});
}

TransactionController DlcManager::CreateFundTransaction(
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Amount& output_amount, const std::vector<TxIn>& local_inputs,
    const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
    const TxOut& remote_change_output, uint32_t n_lock_time) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return CreateFundTransaction(local_pubkey, remote_pubkey, output_amount,
                               local_inputs, local_change_output, remote_inputs,
                               remote_change_output, n_lock_time);
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& output_amount, const std::vector<TxIn>& local_inputs,
    const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
    const TxOut& remote_change_output, uint32_t n_lock_time) {
  auto transaction = TransactionController(TX_VERSION, n_lock_time);
  std::vector<Pubkey> requiredSigs{local_pubkey, remote_pubkey};
  auto multi_sig_script =
      ScriptUtil::CreateMultisigRedeemScript(2, requiredSigs);
  auto wit_script = ScriptUtil::CreateP2wshLockingScript(multi_sig_script);
  transaction.AddTxOut(wit_script, output_amount);

  std::vector<TxIn> inputs;
  inputs.reserve(local_inputs.size() + remote_inputs.size());
  inputs.insert(inputs.end(), local_inputs.begin(), local_inputs.end());
  inputs.insert(inputs.end(), remote_inputs.begin(), remote_inputs.end());

  for (auto it = inputs.cbegin(); it != inputs.end(); ++it) {
    transaction.AddTxIn(it->GetTxid(), it->GetVout());
  }

  AddOutputIfNotDust(&transaction, local_change_output);
  AddOutputIfNotDust(&transaction, remote_change_output);

  return transaction;
}

TransactionController DlcManager::CreateFundTransaction(
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Amount& local_input_amount, const Amount& local_collateral_amount,
    const Amount& remote_input_amount, const Amount& remote_collateral_amount,
    const std::vector<TxIn>& local_inputs, const Address& local_change_address,
    const std::vector<TxIn>& remote_inputs,
    const Address& remote_change_address, uint32_t fee_rate,
    uint32_t n_lock_time) {
  auto total_fee =
      (APPROXIMATE_CET_VBYTES + APPROXIMATE_CLOSING_VBYTES) * fee_rate;
  auto total_fee_amount = Amount::CreateBySatoshiAmount(total_fee);
  auto fund_output_amount =
      local_collateral_amount + remote_collateral_amount + total_fee_amount;

  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);

  auto local_change = local_input_amount.GetSatoshiValue() -
                      local_collateral_amount.GetSatoshiValue() - total_fee / 2;
  auto remote_change = remote_input_amount.GetSatoshiValue() -
                       remote_collateral_amount.GetSatoshiValue() -
                       total_fee / 2;
  if (local_change < 0) {
    throw DlcException("Not enough fund for local input.");
  }

  if (remote_change < 0) {
    throw DlcException("Not enough fund for remote input.");
  }

  auto local_change_amount = Amount::CreateBySatoshiAmount(local_change);
  auto remote_change_amount = Amount::CreateBySatoshiAmount(remote_change);

  TxOut local_change_output(local_change_amount, local_change_address);
  TxOut remote_change_output(remote_change_amount, remote_change_address);

  auto fund_tx = CreateFundTransaction(
      local_pubkey, remote_pubkey, fund_output_amount, local_inputs,
      local_change_output, remote_inputs, remote_change_output, n_lock_time);
  uint32_t common_size = fund_tx.GetSizeIgnoreTxIn();
  uint32_t local_input_size = GetTotalInputSize(local_inputs);
  uint32_t remote_input_size = GetTotalInputSize(remote_inputs);
  auto local_fund_fee = common_size / 2 + local_input_size;
  auto remote_fund_fee = common_size / 2 + remote_input_size;

  local_change = local_change - local_fund_fee;
  remote_change = remote_change - remote_fund_fee;

  if (local_change < 0) {
    throw DlcException("Not enough fund for local input.");
  }

  if (remote_change < 0) {
    throw DlcException("Not enough fund for remote input.");
  }

  local_change_amount = Amount::CreateBySatoshiAmount(local_change);
  remote_change_amount = Amount::CreateBySatoshiAmount(remote_change);

  local_change_output = TxOut(local_change_amount, local_change_address);
  remote_change_output = TxOut(remote_change_amount, remote_change_address);

  return CreateFundTransaction(local_pubkey, remote_pubkey, fund_output_amount,
                               local_inputs, local_change_output, remote_inputs,
                               remote_change_output, n_lock_time);
}

int32_t DlcManager::GetChangeValue(const Amount& input_amount,
                                   const Amount& collateral_amount,
                                   const Amount& fund_fee,
                                   const Amount& cet_closing_fee) {
  return input_amount.GetSatoshiValue() - collateral_amount.GetSatoshiValue() -
         fund_fee.GetSatoshiValue() - cet_closing_fee.GetSatoshiValue() / 2;
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

TransactionController DlcManager::CreateRefundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_amount, const Amount& remote_amount, uint32_t lock_time,
    const Txid& fund_tx_id, uint32_t fund_vout, NetType net_type) {
  auto local_out_address =
      Address(net_type, WitnessVersion::kVersion0, local_pubkey);
  auto remote_out_address =
      Address(net_type, WitnessVersion::kVersion0, remote_pubkey);
  return CreateRefundTransaction(local_out_address, remote_out_address,
                                 local_amount, remote_amount, lock_time,
                                 fund_tx_id, fund_vout);
}

TransactionController DlcManager::CreateRefundTransaction(
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Amount& local_amount, const Amount& remote_amount, uint32_t lock_time,
    const Txid& fund_tx_id, uint32_t fund_vout, NetType net_type) {
  auto local_pubkey = DeriveRefundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveRefundTxPubkey(remote_ext_pubkey);
  return CreateRefundTransaction(local_pubkey, remote_pubkey, local_amount,
                                 remote_amount, lock_time, fund_tx_id,
                                 fund_vout, net_type);
}

TransactionController DlcManager::CreateMutualClosingTransaction(
    const Address& local_out_address, const Address& remote_out_address,
    const Amount& local_amount, const Amount& remote_amount,
    const Txid& fund_tx_id, uint32_t fund_vout, uint32_t n_lock_time) {
  auto transaction_controller = TransactionController(TX_VERSION, n_lock_time);
  transaction_controller.AddTxIn(fund_tx_id, fund_vout);
  transaction_controller.AddTxOut(local_out_address, local_amount);
  transaction_controller.AddTxOut(remote_out_address, remote_amount);
  return transaction_controller;
}

TransactionController DlcManager::CreateMutualClosingTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_amount, const Amount& remote_amount,
    const Txid& fund_tx_id, uint32_t fund_vout, NetType net_type,
    uint32_t n_lock_time) {
  auto local_out_address =
      Address(net_type, WitnessVersion::kVersion0, local_pubkey);
  auto remote_out_address =
      Address(net_type, WitnessVersion::kVersion0, remote_pubkey);
  return CreateMutualClosingTransaction(local_out_address, remote_out_address,
                                        local_amount, remote_amount, fund_tx_id,
                                        fund_vout, n_lock_time);
}

TransactionController DlcManager::CreateMutualClosingTransaction(
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Amount& local_amount, const Amount& remote_amount,
    const Txid& fund_tx_id, uint32_t fund_vout, NetType net_type,
    uint32_t n_lock_time) {
  auto local_pubkey = DeriveMutualClosingTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveMutualClosingTxPubkey(remote_ext_pubkey);
  return CreateMutualClosingTransaction(local_pubkey, remote_pubkey,
                                        local_amount, remote_amount, fund_tx_id,
                                        fund_vout, net_type, n_lock_time);
}

ByteData DlcManager::GetRawMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const Privkey& privkey,
    const Script& fund_lockscript, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const Amount& input_amount) {
  return GetRawTxWitSigAllSignature(mutual_closing_tx, privkey, fund_tx_id,
                                    fund_tx_vout, fund_lockscript,
                                    input_amount);
}

ByteData DlcManager::GetRawMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const Privkey& privkey,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout,
    const Amount& input_amount) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawMutualClosingTxSignature(mutual_closing_tx, privkey, script,
                                        fund_tx_id, fund_tx_vout, input_amount);
}

ByteData DlcManager::GetRawMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx,
    const ExtPrivkey& ext_privkey, const ExtPubkey& local_ext_pubkey,
    const ExtPubkey& remote_ext_pubkey, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const Amount& input_amount) {
  auto privkey = DeriveFundTxPrivkey(ext_privkey);
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return GetRawMutualClosingTxSignature(mutual_closing_tx, privkey,
                                        local_pubkey, remote_pubkey, fund_tx_id,
                                        fund_tx_vout, input_amount);
}

void DlcManager::AddSignaturesToMutualClosingTx(
    TransactionController* mutual_closing_tx, const Script& fund_lockscript,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout,
    const std::vector<ByteData>& signatures) {
  AddSignaturesForMultiSigInput(mutual_closing_tx, fund_tx_id, fund_tx_vout,
                                fund_lockscript, signatures);
}

void DlcManager::AddSignaturesToMutualClosingTx(
    TransactionController* mutual_closing_tx, const ExtPubkey& local_ext_pubkey,
    const ExtPubkey& remote_ext_pubkey, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const std::vector<ByteData>& signatures) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  AddSignaturesToMutualClosingTx(mutual_closing_tx, local_pubkey, remote_pubkey,
                                 fund_tx_id, fund_tx_vout, signatures);
}

void DlcManager::AddSignaturesToMutualClosingTx(
    TransactionController* mutual_closing_tx, const Pubkey& local_pubkey,
    const Pubkey& remote_pubkey, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const std::vector<ByteData>& signatures) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToMutualClosingTx(mutual_closing_tx, script, fund_tx_id,
                                 fund_tx_vout, signatures);
}

bool DlcManager::VerifyMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const ByteData& signature,
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
    bool verify_remote) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return VerifyMutualClosingTxSignature(mutual_closing_tx, signature,
                                        local_pubkey, remote_pubkey, fund_txid,
                                        fund_vout, input_amount, verify_remote);
}

bool DlcManager::VerifyMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const ByteData& signature,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
    bool verify_remote) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyMutualClosingTxSignature(mutual_closing_tx, signature, pubkey,
                                        lock_script, fund_txid, fund_vout,
                                        input_amount);
}

bool DlcManager::VerifyMutualClosingTxSignature(
    const TransactionController& mutual_closing_tx, const ByteData& signature,
    const Pubkey& pubkey, const Script& lock_script, const Txid& fund_txid,
    uint32_t fund_vout, const Amount& input_amount) {
  return mutual_closing_tx.VerifyInputSignature(
      signature, pubkey, fund_txid, fund_vout, lock_script, SigHashType(),
      input_amount, WitnessVersion::kVersion0);
}

TransactionController DlcManager::CreateClosingTransaction(
    const Pubkey& pubkey_dest, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout, uint32_t n_lock_time, NetType net_type) {
  auto address = Address(net_type, WitnessVersion::kVersion0, pubkey_dest);
  return CreateClosingTransaction(address, amount, cet_id, cet_vout,
                                  n_lock_time);
}

TransactionController DlcManager::CreateClosingTransaction(
    const ExtPubkey& ext_pubkey, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout, uint32_t n_lock_time, NetType net_type) {
  auto pubkey = DeriveClosingTxPubkey(ext_pubkey);
  return CreateClosingTransaction(pubkey, amount, cet_id, cet_vout, n_lock_time,
                                  net_type);
}

TransactionController DlcManager::CreateClosingTransaction(
    const Address& address, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout, uint32_t n_lock_time) {
  auto closing_tx = TransactionController(TX_VERSION, n_lock_time);
  closing_tx.AddTxIn(cet_id, cet_vout);
  closing_tx.AddTxOut(address, amount);
  return closing_tx;
}

void DlcManager::SignClosingTransactionInput(
    TransactionController* closing_transaction, const Privkey& local_privkey,
    const ByteData& oracle_sig, const Script& cet_script, const Txid& cet_tx_id,
    uint32_t cet_vout, const Amount& value) {
  auto raw_signature = GetRawClosingTransactionSignature(
      *closing_transaction, local_privkey, oracle_sig, cet_script, cet_tx_id,
      cet_vout, value);
  auto signature =
      CryptoUtil::ConvertSignatureToDer(raw_signature, SigHashType());
  std::vector<std::string> signed_params;
  signed_params.push_back(signature.GetHex());
  signed_params.push_back("01");
  closing_transaction->AddWitnessStack(cet_tx_id, cet_vout, signed_params,
                                       cet_script);
}

void DlcManager::SignClosingTransactionInput(
    TransactionController* closing_transaction, const Privkey& local_privkey,
    const Pubkey& remote_penalty_pubkey, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto cet_script = CreateCetRedeemScript(
      local_privkey.GeneratePubkey(), oracle_pubkey, oracle_r_points, messages,
      delay, remote_penalty_pubkey);
  return SignClosingTransactionInput(closing_transaction, local_privkey,
                                     oracle_sig, cet_script, cet_tx_id,
                                     cet_vout, value);
}

void DlcManager::SignClosingTransactionInput(
    TransactionController* closingTransaction,
    const ExtPrivkey& local_ext_privkey, const ExtPubkey& remote_ext_pubkey,
    uint32_t event_index, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto local_private = DeriveCetPrivkey(local_ext_privkey, event_index, 0);
  auto remote_penalty_pubkey =
      DeriveCetPubkey(remote_ext_pubkey, event_index, 1);
  return SignClosingTransactionInput(
      closingTransaction, local_private, remote_penalty_pubkey, oracle_pubkey,
      oracle_r_points, messages, delay, oracle_sig, cet_tx_id, cet_vout, value);
}

ByteData DlcManager::GetRawClosingTransactionSignature(
    const TransactionController& closing_transaction,
    const Privkey& local_privkey, const ByteData& oracle_sig,
    const Script& cet_script, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto hash_type = SigHashType();
  auto sig_hash_str = closing_transaction.CreateSignatureHash(
      cet_tx_id, cet_vout, cet_script, hash_type, value,
      WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  auto tweaked_key = DlcUtil::GetTweakAddPrivateKey(local_privkey, oracle_sig);
  return SignatureUtil::CalculateEcSignature(sig_hash, tweaked_key);
}

ByteData DlcManager::GetRawClosingTransactionSignature(
    const TransactionController& closing_transaction,
    const Privkey& local_privkey, const Pubkey& remote_penalty_pubkey,
    const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto cet_script = CreateCetRedeemScript(
      local_privkey.GeneratePubkey(), oracle_pubkey, oracle_r_points, messages,
      delay, remote_penalty_pubkey);
  return GetRawClosingTransactionSignature(closing_transaction, local_privkey,
                                           oracle_sig, cet_script, cet_tx_id,
                                           cet_vout, value);
}

ByteData DlcManager::GetRawClosingTransactionSignature(
    const TransactionController& closing_transaction,
    const ExtPrivkey& local_ext_privkey, const ExtPubkey& remote_ext_pubkey,
    uint32_t event_index, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto local_privkey = DeriveCetPrivkey(local_ext_privkey, event_index, 0);
  auto remote_penalty_key = DeriveCetPubkey(remote_ext_pubkey, event_index, 1);
  return GetRawClosingTransactionSignature(
      closing_transaction, local_privkey, remote_penalty_key, oracle_pubkey,
      oracle_r_points, messages, delay, oracle_sig, cet_tx_id, cet_vout, value);
}

TransactionController DlcManager::CreatePenaltyTransaction(
    const Pubkey& pubkey_dest, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout, uint32_t n_lock_time, NetType net_type) {
  auto address = Address(net_type, WitnessVersion::kVersion0, pubkey_dest);
  return CreatePenaltyTransaction(address, amount, cet_id, cet_vout,
                                  n_lock_time);
}

TransactionController DlcManager::CreatePenaltyTransaction(
    const ExtPubkey& ext_pubkey, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout, uint32_t n_lock_time, NetType net_type) {
  auto pubkey = DerivePenaltyTxPubkey(ext_pubkey);
  return CreatePenaltyTransaction(pubkey, amount, cet_id, cet_vout, n_lock_time,
                                  net_type);
}

TransactionController DlcManager::CreatePenaltyTransaction(
    const Address& address, const Amount& amount, const Txid& cet_id,
    uint32_t cet_vout, uint32_t n_lock_time) {
  auto penalty_tx = TransactionController(TX_VERSION, n_lock_time);
  penalty_tx.AddTxIn(cet_id, cet_vout);
  penalty_tx.AddTxOut(address, amount);
  return penalty_tx;
}

ByteData DlcManager::GetRawPenaltyTransactionSignature(
    const TransactionController& penalty_transaction, const Privkey& privkey,
    const Script& cet_script, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto hash_type = SigHashType();
  auto sig_hash_str = penalty_transaction.CreateSignatureHash(
      cet_tx_id, cet_vout, cet_script, hash_type, value,
      WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  return SignatureUtil::CalculateEcSignature(sig_hash, privkey);
}

ByteData DlcManager::GetRawPenaltyTransactionSignature(
    const TransactionController& penalty_transaction,
    const Privkey& remote_privkey, const Pubkey& local_pubkey,
    const Pubkey& oracle_public_key, const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value) {
  auto cet_script =
      CreateCetRedeemScript(local_pubkey, oracle_public_key, oracle_r_points,
                            messages, delay, remote_privkey.GeneratePubkey());
  return GetRawPenaltyTransactionSignature(penalty_transaction, remote_privkey,
                                           cet_script, cet_tx_id, cet_vout,
                                           value);
}

ByteData DlcManager::GetRawPenaltyTransactionSignature(
    const TransactionController penalty_transaction,
    const ExtPrivkey& remote_ext_privkey, uint32_t event_index,
    const ExtPubkey& local_ext_pubkey, const Pubkey& oracle_public_key,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value) {
  auto remote_privkey = DeriveCetPrivkey(remote_ext_privkey, event_index, 1);
  auto local_pubkey = DeriveCetPubkey(local_ext_pubkey, event_index, 0);
  return GetRawPenaltyTransactionSignature(
      penalty_transaction, remote_privkey, local_pubkey, oracle_public_key,
      oracle_r_points, messages, delay, cet_tx_id, cet_vout, value);
}

void DlcManager::SignPenaltyTransactionInput(
    TransactionController* penalty_transaction, const Privkey& privkey,
    const Script& cet_script, const Txid& cet_tx_id, uint32_t cet_vout,
    const Amount& value) {
  auto raw_signature = GetRawPenaltyTransactionSignature(
      *penalty_transaction, privkey, cet_script, cet_tx_id, cet_vout, value);
  auto signature =
      CryptoUtil::ConvertSignatureToDer(raw_signature, SigHashType());
  std::vector<std::string> signed_params;
  signed_params.push_back(signature.GetHex());
  signed_params.push_back("00");
  penalty_transaction->AddWitnessStack(cet_tx_id, cet_vout, signed_params,
                                       cet_script);
}

void DlcManager::SignPenaltyTransactionInput(
    TransactionController* penalty_transaction, const Privkey& remote_privkey,
    const Pubkey& local_pubkey, const Pubkey& oracle_public_key,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value) {
  auto cet_script =
      CreateCetRedeemScript(local_pubkey, oracle_public_key, oracle_r_points,
                            messages, delay, remote_privkey.GeneratePubkey());
  return SignPenaltyTransactionInput(penalty_transaction, remote_privkey,
                                     cet_script, cet_tx_id, cet_vout, value);
}

void DlcManager::SignPenaltyTransactionInput(
    TransactionController* penalty_transaction,
    const ExtPrivkey& remote_ext_privkey, uint32_t event_index,
    const ExtPubkey& local_ext_pubkey, const Pubkey& oracle_public_key,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string>& messages, uint32_t delay,
    const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value) {
  auto remote_privkey = DeriveCetPrivkey(remote_ext_privkey, event_index, 1);
  auto local_pubkey = DeriveCetPubkey(local_ext_pubkey, event_index, 0);
  return SignPenaltyTransactionInput(
      penalty_transaction, remote_privkey, local_pubkey, oracle_public_key,
      oracle_r_points, messages, delay, cet_tx_id, cet_vout, value);
}

void DlcManager::SignFundingTransactionInput(
    TransactionController* funding_transaction, const Privkey& privkey,
    const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value) {
  auto raw_signature = GetRawFundingTransactionInputSignature(
      *funding_transaction, privkey, prev_tx_id, prev_tx_vout, value);
  auto hash_type = SigHashType(SigHashAlgorithm::kSigHashAll);
  auto signature = CryptoUtil::ConvertSignatureToDer(raw_signature, hash_type);
  funding_transaction->AddWitnessStack(
      prev_tx_id, prev_tx_vout, signature.GetHex(), privkey.GeneratePubkey());
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
                                    const ExtPubkey& local_ext_pubkey,
                                    const ExtPubkey& remote_ext_pubkey,
                                    const Txid& fund_txid, uint32_t fund_vout,
                                    const Amount& input_amount,
                                    bool verify_remote) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return VerifyCetSignature(cet, signature, local_pubkey, remote_pubkey,
                            fund_txid, fund_vout, input_amount, verify_remote);
}
bool DlcManager::VerifyCetSignature(const TransactionController& cet,
                                    const ByteData& signature,
                                    const Pubkey& local_pubkey,
                                    const Pubkey& remote_pubkey,
                                    const Txid& fund_txid, uint32_t fund_vout,
                                    const Amount& input_amount,
                                    bool verify_remote) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyCetSignature(cet, signature, pubkey, lock_script, fund_txid,
                            fund_vout, input_amount);
}

bool DlcManager::VerifyCetSignature(const TransactionController& cet,
                                    const ByteData& signature,
                                    const Pubkey& pubkey,
                                    const Script& lock_script,
                                    const Txid& fund_txid, uint32_t fund_vout,
                                    const Amount& input_amount) {
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
                                    const Txid& fund_tx_id,
                                    uint32_t fund_tx_vout,
                                    const Script& fund_lockscript,
                                    const std::vector<ByteData>& signatures) {
  AddSignaturesForMultiSigInput(cet, fund_tx_id, fund_tx_vout, fund_lockscript,
                                signatures);
}

void DlcManager::AddSignaturesToCet(TransactionController* cet,
                                    const Txid& fund_tx_id,
                                    uint32_t fund_tx_vout,
                                    const Pubkey& local_pubkey,
                                    const Pubkey& remote_pubkey,
                                    const std::vector<ByteData>& signatures) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToCet(cet, fund_tx_id, fund_tx_vout, script, signatures);
}

void DlcManager::AddSignaturesToCet(TransactionController* cet,
                                    const Txid& fund_tx_id,
                                    uint32_t fund_tx_vout,
                                    const ExtPubkey& local_ext_pubkey,
                                    const ExtPubkey& remote_ext_pubkey,
                                    const std::vector<ByteData>& signatures) {
  auto local_fund_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  AddSignaturesToCet(cet, fund_tx_id, fund_tx_vout, local_fund_pubkey,
                     remote_fund_pubkey, signatures);
}

void DlcManager::AddSignaturesToRefundTx(
    TransactionController* refund_tx, const Script& fund_lockscript,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout,
    const std::vector<ByteData>& signatures) {
  AddSignaturesForMultiSigInput(refund_tx, fund_tx_id, fund_tx_vout,
                                fund_lockscript, signatures);
}

void DlcManager::AddSignaturesToRefundTx(
    TransactionController* refund_tx, const ExtPubkey& local_ext_pubkey,
    const ExtPubkey& remote_ext_pubkey, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const std::vector<ByteData>& signatures) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  AddSignaturesToRefundTx(refund_tx, local_pubkey, remote_pubkey, fund_tx_id,
                          fund_tx_vout, signatures);
}
void DlcManager::AddSignaturesToRefundTx(
    TransactionController* refund_tx, const Pubkey& local_pubkey,
    const Pubkey& remote_pubkey, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const std::vector<ByteData>& signatures) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToRefundTx(refund_tx, script, fund_tx_id, fund_tx_vout,
                          signatures);
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

ByteData DlcManager::GetRawCetSignature(const TransactionController& cet,
                                        const Privkey& privkey,
                                        const Txid& fund_tx_id,
                                        uint32_t fund_tx_vout,
                                        const Script& fund_tx_lockscript,
                                        const Amount& fund_amount) {
  return GetRawTxWitSigAllSignature(cet, privkey, fund_tx_id, fund_tx_vout,
                                    fund_tx_lockscript, fund_amount);
}

ByteData DlcManager::GetRawCetSignature(
    const TransactionController& cet, const Privkey& privkey,
    const Txid& fund_tx_id, uint32_t fund_tx_vout, const Pubkey& local_pubkey,
    const Pubkey& remote_pubkey, const Amount& fund_amount) {
  auto redeem_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawCetSignature(cet, privkey, fund_tx_id, fund_tx_vout,
                            redeem_script, fund_amount);
}

ByteData DlcManager::GetRawCetSignature(const TransactionController& cet,
                                        const ExtPrivkey& ext_privkey,
                                        const Txid& fund_tx_id,
                                        uint32_t fund_tx_vout,
                                        const ExtPubkey& local_ext_pubkey,
                                        const ExtPubkey& remote_ext_pubkey,
                                        const Amount& fund_amount) {
  auto privkey = DeriveFundTxPrivkey(ext_privkey);
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return GetRawCetSignature(cet, privkey, fund_tx_id, fund_tx_vout,
                            local_pubkey, remote_pubkey, fund_amount);
}

bool DlcManager::VerifyRefundTxSignature(
    const TransactionController& refund_tx, const ByteData& signature,
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
    bool verify_remote) {
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return VerifyRefundTxSignature(refund_tx, signature, local_pubkey,
                                 remote_pubkey, fund_txid, fund_vout,
                                 input_amount, verify_remote);
}

bool DlcManager::VerifyRefundTxSignature(
    const TransactionController& refund_tx, const ByteData& signature,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
    bool verify_remote) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyRefundTxSignature(refund_tx, signature, pubkey, lock_script,
                                 fund_txid, fund_vout, input_amount);
}

bool DlcManager::VerifyRefundTxSignature(
    const TransactionController& refund_tx, const ByteData& signature,
    const Pubkey& pubkey, const Script& lock_script, const Txid& fund_txid,
    uint32_t fund_vout, const Amount& input_amount) {
  return refund_tx.VerifyInputSignature(
      signature, pubkey, fund_txid, fund_vout, lock_script, SigHashType(),
      input_amount, WitnessVersion::kVersion0);
}

ByteData DlcManager::GetRawRefundTxSignature(
    const TransactionController& refund_tx, const Privkey& privkey,
    const Script& fund_lockscript, const Txid& fund_tx_id,
    const uint32_t fund_tx_vout, const Amount& input_amount) {
  return GetRawTxWitSigAllSignature(refund_tx, privkey, fund_tx_id,
                                    fund_tx_vout, fund_lockscript,
                                    input_amount);
}

ByteData DlcManager::GetRawRefundTxSignature(
    const TransactionController& refund_tx, const Privkey& privkey,
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout,
    const Amount& input_amount) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawRefundTxSignature(refund_tx, privkey, script, fund_tx_id,
                                 fund_tx_vout, input_amount);
}

ByteData DlcManager::GetRawRefundTxSignature(
    const TransactionController& refund_tx, const ExtPrivkey& ext_privkey,
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Txid& fund_tx_id, const uint32_t fund_tx_vout,
    const Amount& input_amount) {
  auto privkey = DeriveFundTxPrivkey(ext_privkey);
  auto local_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  return GetRawRefundTxSignature(refund_tx, privkey, local_pubkey,
                                 remote_pubkey, fund_tx_id, fund_tx_vout,
                                 input_amount);
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome>& outcomes, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
    const Amount& local_input_amount, const Amount& local_collateral_amount,
    const Amount& remote_input_amount, const Amount& remote_collateral_amount,
    int64_t timeout, const std::vector<TxIn>& local_inputs,
    const Address& local_change_address, const std::vector<TxIn>& remote_inputs,
    const Address& remote_change_address, uint32_t fee_rate,
    uint32_t maturity_time, uint32_t n_lock_time, const NetType& net_type) {
  auto fund_tx = CreateFundTransaction(
      local_ext_pubkey, remote_ext_pubkey, local_input_amount,
      local_collateral_amount, remote_input_amount, remote_collateral_amount,
      local_inputs, local_change_address, remote_inputs, remote_change_address,
      fee_rate, n_lock_time);
  auto nb_outcomes = outcomes.size();

  std::vector<TransactionController> cets;
  cets.reserve(nb_outcomes);
  auto local_fund_pubkey = DeriveFundTxPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundTxPubkey(remote_ext_pubkey);
  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();
  auto closing_fee =
      Amount::CreateBySatoshiAmount(fee_rate * APPROXIMATE_CLOSING_VBYTES);
  for (int i = 0; (size_t)i < nb_outcomes; i++) {
    auto cet = CreateCet(local_ext_pubkey, remote_ext_pubkey, i + 1,
                         oracle_pubkey, oracle_r_points, outcomes[i].messages,
                         timeout, outcomes[i].local_payout, closing_fee,
                         outcomes[i].remote_payout, fund_tx_id, 0,
                         maturity_time, net_type);
    cets.push_back(cet);
  }

  auto fee_back_per_party =
      ((APPROXIMATE_CLOSING_VBYTES + APPROXIMATE_CET_VBYTES -
        APPROXIMATE_REFUND_VBYTES) *
       fee_rate) /
      2;
  auto refund_tx =
      CreateRefundTransaction(local_ext_pubkey, remote_ext_pubkey,
                              local_collateral_amount + fee_back_per_party,
                              remote_collateral_amount + fee_back_per_party,
                              n_lock_time, fund_tx_id, 0, net_type);
  return {fund_tx, cets, refund_tx};
}

Script DlcManager::CreateCetRedeemScript(
    const Pubkey& local_pubkey, const Pubkey& oracle_pubkey,
    const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string> messages, uint64_t delay,
    const Pubkey& remote_penalty_pubkey) {
  auto oracle_message_key =
      DlcUtil::GetCommittedKey(oracle_pubkey, oracle_r_points, messages);
  Pubkey combine_pubkey =
      Pubkey::CombinePubkey(local_pubkey, oracle_message_key);

  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_IF);
  builder.AppendData(combine_pubkey);
  builder.AppendOperator(ScriptOperator::OP_ELSE);
  builder.AppendData(delay);
  builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
  builder.AppendOperator(ScriptOperator::OP_DROP);
  builder.AppendData(remote_penalty_pubkey);
  builder.AppendOperator(ScriptOperator::OP_ENDIF);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  if (!ScriptUtil::IsValidRedeemScript(script)) {
    throw DlcException("CETxLockingScript size is over.");
  }
  return script;
}

Script DlcManager::CreateCetRedeemScript(
    const ExtPubkey& local_ext_pubkey, uint32_t event_index,
    const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
    const std::vector<std::string> messages, uint64_t delay,
    const ExtPubkey& remote_ext_pubkey) {
  auto local_pubkey = DeriveCetPubkey(local_ext_pubkey, event_index, 0);
  auto remote_penalty_pubkey =
      DeriveCetPubkey(remote_ext_pubkey, event_index, 1);
  return CreateCetRedeemScript(local_pubkey, oracle_pubkey, oracle_r_points,
                               messages, delay, remote_penalty_pubkey);
}

Pubkey DlcManager::DeriveFundTxPubkey(const ExtPubkey& parent_key) {
  return parent_key.DerivePubkey(0).GetPubkey();
}

Privkey DlcManager::DeriveFundTxPrivkey(const ExtPrivkey& parent_key) {
  return parent_key.DerivePrivkey(0).GetPrivkey();
}

Pubkey DlcManager::DeriveRefundTxPubkey(const ExtPubkey& parent_key) {
  return parent_key.DerivePubkey(1).DerivePubkey(0).GetPubkey();
}

Privkey DlcManager::DeriveRefundTxPrivkey(const ExtPrivkey& parent_key) {
  return parent_key.DerivePrivkey(1).DerivePrivkey(0).GetPrivkey();
}

Pubkey DlcManager::DeriveCetPubkey(const ExtPubkey& parent_key,
                                   uint32_t event_index, uint32_t key_index) {
  return parent_key.DerivePubkey(1)
      .DerivePubkey(event_index)
      .DerivePubkey(key_index)
      .GetPubkey();
}

Privkey DlcManager::DeriveCetPrivkey(const ExtPrivkey& parent_key,
                                     uint32_t event_index, uint32_t key_index) {
  return parent_key.DerivePrivkey(1)
      .DerivePrivkey(event_index)
      .DerivePrivkey(key_index)
      .GetPrivkey();
}

Pubkey DlcManager::DeriveMutualClosingTxPubkey(const ExtPubkey& parent_key) {
  return parent_key.DerivePubkey(2).DerivePubkey(0).GetPubkey();
}

Privkey DlcManager::DeriveMutualClosingTxPrivkey(const ExtPrivkey& parent_key) {
  return parent_key.DerivePrivkey(2).DerivePrivkey(0).GetPrivkey();
}

Pubkey DlcManager::DeriveClosingTxPubkey(const ExtPubkey& parent_key) {
  return parent_key.DerivePubkey(2).DerivePubkey(1).GetPubkey();
}

Privkey DlcManager::DeriveClosingTxPrivkey(const ExtPrivkey& parent_key) {
  return parent_key.DerivePrivkey(2).DerivePrivkey(1).GetPrivkey();
}

Pubkey DlcManager::DerivePenaltyTxPubkey(const ExtPubkey& parent_key) {
  return parent_key.DerivePubkey(2).DerivePubkey(2).GetPubkey();
}

Privkey DlcManager::DerivePenaltyTxPrivkey(const ExtPrivkey& parent_key) {
  return parent_key.DerivePrivkey(2).DerivePrivkey(2).GetPrivkey();
}

uint32_t DlcManager::GetTotalInputSize(const std::vector<TxIn>& inputs) {
  uint32_t total_size = 0;
  for (auto it = inputs.begin(); it != inputs.end(); ++it) {
    total_size += it->EstimateTxInSize(AddressType::kP2wpkhAddress);
  }

  return total_size;
}

void DlcManager::AddOutputIfNotDust(TransactionController* transaction,
                                    const TxOut& output) {
  if (output.GetValue() > CHANGE_DELTA) {
    transaction->AddTxOut(output.GetLockingScript(), output.GetValue());
  }
}
}  // namespace dlc
}  // namespace cfd
