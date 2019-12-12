// Copyright 2019 CryptoGarage

#include <cstring>
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

namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::core::Address;
using cfd::core::AddressType;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::HashUtil;
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

const uint32_t TX_VERSION = 2;

TransactionController DlcManager::CreateCet(
    const Pubkey& local_pubkey, const Pubkey& oracle_pubkey,
    const Pubkey& oracle_r_point, std::string message, uint64_t delay,
    const Pubkey& remote_pubkey_payout, const Pubkey& remote_pubkey_penalty,
    const Amount& local_payout, const Amount& remote_payout,
    const Txid& fund_tx_id, uint32_t fund_vout, uint32_t n_lock_time) {
  auto commited_key =
      DlcUtil::GetCommittedKey(oracle_pubkey, oracle_r_point, message);
  auto cet_tx = TransactionController(TX_VERSION, n_lock_time);
  auto sender_script = CreateCetRedeemScript(local_pubkey, commited_key, delay,
                                             remote_pubkey_penalty);
  auto lock_script = ScriptUtil::CreateP2wshLockingScript(sender_script);
  cet_tx.AddTxOut(lock_script, local_payout);
  auto receiver_script =
      ScriptUtil::CreateP2wpkhLockingScript(remote_pubkey_payout);
  cet_tx.AddTxOut(receiver_script, remote_payout);
  cet_tx.AddTxIn(fund_tx_id, fund_vout);
  return cet_tx;
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_fund_amount, const Amount& remote_fund_amount,
    const std::vector<TxIn> local_inputs, const std::vector<TxIn> remote_inputs,
    uint32_t n_lock_time) {
  auto transaction_ctl = TransactionController(TX_VERSION, n_lock_time);
  std::vector<Pubkey> requiredSigs{local_pubkey, remote_pubkey};
  auto multi_sig_script =
      ScriptUtil::CreateMultisigRedeemScript(2, requiredSigs);
  transaction_ctl.AddTxOut(multi_sig_script,
                           local_fund_amount + remote_fund_amount);

  std::vector<TxIn> inputs;
  inputs.reserve(local_inputs.size() + remote_inputs.size());
  inputs.insert(inputs.end(), local_inputs.begin(), local_inputs.end());
  inputs.insert(inputs.end(), remote_inputs.begin(), remote_inputs.end());

  for (auto it = inputs.cbegin(); it != inputs.end(); ++it) {
    transaction_ctl.AddTxIn(it->GetTxid(), it->GetVout());
  }

  return transaction_ctl;
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_fund_amount, const Amount& remote_fund_amount,
    const std::vector<TxIn> local_inputs, const TxOut& local_change_output,
    const std::vector<TxIn> remote_inputs, const TxOut& remote_change_output,
    uint32_t n_lock_time) {
  auto transaction_ctl = CreateFundTransaction(
      local_pubkey, remote_pubkey, local_fund_amount, remote_fund_amount,
      local_inputs, remote_inputs, n_lock_time);
  transaction_ctl.AddTxOut(local_change_output.GetLockingScript(),
                           local_change_output.GetValue());
  transaction_ctl.AddTxOut(remote_change_output.GetLockingScript(),
                           remote_change_output.GetValue());
  return transaction_ctl;
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_fund_amount, const Amount& remote_fund_amount,
    const std::vector<TxIn> local_inputs, const TxOut& local_change_output,
    const std::vector<TxIn> remote_inputs, uint32_t n_lock_time) {
  auto transaction_ctl = CreateFundTransaction(
      local_pubkey, remote_pubkey, local_fund_amount, remote_fund_amount,
      local_inputs, remote_inputs, n_lock_time);
  transaction_ctl.AddTxOut(local_change_output.GetLockingScript(),
                           local_change_output.GetValue());
  return transaction_ctl;
}

TransactionController DlcManager::CreateFundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_fund_amount, const Amount& remote_fund_amount,
    const std::vector<TxIn> local_inputs, const std::vector<TxIn> remote_inputs,
    const TxOut& remote_change_output, uint32_t n_lock_time) {
  auto transaction_ctl = CreateFundTransaction(
      local_pubkey, remote_pubkey, local_fund_amount, remote_fund_amount,
      local_inputs, remote_inputs, n_lock_time);
  transaction_ctl.AddTxOut(remote_change_output.GetLockingScript(),
                           remote_change_output.GetValue());
  return transaction_ctl;
}

TransactionController DlcManager::CreateRefundTransaction(
    const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
    const Amount& local_amount, const Amount& remote_amount,
    const uint32_t lock_time, const Txid& fund_tx_id,
    const uint32_t fund_vout) {
  auto transaction_controller = TransactionController(2, lock_time);
  transaction_controller.AddTxIn(fund_tx_id, fund_vout);
  auto local_script = ScriptUtil::CreateP2wpkhLockingScript(local_pubkey);
  transaction_controller.AddTxOut(local_script, local_amount);
  auto remote_script = ScriptUtil::CreateP2wpkhLockingScript(remote_pubkey);
  transaction_controller.AddTxOut(remote_script, remote_amount);
  return transaction_controller;
}

TransactionController DlcManager::CreateClosingTransaction(
    const Pubkey& pubkey_dest, const Amount& amount, const Txid& cet_id,
    const uint32_t cet_vout, uint32_t n_lock_time) {
  auto closing_tx = TransactionController(TX_VERSION, n_lock_time);
  closing_tx.AddTxIn(cet_id, cet_vout);
  auto script = ScriptUtil::CreateP2wpkhLockingScript(pubkey_dest);
  closing_tx.AddTxOut(script, amount);
  return closing_tx;
}

void DlcManager::SignClosingTransaction(
    TransactionController* closingTransaction, const Privkey& privkey,
    const ByteData256 oracle_sig, const Txid& cet_tx_id,
    const uint32_t cet_vout, const Script cet_script, const Amount& value) {
  auto tweaked_key = DlcUtil::GetTweakedPrivateKey(privkey, oracle_sig);
  auto hash_type = SigHashType(SigHashAlgorithm::kSigHashAll);
  auto sig_hash_str = closingTransaction->CreateP2wshSignatureHash(
      cet_tx_id, cet_vout, cet_script, hash_type, value);
  auto sig_hash = ByteData256(sig_hash_str);
  auto signature = SignatureUtil::CalculateEcSignature(sig_hash, tweaked_key);
  std::vector<std::string> signed_params;
  signed_params.push_back(signature.GetHex());
  closingTransaction->AddWitnessStack(cet_tx_id, cet_vout, signed_params,
                                      cet_script);
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
    const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
    const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
    const Amount& remote_amount, const int64_t timeout,
    const std::vector<TxIn> local_inputs, const std::vector<TxIn> remote_inputs,
    uint32_t n_lock_time) {
  auto local_fund_pubkey = DeriveFundingPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundingPubkey(remote_ext_pubkey);
  auto fund_tx = CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, local_amount, remote_amount,
      local_inputs, remote_inputs, n_lock_time);

  return CreateDlcTransactions(outcomes, oracle_pubkey, oracle_r_point,
                               local_ext_pubkey, remote_ext_pubkey,
                               local_amount, remote_amount, timeout, fund_tx,
                               n_lock_time);
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
    const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
    const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
    const Amount& remote_amount, const int64_t timeout,
    const std::vector<TxIn> local_inputs, const TxOut& local_change,
    const std::vector<TxIn> remote_inputs, uint32_t n_lock_time) {
  auto local_fund_pubkey = DeriveFundingPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundingPubkey(remote_ext_pubkey);
  auto fund_tx = CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, local_amount, remote_amount,
      local_inputs, local_change, remote_inputs, n_lock_time);

  return CreateDlcTransactions(outcomes, oracle_pubkey, oracle_r_point,
                               local_ext_pubkey, remote_ext_pubkey,
                               local_amount, remote_amount, timeout, fund_tx,
                               n_lock_time);
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
    const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
    const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
    const Amount& remote_amount, const int64_t timeout,
    const std::vector<TxIn> local_inputs, const std::vector<TxIn> remote_inputs,
    const TxOut& remote_change, uint32_t n_lock_time) {
  auto local_fund_pubkey = DeriveFundingPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundingPubkey(remote_ext_pubkey);
  auto fund_tx = CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, local_amount, remote_amount,
      local_inputs, remote_inputs, remote_change, n_lock_time);

  return CreateDlcTransactions(outcomes, oracle_pubkey, oracle_r_point,
                               local_ext_pubkey, remote_ext_pubkey,
                               local_amount, remote_amount, timeout, fund_tx,
                               n_lock_time);
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
    const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
    const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
    const Amount& remote_amount, const int64_t timeout,
    const std::vector<TxIn> local_inputs, const TxOut& local_change,
    const std::vector<TxIn> remote_inputs, const TxOut& remote_change,
    uint32_t n_lock_time) {
  auto local_fund_pubkey = DeriveFundingPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundingPubkey(remote_ext_pubkey);
  auto fund_tx = CreateFundTransaction(
      local_fund_pubkey, remote_fund_pubkey, local_amount, remote_amount,
      local_inputs, local_change, remote_inputs, remote_change, n_lock_time);

  return CreateDlcTransactions(outcomes, oracle_pubkey, oracle_r_point,
                               local_ext_pubkey, remote_ext_pubkey,
                               local_amount, remote_amount, timeout, fund_tx,
                               n_lock_time);
}

Script DlcManager::CreateCetRedeemScript(const Pubkey& local_pubkey,
                                         const Pubkey& oracle_message_key,
                                         uint64_t delay,
                                         const Pubkey& remote_pubkey) {
  Pubkey combine_pubkey =
      Pubkey::CombinePubkey(local_pubkey, oracle_message_key);

  ScriptBuilder builder;
  builder.AppendOperator(ScriptOperator::OP_IF);
  builder.AppendData(combine_pubkey);
  builder.AppendOperator(ScriptOperator::OP_ELSE);
  builder.AppendData(delay);
  builder.AppendOperator(ScriptOperator::OP_CHECKSEQUENCEVERIFY);
  builder.AppendOperator(ScriptOperator::OP_DROP);
  builder.AppendData(remote_pubkey);
  builder.AppendOperator(ScriptOperator::OP_ENDIF);
  builder.AppendOperator(ScriptOperator::OP_CHECKSIG);
  Script script = builder.Build();

  if (!ScriptUtil::IsValidRedeemScript(script)) {
    throw DlcException("CETxLockingScript size is over.");
  }
  return script;
}

DlcTransactions DlcManager::CreateDlcTransactions(
    const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
    const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
    const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
    const Amount& remote_amount, const int64_t timeout,
    TransactionController fund_tx, uint32_t n_lock_time) {
  auto nb_outcomes = outcomes.size();

  std::vector<TransactionController> cets;
  cets.reserve(nb_outcomes);
  auto local_fund_pubkey = DeriveFundingPubkey(local_ext_pubkey);
  auto remote_fund_pubkey = DeriveFundingPubkey(remote_ext_pubkey);
  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();
  for (int i = 0; (size_t)i < nb_outcomes; i++) {
    uint32_t event_index = i + 1;
    auto local_cet_pubkey = DeriveCetPubkey(local_ext_pubkey, event_index, 0);
    auto remote_payout_pubkey =
        DeriveCetPubkey(remote_ext_pubkey, event_index, 2);
    auto remote_penalty_pubkey =
        DeriveCetPubkey(remote_ext_pubkey, event_index, 1);
    auto cet = CreateCet(local_cet_pubkey, oracle_pubkey, oracle_r_point,
                         outcomes[i].message, timeout, remote_payout_pubkey,
                         remote_penalty_pubkey, outcomes[i].local_payout,
                         outcomes[i].remote_payout, fund_tx_id, n_lock_time);
    cets.push_back(cet);
  }
  auto local_refund_pubkey = DeriveRefundPubkey(local_ext_pubkey);
  auto remote_refund_pubkey = DeriveRefundPubkey(remote_ext_pubkey);
  auto refund_tx = CreateRefundTransaction(
      local_refund_pubkey, remote_refund_pubkey, local_amount, remote_amount,
      timeout, fund_tx_id, 0);
  DlcTransactions dlc_transactions = {fund_tx, cets, refund_tx};
  return dlc_transactions;
}

Pubkey DlcManager::DeriveFundingPubkey(const ExtPubkey parent_key) {
  return parent_key.DerivePubkey(0).GetPubkey();
}

Pubkey DlcManager::DeriveRefundPubkey(const ExtPubkey parent_key) {
  return parent_key.DerivePubkey(1).DerivePubkey(0).GetPubkey();
}

Pubkey DlcManager::DeriveCetPubkey(const ExtPubkey parent_key,
                                   uint32_t event_index, uint32_t key_index) {
  return parent_key.DerivePubkey(1)
      .DerivePubkey(event_index)
      .DerivePubkey(key_index)
      .GetPubkey();
}

};  // namespace dlc
