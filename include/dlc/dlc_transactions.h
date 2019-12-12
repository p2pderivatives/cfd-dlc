// Copyright 2019 CryptoGarage

#ifndef DLC_DLC_TRANSACTIONS_H_
#define DLC_DLC_TRANSACTIONS_H_

#include <string>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_hdwallet.h"

namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::Txid;
using cfd::TxIn;
using cfd::TxOut;
using cfd::core::ByteData256;
using cfd::core::ExtPubkey;
using cfd::core::Privkey;
using cfd::core::Pubkey;

/**
 * @brief A structure holding the set of transactions that make up a DLC.
 *
 */
struct DlcTransactions {
  TransactionController fund_transaction;
  std::vector<TransactionController> cets;
  TransactionController refund_transaction;
};

struct DlcOutcome {
  std::string message;
  Amount local_payout;
  Amount remote_payout;
};

/**
 * @brief Provide utility functions to create DLC transactions.
 *
 */
class DlcManager {
 public:
  /**
   * @brief Create a Cet (Contract Execution Transaction)
   *
   * @param local_pubkey the public key of the party that can submit the
   * transaction.
   * @param oracle_r_point the R point of the oracle.
   * @param delay the time after which the counter-party can claim all the
   * funds.
   * @param remote_pubkey the public key of the counter-party.
   * @param local_payout the payout to the party that might submit the
   * transaction.
   * @param remote_payout the payout of the counter-party.
   * @param fund_tx_id the transaction id of the fund transaction.
   * @param fund_vout the vout of the multi-sig fund transaction output.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController the CET.
   */
  static TransactionController CreateCet(
      const Pubkey& local_pubkey, const Pubkey& oracle_pubkey,
      const Pubkey& oracle_r_point, std::string message, uint64_t delay,
      const Pubkey& remote_pubkey_payout, const Pubkey& remote_pubkey_penalty,
      const Amount& local_payout, const Amount& remote_payout,
      const Txid& fund_tx_id, uint32_t fund_vout, uint32_t n_lock_time = 0);

  /**
   * @brief Create a Fund Transaction
   *
   * @param local_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_pubkey the public key of the counter-party.
   * @param local_fund_amount the amount funded by the local party.
   * @param remote_fund_amount the amount funded by the counter-party.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_fund_amount, const Amount& remote_fund_amount,
      const std::vector<TxIn> local_inputs,
      const std::vector<TxIn> remote_inputs, uint32_t n_lock_time = 0);
  /**
   * @brief Create a Fund Transaction
   *
   * @param local_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_pubkey the public key of the counter-party.
   * @param local_fund_amount the amount funded by the local party.
   * @param remote_fund_amount the amount funded by the counter-party.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param local_change_output the change output to the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param remote_change_outputs the set of change outputs to the
   * counter-party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_fund_amount, const Amount& remote_fund_amount,
      const std::vector<TxIn> local_inputs, const TxOut& local_change_output,
      const std::vector<TxIn> remote_inputs, uint32_t n_lock_time = 0);

  /**
   * @brief Create a Fund Transaction
   *
   * @param local_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_pubkey the public key of the counter-party.
   * @param local_fund_amount the amount funded by the local party.
   * @param remote_fund_amount the amount funded by the counter-party.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param local_change_output the change output to the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param remote_change_output the change output to the
   * counter-party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_fund_amount, const Amount& remote_fund_amount,
      const std::vector<TxIn> local_inputs, const TxOut& local_change_output,
      const std::vector<TxIn> remote_inputs, const TxOut& remote_change_output,
      uint32_t n_lock_time = 0);
  /**
   * @brief Create a Fund Transaction
   *
   * @param local_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_pubkey the public key of the counter-party.
   * @param local_fund_amount the amount funded by the local party.
   * @param remote_fund_amount the amount funded by the counter-party.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param remote_change_outputs the change output to the
   * counter-party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_fund_amount, const Amount& remote_fund_amount,
      const std::vector<TxIn> local_inputs,
      const std::vector<TxIn> remote_inputs, const TxOut& remote_change_output,
      uint32_t n_lock_time = 0);

  /**
   * @brief Create a Refund Transaction
   *
   * @param local_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_pubkey the public key of the counter-party.
   * @param local_amount the amount to be refunded to the local party.
   * @param remote_amount the amount to be refunded to the counter party.
   * @param lock_time the time after which this transaction can be included in
   * the blockchain.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @return TransactionController the refund transaction.
   */
  static TransactionController CreateRefundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_amount, const Amount& remote_amount,
      const uint32_t lock_time, const Txid& fund_tx_id,
      const uint32_t fund_vout);

  /**
   * @brief Create a Closing Transaction object
   *
   * @param pubkey_dest the public key to create the transaction output.
   * @param amount the amount to be transfered in the output.
   * @param cet_tx_id
   * @param cet_vout
   * @param n_lock_time
   * @return TransactionController
   */
  static TransactionController CreateClosingTransaction(
      const Pubkey& pubkey_dest, const Amount& amount, const Txid& cet_tx_id,
      const uint32_t cet_vout, uint32_t n_lock_time = 0);

  static void SignClosingTransaction(
      TransactionController* closingTransaction, const Privkey& privkey,
      const ByteData256 oracle_sig, const Txid& cet_tx_id,
      const uint32_t cet_vout, const Script cet_script, const Amount& value);

  /**
   * @brief Create a set of DLC transactions based on the given parameters. Note
   * that proper fee should be computed ahead of using this function.
   *
   * @param outcomes the possible outcome values.
   * @param payouts the payout of each party for each outcome. The size of the
   * vector should be the same to that of `outcomes`.
   * @param oracle_r_point the R point given by the oracle.
   * @param local_pubkeys the pubkeys to use for the local party.
   * @param remote_pubkeys the pubkeys to use for the remote party.
   * @param local_amount the funding amount for the local party.
   * @param remote_amount the funding amount for the local party.
   * @param timeout the time after which the refund transaction can be used.
   * @param local_inputs the utxos to use for the local party.
   * @param local_change_outputs the change outputs for the local party.
   * @param remote_inputs the utxos to use for the remote party.
   * @param remote_change_outputs the change outputs for the remote party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return DlcTransactions a struct containing the necessary transaction to
   * establish a DLC.
   */
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
      const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
      const ExtPubkey remote_extpubkey, const Amount& local_amount,
      const Amount& remote_amount, const int64_t timeout,
      const std::vector<TxIn> local_inputs, const TxOut& local_change_outputs,
      const std::vector<TxIn> remote_inputs, const TxOut& remote_change_outputs,
      uint32_t n_lock_time);

  /**
   * @brief Create a set of DLC transactions based on the given parameters. Note
   * that proper fee should be computed ahead of using this function.
   *
   * @param outcomes the possible outcome values.
   * @param payouts the payout of each party for each outcome. The size of the
   * vector should be the same to that of `outcomes`.
   * @param oracle_r_point the R point given by the oracle.
   * @param local_pubkeys the pubkeys to use for the local party.
   * @param remote_pubkeys the pubkeys to use for the remote party.
   * @param local_amount the funding amount for the local party.
   * @param remote_amount the funding amount for the local party.
   * @param timeout the time after which the refund transaction can be used.
   * @param local_inputs the utxos to use for the local party.
   * @param local_change_outputs the change outputs for the local party.
   * @param remote_inputs the utxos to use for the remote party.
   * @param remote_change_outputs the change outputs for the remote party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return DlcTransactions a struct containing the necessary transaction to
   * establish a DLC.
   */
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
      const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
      const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
      const Amount& remote_amount, const int64_t timeout,
      const std::vector<TxIn> local_inputs, const TxOut& local_change_outputs,
      const std::vector<TxIn> remote_inputs, uint32_t n_lock_time);

  /**
   * @brief Create a set of DLC transactions based on the given parameters. Note
   * that proper fee should be computed ahead of using this function.
   *
   * @param outcomes the possible outcome values.
   * @param payouts the payout of each party for each outcome. The size of the
   * vector should be the same to that of `outcomes`.
   * @param oracle_r_point the R point given by the oracle.
   * @param local_pubkeys the pubkeys to use for the local party.
   * @param remote_pubkeys the pubkeys to use for the remote party.
   * @param local_amount the funding amount for the local party.
   * @param remote_amount the funding amount for the local party.
   * @param timeout the time after which the refund transaction can be used.
   * @param local_inputs the utxos to use for the local party.
   * @param local_change_outputs the change outputs for the local party.
   * @param remote_inputs the utxos to use for the remote party.
   * @param remote_change_outputs the change outputs for the remote party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return DlcTransactions a struct containing the necessary transaction to
   * establish a DLC.
   */
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
      const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
      const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
      const Amount& remote_amount, const int64_t timeout,
      const std::vector<TxIn> local_inputs,
      const std::vector<TxIn> remote_inputs, const TxOut& remote_change_outputs,
      uint32_t n_lock_time);

  /**
   * @brief Create a set of DLC transactions based on the given parameters. Note
   * that proper fee should be computed ahead of using this function.
   *
   * @param outcomes the possible outcome values.
   * @param payouts the payout of each party for each outcome. The size of the
   * vector should be the same to that of `outcomes`.
   * @param oracle_r_point the R point given by the oracle.
   * @param local_pubkeys the pubkeys to use for the local party.
   * @param remote_pubkeys the pubkeys to use for the remote party.
   * @param local_amount the funding amount for the local party.
   * @param remote_amount the funding amount for the local party.
   * @param timeout the time after which the refund transaction can be used.
   * @param local_inputs the utxos to use for the local party.
   * @param local_change_outputs the change outputs for the local party.
   * @param remote_inputs the utxos to use for the remote party.
   * @param remote_change_outputs the change outputs for the remote party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return DlcTransactions a struct containing the necessary transaction to
   * establish a DLC.
   */
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_r_point,
      const Pubkey& oracle_pubkey, const ExtPubkey local_ext_pubkey,
      const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
      const Amount& remote_amount, const int64_t timeout,
      const std::vector<TxIn> local_inputs,
      const std::vector<TxIn> remote_inputs, uint32_t n_lock_time);

  /**
   * @brief Creates CET redeem script.
   *
   * @param local_pubkey the public key of the local party.
   * @param oracle_message_key the key commited to the message associated with
   * the outcome.
   * @param delay the time after which the counter party can claim all the
   * funds.
   * @param remote_pubkey the public key of the remote party.
   * @return Script the CET redeem script.
   */
  static Script CreateCetRedeemScript(const Pubkey& local_pubkey,
                                      const Pubkey& oracle_message_key,
                                      uint64_t delay,
                                      const Pubkey& remote_pubkey);

 private:
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome> outcomes, const Pubkey& oracle_pubkey,
      const Pubkey& oracle_r_point, const ExtPubkey local_ext_pubkey,
      const ExtPubkey remote_ext_pubkey, const Amount& local_amount,
      const Amount& remote_amount, const int64_t timeout,
      TransactionController fund_tx, uint32_t n_lock_time);

  static Pubkey DeriveFundingPubkey(const ExtPubkey parent_key);
  static Pubkey DeriveRefundPubkey(const ExtPubkey parent_key);
  static Pubkey DeriveCetPubkey(const ExtPubkey parent_key,
                                uint32_t event_index, uint32_t key_index);
};

}  // namespace dlc

#endif  // DLC_DLC_TRANSACTIONS_H_
