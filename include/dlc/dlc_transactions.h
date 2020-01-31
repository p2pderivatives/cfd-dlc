// Copyright 2019 CryptoGarage

#ifndef DLC_DLC_TRANSACTIONS_H_
#define DLC_DLC_TRANSACTIONS_H_

#include <string>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_hdwallet.h"

namespace cfd {
namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::Txid;
using cfd::TxIn;
using cfd::TxOut;
using cfd::core::Address;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::NetType;
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
  std::vector<std::string> messages;
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
   * @brief Create a Cet object
   *
   * @param local_ext_pubkey the extended public key of the party that can
   * submit the transaction.
   * @param remote_ext_pubkey the extended public key of the counter party to
   * use for the penalty transaction.
   * @param event_index the index of the CET used to derive the public keys
   * (starts at 1).
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the r points with which the oracle will sign the
   * outcome message.
   * @param messages the messages that this CET is for.
   * @param delay the number of blocks after which the penalty transaction can
   * be used.
   * @param local_payout the payout to the local party.
   * @param closing_fee the fee for the closing transaction to be added to the
   * local payout.
   * @param remote_payout the payout the the remote party.
   * @param fund_tx_id the ID of the fund transaction.
   * @param fund_vout the vout of the fund transaction output.
   * @param maturity_time the maturity time of the contract before which the
   * created CET cannot be broadcast.
   * @param net_type the target network.
   * @return TransactionController the created CET.
   */
  static TransactionController CreateCet(
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      uint32_t event_index, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint64_t delay,
      const Amount& local_payout, const Amount& closing_fee,
      const Amount& remote_payout, const Txid& fund_tx_id, uint32_t fund_vout,
      uint32_t maturity_time, NetType net_type);

  /**
   * @brief Create a Cet object
   *
   * @param local_pubkey the public key of the party that can submit the
   * transaction.
   * @param remote_payout_pubkey the public key of the counter party for
   * receiving their payout.
   * @param remote_penalty_pubkey the public key of the counter party to use for
   * the penalty transaction.
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the r points with which the oracle will sign the
   * outcome message.
   * @param messages the messages that this CET is for.
   * @param delay the number of blocks after which the penalty transaction can
   * be used.
   * @param local_payout the payout to the local party.
   * @param closing_fee the fee for the closing transaction to be added to the
   * local payout.
   * @param remote_payout the payout the the remote party.
   * @param fund_tx_id the ID of the fund transaction.
   * @param fund_vout the vout of the fund transaction output.
   * @param maturity_time the maturity time of the contract before which the
   * created CET cannot be broadcast.
   * @param net_type the target network.
   * @return TransactionController the created CET.
   */
  static TransactionController CreateCet(
      const Pubkey& local_pubkey, const Pubkey& remote_payout_pubkey,
      const Pubkey& remote_penalty_pubkey, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint64_t delay,
      const Amount& local_payout, const Amount& closing_fee,
      const Amount& remote_payout, const Txid& fund_tx_id, uint32_t fund_vout,
      uint32_t maturity_time, NetType net_type);

  /**
   * @brief Create a Cet object
   *
   * @param cet_script the cet script.
   * @param remote_payout_address the address for the remote payout.
   * @param local_payout the local payout.
   * @param closing_fee the closing fee to be added to the local payout.
   * @param remote_payout the remote payout.
   * @param fund_txid the ID of the fund transaction.
   * @param fund_vout the output number within the fund transaction.
   * @param maturity_time the maturity time of the contract before which the
   * created CET cannot be broadcast.
   * @return TransactionController the created CET
   */
  static TransactionController CreateCet(
      const Script& cet_script, const Address& remote_payout_address,
      const Amount& local_payout, const Amount& closing_fee,
      const Amount& remote_payout, const Txid& fund_txid, uint32_t fund_vout,
      uint32_t maturity_time);

  /**
   * @brief Create a Fund Transaction
   *
   * @param local_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_pubkey the public key of the counter-party.
   * @param output_amount the amount to direct to the multisig output.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param local_change_output the change output to the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param remote_change_output the change output to the
   * counter-party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController the created fund transaction.
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& output_amount, const std::vector<TxIn>& local_inputs,
      const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
      const TxOut& remote_change_output, uint32_t n_lock_time = 0);

  /**
   * @brief Create a Fund Transaction
   *
   * @param local_ext_pubkey the extended public key of the party that might
   * submit the transaction.
   * @param remote_ext_pubkey the extended public key of the counter-party.
   * @param output_amount the amount to direct to the multisig output.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param local_change_output the change output to the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param remote_change_output the change output to the
   * counter-party.
   * @param n_lock_time (optional) the lock time for the transaction to avoid
   * fee snipping and increase privacy.
   * @return TransactionController the created fund transaction.
   */
  static TransactionController CreateFundTransaction(
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      const Amount& output_amount, const std::vector<TxIn>& local_inputs,
      const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
      const TxOut& remote_change_output, uint32_t n_lock_time = 0);

  /**
   * @brief Create a Fund Tx Locking Script object
   * @param local_ext_pubkey the extended public key of the local party.
   * @param remote_ext_pubkey the extended public key of the remote party.
   *
   * @return Script the multi sig lock script.
   */
  static Script CreateFundTxLockingScript(const ExtPubkey& local_ext_pubkey,
                                          const ExtPubkey& remote_ext_pubkey);

  /**
   * @brief Create a Fund Tx Locking Script object
   * @param local_pubkey the public key of the local party.
   * @param remote_pubkey the public key of the remote party.
   *
   * @return Script the multi sig lock script.
   */
  static Script CreateFundTxLockingScript(const Pubkey& local_pubkey,
                                          const Pubkey& remote_pubkey);
  /**
   * @brief Create a Refund Transaction
   *
   * @param local_out_address the address of the local party.
   * @param remote_out_address the public key of the remote party.
   * @param local_amount the amount to be refunded to the local party.
   * @param remote_amount the amount to be refunded to the counter party.
   * @param lock_time the time after which this transaction can be included in
   * the blockchain.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @return TransactionController the refund transaction.
   */
  static TransactionController CreateRefundTransaction(
      const Address& local_out_address, const Address& remote_out_address,
      const Amount& local_amount, const Amount& remote_amount,
      uint32_t lock_time, const Txid& fund_tx_id, uint32_t fund_vout);

  /**
   * @brief Create a Refund Transaction
   *
   * @param local_pubkey the public key of the local party.
   * @param remote_pubkey the public key of the counter party.
   * @param local_amount the amount to be refunded to the local party.
   * @param remote_amount the amount to be refunded to the counter party.
   * @param lock_time the time after which this transaction can be included in
   * the blockchain.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param net_type the network type for creating the addresses.
   * @return TransactionController the refund transaction.
   */
  static TransactionController CreateRefundTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_amount, const Amount& remote_amount,
      uint32_t lock_time, const Txid& fund_tx_id, uint32_t fund_vout,
      NetType net_type);

  /**
   * @brief Create a Refund Transaction
   *
   * @param local_ext_pubkey the extended public key of the local party.
   * @param remote_ext_pubkey the extended public key of the counter-party.
   * @param local_amount the amount to be refunded to the local party.
   * @param remote_amount the amount to be refunded to the counter party.
   * @param lock_time the time after which this transaction can be included in
   * the blockchain.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param net_type the network type for creating the addresses.
   * @return TransactionController the refund transaction.
   */
  static TransactionController CreateRefundTransaction(
      const ExtPubkey& local_pubkey, const ExtPubkey& remote_pubkey,
      const Amount& local_amount, const Amount& remote_amount,
      uint32_t lock_time, const Txid& fund_tx_id, uint32_t fund_vout,
      NetType net_type);

  /**
   * @brief Create a Mutual Closing Transaction
   *
   * @param local_out_address the address of the local party.
   * @param remote_out_address the public key of the counter party.
   * @param local_amount the amount to the local party.
   * @param remote_amount the amount to the counter party.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param n_lock_time the nLockTime for this transaction.
   * @return TransactionController the mutual closing transaction.
   */
  static TransactionController CreateMutualClosingTransaction(
      const Address& local_out_address, const Address& remote_out_address,
      const Amount& local_amount, const Amount& remote_amount,
      const Txid& fund_tx_id, uint32_t fund_vout, uint32_t n_lock_time);

  /**
   * @brief Create a Mutual Closing Transaction
   *
   * @param local_pubkey the public key of the local party.
   * @param remote_pubkey the public key of the counter party.
   * @param local_amount the amount to local party.
   * @param remote_amount the amount to counter party.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param net_type the network type for creating the addresses.
   * @param n_lock_time the nLockTime for this transaction.
   * @return TransactionController the mutual closing transaction.
   */
  static TransactionController CreateMutualClosingTransaction(
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Amount& local_amount, const Amount& remote_amount,
      const Txid& fund_tx_id, uint32_t fund_vout, NetType net_type,
      uint32_t n_lock_time);

  /**
   * @brief Create a Mutual Closing Transaction
   *
   * @param local_ext_pubkey the extended public key of the local party.
   * @param remote_ext_pubkey the extended public key of the counter-party.
   * @param local_amount the amount to the local party.
   * @param remote_amount the amount to the counter party.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param net_type the network type for creating the addresses.
   * @param n_lock_time the nLockTime for this transaction.
   * @return TransactionController the mutual closing transaction.
   */
  static TransactionController CreateMutualClosingTransaction(
      const ExtPubkey& local_pubkey, const ExtPubkey& remote_pubkey,
      const Amount& local_amount, const Amount& remote_amount,
      const Txid& fund_tx_id, uint32_t fund_vout, NetType net_type,
      uint32_t n_lock_time);

  /**
   * @brief Get the Raw Mutual Closing Tx Signature object
   *
   * @param mutual_closing_tx The transaction for which to get a signature.
   * @param privkey The private key with which to sign.
   * @param fund_lockscript The redeem multi sig script of the fund transaction.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @param input_amount The output value of the fund output.
   * @return ByteData a raw signature.
   */
  static ByteData GetRawMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const Privkey& privkey,
      const Script& fund_lockscript, const Txid& fund_tx_id,
      const uint32_t fund_tx_vout, const Amount& input_amount);

  /**
   * @brief Get the Raw Mutual Closing Tx Signature object
   *
   * @param mutual_closing_tx The transaction for which to get a signature.
   * @param ext_privkey The extended private key with which to sign.
   * @param local_ext_pubkey The extended public key of the local party.
   * @param remote_ext_pubkey The extended public key of the remote party.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @param input_amount The output value of the fund output.
   * @return ByteData a raw signature.
   */
  static ByteData GetRawMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx,
      const ExtPrivkey& ext_privkey, const ExtPubkey& local_ext_pubkey,
      const ExtPubkey& remote_ext_pubkey, const Txid& fund_tx_id,
      const uint32_t fund_tx_vout, const Amount& input_amount);

  /**
   * @brief Get the Raw Mutual Closing Tx Signature object
   *
   * @param mutual_closing_tx The transaction for which to get a signature.
   * @param privkey The private key with which to sign.
   * @param local_pubkey The public key of the local party.
   * @param remote_pubkey The public key of the remote party.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @param input_amount The output value of the fund output.
   * @return ByteData a raw signature.
   */
  static ByteData GetRawMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const Privkey& privkey,
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout,
      const Amount& input_amount);

  /**
   * @brief Add the raw signatures to the mutual closing transaction.
   *
   * @param mutual_closing_tx The transaction
   * @param fund_lockscript The redeem multi sig script of the fund transaction.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @param signatures the signatures to add.
   * @return ByteData a raw signature.
   */
  static void AddSignaturesToMutualClosingTx(
      TransactionController* mutual_closing_tx, const Script& fund_lockscript,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout,
      const std::vector<ByteData>& signatures);

  /**
   * @brief Add the raw signatures to the mutual closing transaction.
   *
   * @param mutual_closing_tx The transaction
   * @param local_ext_pubkey The extended public key of the local party.
   * @param remote_ext_pubkey The extended public key of the remote party.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @param signatures the signatures to add.
   * @return ByteData a raw signature.
   */
  static void AddSignaturesToMutualClosingTx(
      TransactionController* mutual_closing_tx,
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout,
      const std::vector<ByteData>& signatures);

  /**
   * @brief Add the raw signatures to the mutual closing transaction.
   *
   * @param mutual_closing_tx The transaction
   * @param local_pubkey The public key of the local party.
   * @param remote_pubkey The public key of the remote party.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @param signatures the signatures to add.
   * @return ByteData a raw signature.
   */
  static void AddSignaturesToMutualClosingTx(
      TransactionController* mutual_closing_tx, const Pubkey& local_pubkey,
      const Pubkey& remote_pubkey, const Txid& fund_tx_id,
      const uint32_t fund_tx_vout, const std::vector<ByteData>& signatures);

  static bool VerifyMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const ByteData& signature,
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
      bool verify_remote);

  static bool VerifyMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const ByteData& signature,
      const Pubkey& local_pubkey, const Pubkey& remote_pubkey,
      const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
      bool verify_remote);

  static bool VerifyMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const ByteData& signature,
      const Pubkey& pubkey, const Script& lock_script, const Txid& fund_txid,
      uint32_t fund_vout, const Amount& input_amount);
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
      const Pubkey& pubkey_dest, const Amount& amount, const Txid& cet_id,
      uint32_t cet_vout, uint32_t n_lock_time, NetType net_type);

  static TransactionController CreateClosingTransaction(
      const ExtPubkey& ext_pubkey, const Amount& amount, const Txid& cet_id,
      uint32_t cet_vout, uint32_t n_lock_time, NetType net_type);

  static TransactionController CreateClosingTransaction(const Address& address,
                                                        const Amount& amount,
                                                        const Txid& cet_id,
                                                        uint32_t cet_vout,
                                                        uint32_t n_lock_time);

  static void SignClosingTransactionInput(
      TransactionController* closing_transaction,
      const ExtPrivkey& local_ext_privkey, const ExtPubkey& remote_ext_pubkey,
      uint32_t event_index, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static void SignClosingTransactionInput(
      TransactionController* closing_transaction, const Privkey& local_privkey,
      const Pubkey& remote_penalty_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static void SignClosingTransactionInput(
      TransactionController* closing_transaction, const Privkey& local_privkey,
      const ByteData& oracle_sig, const Script& cet_script,
      const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value);

  static TransactionController CreatePenaltyTransaction(
      const Pubkey& pubkey_dest, const Amount& amount, const Txid& cet_id,
      uint32_t cet_vout, uint32_t n_lock_time, NetType net_type);

  static TransactionController CreatePenaltyTransaction(
      const ExtPubkey& ext_pubkey, const Amount& amount, const Txid& cet_id,
      uint32_t cet_vout, uint32_t n_lock_time, NetType net_type);

  static TransactionController CreatePenaltyTransaction(const Address& address,
                                                        const Amount& amount,
                                                        const Txid& cet_id,
                                                        uint32_t cet_vout,
                                                        uint32_t n_lock_time);

  static void SignPenaltyTransactionInput(
      TransactionController* penalty_transaction,
      const ExtPrivkey& remote_ext_privkey, uint32_t event_index,
      const ExtPubkey& local_ext_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value);

  static void SignPenaltyTransactionInput(
      TransactionController* penalty_transaction, const Privkey& remote_privkey,
      const Pubkey& local_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value);

  static void SignPenaltyTransactionInput(
      TransactionController* penalty_transaction, const Privkey& privkey,
      const Script& cet_script, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static ByteData GetRawClosingTransactionSignature(
      const TransactionController& closing_transaction,
      const ExtPrivkey& local_ext_privkey, const ExtPubkey& remote_ext_pubkey,
      uint32_t event_index, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static ByteData GetRawClosingTransactionSignature(
      const TransactionController& closing_transaction,
      const Privkey& local_privkey, const Pubkey& remote_penalty_pubkey,
      const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const ByteData& oracle_sig, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static ByteData GetRawClosingTransactionSignature(
      const TransactionController& closing_transaction,
      const Privkey& local_privkey, const ByteData& oracle_sig,
      const Script& cet_script, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static ByteData GetRawPenaltyTransactionSignature(
      const TransactionController penalty_transaction,
      const ExtPrivkey& remote_ext_privkey, uint32_t event_index,
      const ExtPubkey& local_ext_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value);

  static ByteData GetRawPenaltyTransactionSignature(
      const TransactionController& penalty_transaction,
      const Privkey& remote_privkey, const Pubkey& local_pubkey,
      const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
      const Txid& cet_tx_id, uint32_t cet_vout, const Amount& value);

  static ByteData GetRawPenaltyTransactionSignature(
      const TransactionController& penalty_transaction, const Privkey& privkey,
      const Script& cet_script, const Txid& cet_tx_id, uint32_t cet_vout,
      const Amount& value);

  static void SignFundingTransactionInput(
      TransactionController* funding_transaction, const Privkey& privkey,
      const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value);

  static bool VerifyFundTxSignature(const TransactionController& fund_tx,
                                    const ByteData& signature,
                                    const Pubkey& pubkey, const Txid& prev_txid,
                                    uint32_t prev_vout,
                                    const Amount& input_amount);

  static bool VerifyCetSignature(const TransactionController& cet,
                                 const ByteData& signature,
                                 const ExtPubkey& local_ext_pubkey,
                                 const ExtPubkey& remote_ext_pubkey,
                                 const Txid& fund_txid, uint32_t fund_vout,
                                 const Amount& input_amount,
                                 bool verify_remote);

  static bool VerifyCetSignature(const TransactionController& cet,
                                 const ByteData& signature,
                                 const Pubkey& local_pubkey,
                                 const Pubkey& remote_pubkey,
                                 const Txid& fund_txid, uint32_t fund_vout,
                                 const Amount& input_amount,
                                 bool verify_remote);

  static bool VerifyCetSignature(const TransactionController& cet,
                                 const ByteData& signature,
                                 const Pubkey& pubkey,
                                 const Script& lock_script,
                                 const Txid& fund_txid, uint32_t fund_vout,
                                 const Amount& input_amount);

  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const Privkey& privkey,
      const Script& fund_lockscript, const Txid& fund_tx_id,
      const uint32_t fund_tx_vout, const Amount& input_amount);

  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const ExtPrivkey& ext_privkey,
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout,
      const Amount& input_amount);

  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const Privkey& ext_privkey,
      const Pubkey& local_ext_pubkey, const Pubkey& remote_ext_pubkey,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout,
      const Amount& input_amount);

  static void AddSignaturesToRefundTx(TransactionController* refund_tx,
                                      const Script& fund_lockscript,
                                      const Txid& fund_tx_id,
                                      const uint32_t fund_tx_vout,
                                      const std::vector<ByteData>& signatures);

  static void AddSignaturesToRefundTx(TransactionController* refund_tx,
                                      const ExtPubkey& local_ext_pubkey,
                                      const ExtPubkey& remote_ext_pubkey,
                                      const Txid& fund_tx_id,
                                      const uint32_t fund_tx_vout,
                                      const std::vector<ByteData>& signatures);

  static void AddSignaturesToRefundTx(TransactionController* refund_tx,
                                      const Pubkey& local_ext_pubkey,
                                      const Pubkey& remote_ext_pubkey,
                                      const Txid& fund_tx_id,
                                      const uint32_t fund_tx_vout,
                                      const std::vector<ByteData>& signatures);

  static bool VerifyRefundTxSignature(const TransactionController& refund_tx,
                                      const ByteData& signature,
                                      const ExtPubkey& local_ext_pubkey,
                                      const ExtPubkey& remote_ext_pubkey,
                                      const Txid& fund_txid, uint32_t fund_vout,
                                      const Amount& input_amount,
                                      bool verify_remote);

  static bool VerifyRefundTxSignature(const TransactionController& refund_tx,
                                      const ByteData& signature,
                                      const Pubkey& local_pubkey,
                                      const Pubkey& remote_pubkey,
                                      const Txid& fund_txid, uint32_t fund_vout,
                                      const Amount& input_amount,
                                      bool verify_remote);

  static bool VerifyRefundTxSignature(const TransactionController& refund_tx,
                                      const ByteData& signature,
                                      const Pubkey& pubkey,
                                      const Script& lock_script,
                                      const Txid& fund_txid, uint32_t fund_vout,
                                      const Amount& input_amount);

  static void AddSignaturesToCet(TransactionController* cet,
                                 const Txid& fund_tx_id, uint32_t fund_tx_vout,
                                 const Script& fund_lock_script,
                                 const std::vector<ByteData>& signatures);

  static void AddSignaturesToCet(TransactionController* cet,
                                 const Txid& fund_tx_id, uint32_t fund_tx_vout,
                                 const Pubkey& local_pubkey,
                                 const Pubkey& remote_pubkey,
                                 const std::vector<ByteData>& signatures);

  static void AddSignaturesToCet(TransactionController* cet,
                                 const Txid& fund_tx_id, uint32_t fund_tx_vout,
                                 const ExtPubkey& local_ext_pubkey,
                                 const ExtPubkey& remote_ext_pubkey,
                                 const std::vector<ByteData>& signatures);

  static ByteData GetRawCetSignature(const TransactionController& cet,
                                     const ExtPrivkey& ext_privkey,
                                     const Txid& fund_tx_id,
                                     uint32_t fund_tx_vout,
                                     const ExtPubkey& local_ext_pubkey,
                                     const ExtPubkey& remote_ext_pubkey,
                                     const Amount& fund_amount);

  static ByteData GetRawCetSignature(
      const TransactionController& cet, const Privkey& privkey,
      const Txid& fund_tx_id, uint32_t fund_tx_vout, const Pubkey& local_pubkey,
      const Pubkey& remote_pubkey, const Amount& fund_amount);

  static ByteData GetRawCetSignature(const TransactionController& cet,
                                     const Privkey& privkey,
                                     const Txid& fund_tx_id,
                                     uint32_t fund_tx_vout,
                                     const Script& fund_tx_lockscript,
                                     const Amount& fund_amount);

  static ByteData GetRawFundingTransactionInputSignature(
      const TransactionController& funding_transaction, const Privkey& privkey,
      const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value);
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
      const std::vector<DlcOutcome>& outcomes, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      const Amount& local_input_amount, const Amount& local_collateral_amount,
      const Amount& remote_input_amount, const Amount& remote_collateral_amount,
      int64_t timeout, const std::vector<TxIn>& local_inputs,
      const Address& local_change_address,
      const std::vector<TxIn>& remote_inputs,
      const Address& remote_change_address, uint32_t fee_rate,
      uint32_t maturity_time, uint32_t n_lock_time, const NetType& net_type);
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
  static Script CreateCetRedeemScript(
      const ExtPubkey& local_ext_pubkey, uint32_t event_index,
      const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string> messages, uint64_t delay,
      const ExtPubkey& remote_ext_pubkey);

  static Script CreateCetRedeemScript(
      const Pubkey& local_pubkey, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string> messages, uint64_t delay,
      const Pubkey& remote_penalty_pubkey);

  static Pubkey DeriveFundTxPubkey(const ExtPubkey& parent_key);
  static Pubkey DeriveRefundTxPubkey(const ExtPubkey& parent_key);
  static Pubkey DeriveCetPubkey(const ExtPubkey& parent_key,
                                uint32_t event_index, uint32_t key_index);
  static Pubkey DeriveMutualClosingTxPubkey(const ExtPubkey& parent_key);
  static Pubkey DeriveClosingTxPubkey(const ExtPubkey& parent_key);
  static Pubkey DerivePenaltyTxPubkey(const ExtPubkey& parent_key);
  static Privkey DeriveFundTxPrivkey(const ExtPrivkey& parent_key);
  static Privkey DeriveRefundTxPrivkey(const ExtPrivkey& parent_key);
  static Privkey DeriveCetPrivkey(const ExtPrivkey& parent_key,
                                  uint32_t event_index, uint32_t key_index);
  static Privkey DeriveMutualClosingTxPrivkey(const ExtPrivkey& parent_key);
  static Privkey DeriveClosingTxPrivkey(const ExtPrivkey& parent_key);
  static Privkey DerivePenaltyTxPrivkey(const ExtPrivkey& parent_key);

 private:
  static TransactionController CreateFundTransaction(
      const ExtPubkey& local_ext_pubkey, const ExtPubkey& remote_ext_pubkey,
      const Amount& local_input_amount, const Amount& local_collateral_amount,
      const Amount& remote_input_amount, const Amount& remote_collateral_amount,
      const std::vector<TxIn>& local_inputs,
      const Address& local_change_address,
      const std::vector<TxIn>& remote_inputs,
      const Address& remote_change_address, uint32_t fee_rate,
      uint32_t n_lock_time);

  static int32_t GetChangeValue(const Amount& input_amount,
                                const Amount& collateral_amount,
                                const Amount& fund_fee,
                                const Amount& cet_closing_fee);
  static uint32_t GetTotalInputSize(const std::vector<TxIn>& inputs);
  static void AddOutputIfNotDust(TransactionController* transaction,
                                 const TxOut& output);
  static ByteData GetRawTxWitSigAllSignature(
      const TransactionController& transaction, const Privkey& privkey,
      const Txid& prev_tx_id, uint32_t prev_tx_vout, const Script& lockscript,
      const Amount& amount);

  static void AddSignaturesForMultiSigInput(
      TransactionController* transaction, const Txid& prev_tx_id,
      uint32_t prev_tx_vout, const Script& multisig_script,
      const std::vector<ByteData>& signatures);
};

}  // namespace dlc
}  // namespace cfd

#endif  // DLC_DLC_TRANSACTIONS_H_
