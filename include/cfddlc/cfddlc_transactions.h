// Copyright 2019 CryptoGarage

#ifndef CFD_DLC_INCLUDE_CFDDLC_CFDDLC_TRANSACTIONS_H_
#define CFD_DLC_INCLUDE_CFDDLC_CFDDLC_TRANSACTIONS_H_

#include <string>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfddlc/cfddlc_common.h"

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
struct CFD_DLC_EXPORT DlcTransactions {
  /**
   * @brief The fund transaction
   *
   */
  TransactionController fund_transaction;
  /**
   * @brief The set of CETs for the local party.
   *
   */
  std::vector<TransactionController> local_cets;
  /**
   * @brief The set of CETs for the remote party.
   *
   */
  std::vector<TransactionController> remote_cets;
  /**
   * @brief The refund transaction.
   *
   */
  TransactionController refund_transaction;
};

/**
 * @brief A structure representing a single outcome of a DLC.
 *
 */
struct CFD_DLC_EXPORT DlcOutcome {
  /**
   * @brief The set of messages representing the outcome.
   *
   */
  std::vector<std::string> messages;
  /**
   * @brief The payout for the local party.
   *
   */
  Amount local_payout;
  /**
   * @brief The payout for the remote party.
   *
   */
  Amount remote_payout;
};

/**
 * @brief Class providing utility functions to create DLC transactions.
 *
 */
class CFD_DLC_EXPORT DlcManager {
 public:
  /**
   * @brief Create a Cet object
   *
   * @param local_fund_pubkey the local party's public key used in the multisig
   * output of the fund transaction.
   * @param local_sweep_pubkey the local party's sweep public key.
   * @param remote_sweep_pubkey the remote party's sweep public key.
   * @param remote_final_address the address of the counter party for
   * receiving their payout.
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the r points with which the oracle will sign the
   * outcome message.
   * @param messages the messages that this CET is for.
   * @param csv_delay the number of blocks after which the penalty transaction
   * can be used.
   * @param local_payout the payout to the local party.
   * @param remote_payout the payout the the remote party.
   * @param maturity_time the maturity time of the contract before which the
   * created CET cannot be broadcast.
   * @param fee_rate the fee rate to use to determine if an output will be
   * considered as dust.
   * @param fund_tx_id the ID of the fund transaction.
   * @param fund_vout the vout of the fund transaction output.
   * @return TransactionController the created CET.
   */
  static TransactionController CreateCet(
      const Pubkey& local_fund_pubkey, const Pubkey& local_sweep_pubkey,
      const Pubkey& remote_sweep_pubkey, const Address& remote_final_address,
      const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint64_t csv_delay,
      const Amount& local_payout, const Amount& remote_payout,
      uint32_t maturity_time, uint32_t fee_rate, const Txid& fund_tx_id,
      uint32_t fund_vout = 0);

  /**
   * @brief Create a Cet object
   *
   * @param cet_script the cet script.
   * @param remote_final_address the address for the remote payout.
   * @param local_payout the local payout.
   * @param remote_payout the remote payout.
   * @param maturity_time the maturity time of the contract before which the
   * @param fee_rate the fee rate to use to determine if an output should be
   * considered dust.
   * @param fund_txid the ID of the fund transaction.
   * @param fund_vout the output number within the fund transaction.
   * created CET cannot be broadcast.
   * @return TransactionController the created CET
   */
  static TransactionController CreateCet(
      const Script& cet_script, const Address& remote_final_address,
      const Amount& local_payout, const Amount& remote_payout,
      uint32_t maturity_time, uint32_t fee_rate, const Txid& fund_txid,
      uint32_t fund_vout = 0);

  /**
   * @brief Create a Fund Transaction
   *
   * @param local_fund_pubkey the public key of the party that might submit the
   * transaction.
   * @param remote_fund_pubkey the public key of the counter-party.
   * @param output_amount the amount to direct to the multisig output.
   * @param local_inputs the set of inputs used for funding by the local party.
   * @param local_change_output the change output to the local party.
   * @param remote_inputs the set of inputs used for funding by the
   * counter-party.
   * @param remote_change_output the change output to the
   * counter-party.
   * @param fee_rate the fee rate to use to determine is an output should be
   * considered dust.
   * @return TransactionController the created fund transaction.
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& output_amount, const std::vector<TxIn>& local_inputs,
      const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
      const TxOut& remote_change_output, const uint32_t fee_rate);

  /**
   * @brief Create a Fund Tx Locking Script object
   * @param local_fund_pubkey the public key of the local party.
   * @param remote_fund_pubkey the public key of the remote party.
   *
   * @return Script the multi sig lock script.
   */
  static Script CreateFundTxLockingScript(const Pubkey& local_fund_pubkey,
                                          const Pubkey& remote_fund_pubkey);
  /**
   * @brief Create a Refund Transaction
   *
   * @param local_final_address the address of the local party.
   * @param remote_final_address the public key of the remote party.
   * @param local_amount the amount to be refunded to the local party.
   * @param remote_amount the amount to be refunded to the counter party.
   * @param lock_time the time after which this transaction can be included in
   * the blockchain.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @return TransactionController the refund transaction.
   */
  static TransactionController CreateRefundTransaction(
      const Address& local_final_address, const Address& remote_final_address,
      const Amount& local_amount, const Amount& remote_amount,
      uint32_t lock_time, const Txid& fund_tx_id, uint32_t fund_vout = 0);

  /**
   * @brief Create a Mutual Closing Transaction
   *
   * @param local_final_address the address of the local party.
   * @param remote_final_address the public key of the counter party.
   * @param local_amount the amount to the local party.
   * @param remote_amount the amount to the counter party.
   * @param fee_rate the fee rate to use to determine is an output should be
   * considered dust.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @return TransactionController the mutual closing transaction.
   */
  static TransactionController CreateMutualClosingTransaction(
      const Address& local_final_address, const Address& remote_final_address,
      const Amount& local_amount, const Amount& remote_amount,
      uint32_t fee_rate, const Txid& fund_tx_id, uint32_t fund_vout = 0);

  /**
   * @brief Get the Raw Mutual Closing Tx Signature object
   *
   * @param mutual_closing_tx The transaction for which to get a signature.
   * @param privkey The private key with which to sign.
   * @param fund_lockscript The redeem multi sig script of the fund transaction.
   * @param input_amount The output value of the fund output.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @return ByteData a raw signature.
   */
  static ByteData GetRawMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const Privkey& privkey,
      const Script& fund_lockscript, const Amount& input_amount,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout = 0);

  /**
   * @brief Get the Raw Mutual Closing Tx Signature object
   *
   * @param mutual_closing_tx The transaction for which to get a signature.
   * @param privkey The private key with which to sign.
   * @param local_fund_pubkey The public key of the local party.
   * @param remote_fund_pubkey The public key of the remote party.
   * @param input_amount The output value of the fund output.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   * @return ByteData a raw signature.
   */
  static ByteData GetRawMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const Privkey& privkey,
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& input_amount, const Txid& fund_tx_id,
      const uint32_t fund_tx_vout = 0);

  /**
   * @brief Add the raw signatures to the mutual closing transaction.
   *
   * @param mutual_closing_tx The transaction
   * @param fund_lockscript The redeem multi sig script of the fund transaction.
   * @param signatures the signatures to add.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   */
  static void AddSignaturesToMutualClosingTx(
      TransactionController* mutual_closing_tx, const Script& fund_lockscript,
      const std::vector<ByteData>& signatures, const Txid& fund_tx_id,
      const uint32_t fund_tx_vout);

  /**
   * @brief Add the raw signatures to the mutual closing transaction.
   *
   * @param mutual_closing_tx The transaction
   * @param local_fund_pubkey The public key of the local party.
   * @param remote_fund_pubkey The public key of the remote party.
   * @param signatures the signatures to add.
   * @param fund_tx_id The ID of the fund transaction.
   * @param fund_tx_vout The vout of the multisig output in the fund
   * transaction.
   */
  static void AddSignaturesToMutualClosingTx(
      TransactionController* mutual_closing_tx, const Pubkey& local_fund_pubkey,
      const Pubkey& remote_fund_pubkey, const std::vector<ByteData>& signatures,
      const Txid& fund_tx_id, const uint32_t fund_tx_vout);

  /**
   * @brief Verify the signature of a mutual closing transaction.
   *
   * @param mutual_closing_tx the mutual closing transaction.
   * @param signature the signature to verify.
   * @param local_fund_pubkey the public key of the local party.
   * @param remote_fund_pubkey the public key of the remote party.
   * @param fund_txid the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param input_amount the value of the fund output.
   * @param verify_remote whether the signature is from the remote party or not.
   * @return true if the signature is valid.
   * @return false if the signature is invalid.
   */
  static bool VerifyMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const ByteData& signature,
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& input_amount, const Txid& fund_txid, uint32_t fund_vout = 0,
      bool verify_remote = true);

  /**
   * @brief Verify the signature of a mutual closing transaction.
   *
   * @param mutual_closing_tx the mutual closing transaction.
   * @param signature the signature to verify.
   * @param pubkey the public key against which to verify the signature.
   * @param lock_script the multisig lock script of the fund output.
   * @param fund_txid the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @param input_amount the value of the fund output.
   * @return true if the signature is valid.
   * @return false if the signature is invalid.
   */
  static bool VerifyMutualClosingTxSignature(
      const TransactionController& mutual_closing_tx, const ByteData& signature,
      const Pubkey& pubkey, const Script& lock_script,
      const Amount& input_amount, const Txid& fund_txid,
      uint32_t fund_vout = 0);

  /**
   * @brief Create a Closing Transaction object
   *
   * @param address the destination address for the output.
   * @param amount the output value.
   * @param cet_id the id of the CET this closing transaction refers to.
   * @param cet_vout the output index in the CET.
   * @return TransactionController
   */
  static TransactionController CreateClosingTransaction(const Address& address,
                                                        const Amount& amount,
                                                        const Txid& cet_id,
                                                        uint32_t cet_vout = 0);

  /**
   * @brief Sign a closing transaction input.
   *
   * @param closing_transaction the transaction to sign.
   * @param local_fund_privkey the local party private key that was used in
   * the fund transaction.
   * @param local_sweep_pubkey the local party sweep public key.
   * @param remote_sweep_pubkey the remote party sweep public key.
   * @param oracle_public_key the oracle public key.
   * @param oracle_r_points the oracle r points.
   * @param messages the messages representing the contract outcome.
   * @param csv_delay the delay after which the remote party can take over the
   * funds.
   * @param oracle_sigs the oracle signatures over the messages.
   * @param value the value of the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the output index in the CET.
   */
  static void SignClosingTransactionInput(
      TransactionController* closing_transaction,
      const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
      const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t csv_delay,
      const std::vector<ByteData>& oracle_sigs, const Amount& value,
      const Txid& cet_tx_id, uint32_t cet_vout = 0);

  /**
   * @brief Sign a closing transaction input.
   *
   * @param closing_transaction the transaction to sign.
   * @param local_fund_privkey the local party private key that was used in
   * the fund transaction.
   * @param local_sweep_pubkey the local party sweep public key.
   * @param oracle_sigs the oracle signatures over the messages.
   * @param cet_script the locking script of the CET output
   * @param value the value of the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the output index in the CET.
   */
  static void SignClosingTransactionInput(
      TransactionController* closing_transaction,
      const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
      const std::vector<ByteData>& oracle_sigs, const Script& cet_script,
      const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout = 0);

  /**
   * @brief Create a Penalty Transaction.
   *
   * @param address the destination address for the transaction output.
   * @param amount the output amount.
   * @param cet_id the id of the CET.
   * @param cet_vout the output index in the CET.
   * @return TransactionController representing the penalty transaction.
   */
  static TransactionController CreatePenaltyTransaction(const Address& address,
                                                        const Amount& amount,
                                                        const Txid& cet_id,
                                                        uint32_t cet_vout = 0);

  /**
   * @brief Sign a penalty transaction input.
   *
   * @param penalty_transaction the transaction to sign.
   * @param remote_sweep_privkey the private key used to sign.
   * @param local_fund_pubkey the local party's public key.
   * @param local_sweep_pubkey the local party's sweep key.
   * @param oracle_public_key the oracle public key.
   * @param oracle_r_points the oracle r points.
   * @param messages the messages signed by the oracle.
   * @param csv_delay the delay after which the remote party can claim the local
   * party output.
   * @param value the output value.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the output index in the CET.
   */
  static void SignPenaltyTransactionInput(
      TransactionController* penalty_transaction,
      const Privkey& remote_sweep_privkey, const Pubkey& local_fund_pubkey,
      const Pubkey& local_sweep_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t csv_delay,
      const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout = 0);

  /**
   * @brief
   *
   * @param penalty_transaction the transaction to sign.
   * @param privkey the private key to sign with.
   * @param cet_script the script of the CET.
   * @param value the amount in the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the output index in the CET.
   */
  static void SignPenaltyTransactionInput(
      TransactionController* penalty_transaction, const Privkey& privkey,
      const Script& cet_script, const Amount& value, const Txid& cet_tx_id,
      uint32_t cet_vout = 0);

  /**
   * @brief Get a raw signature (non DER encoded) for a closing transaction.
   *
   * @param closing_transaction the transaction to get the signature for.
   * @param local_fund_privkey the private key to sign with.
   * @param local_sweep_pubkey the local party sweep key.
   * @param remote_sweep_pubkey the remote party sweep key.
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the oracle r points.
   * @param messages the messages signed by the oracle.
   * @param csv_delay the delay after which the remote party can claim the local
   * party output.
   * @param oracle_sigs the signatures from the oracle.
   * @param value the value in the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the index of the CET output.
   * @return ByteData the signature.
   */
  static ByteData GetRawClosingTransactionSignature(
      const TransactionController& closing_transaction,
      const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
      const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t csv_delay,
      const std::vector<ByteData>& oracle_sigs, const Amount& value,
      const Txid& cet_tx_id, uint32_t cet_vout = 0);

  /**
   * @brief Get the Raw Closing Transaction Signature object
   *
   * @param closing_transaction
   * @param local_fund_privkey the private key to sign with.
   * @param local_sweep_pubkey the local party sweep key.
   * @param oracle_sigs the signatures from the oracle.
   * @param cet_script the CET script.
   * @param value the value in the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the index of the CET output.
   * @return ByteData the signature.
   */
  static ByteData GetRawClosingTransactionSignature(
      const TransactionController& closing_transaction,
      const Privkey& local_fund_privkey, const Pubkey& local_sweep_pubkey,
      const std::vector<ByteData>& oracle_sigs, const Script& cet_script,
      const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout = 0);

  /**
   * @brief Get the Raw Penalty Transaction Signature object
   *
   * @param penalty_transaction the transaction to get a signature for.
   * @param remote_sweep_privkey the private key to sign with.
   * @param local_fund_pubkey the local party pubkey used for the multisig
   * script in the fund transaction.
   * @param local_sweep_pubkey the local party sweep key.
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the oracle r points.
   * @param messages the messages signed by the oracle.
   * @param csv_delay the delay after which the remote party can claim the local
   * party output.
   * @param value the value in the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the index of the CET output.
   * @return ByteData
   */
  static ByteData GetRawPenaltyTransactionSignature(
      const TransactionController& penalty_transaction,
      const Privkey& remote_sweep_privkey, const Pubkey& local_fund_pubkey,
      const Pubkey& local_sweep_pubkey, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t csv_delay,
      const Amount& value, const Txid& cet_tx_id, uint32_t cet_vout = 0);

  /**
   * @brief Get a raw signature for a penalty transaction.
   *
   * @param penalty_transaction the transaction to get the signature for.
   * @param privkey the private key to sign with.
   * @param cet_script the CET script.
   * @param value the CET output value.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the index of the CET output.
   * @return ByteData the signature.
   */
  static ByteData GetRawPenaltyTransactionSignature(
      const TransactionController& penalty_transaction, const Privkey& privkey,
      const Script& cet_script, const Amount& value, const Txid& cet_tx_id,
      uint32_t cet_vout = 0);

  /**
   * @brief Sign a funding transaction input.
   *
   * @param fund_transaction the funding transaction to sign.
   * @param privkey the private key to sign with.
   * @param prev_tx_id the id of the previous transaction.
   * @param prev_tx_vout the index of the previous transaction output.
   * @param value the value of the previous transaction output.
   */
  static void SignFundTransactionInput(TransactionController* fund_transaction,
                                       const Privkey& privkey,
                                       const Txid& prev_tx_id,
                                       uint32_t prev_tx_vout,
                                       const Amount& value);

  /**
   * @brief Adds a signature for an input of the fund transaction.
   *
   * @param fund_transaction the fund transaction to add the signature to.
   * @param signature the signature to add.
   * @param pubkey the public key against which the signature is valid.
   * @param prev_tx_id the id of the transaction containing the input.
   * @param prev_tx_vout the vout for the input.
   */
  static void AddSignatureToFundTransaction(
      TransactionController* fund_transaction, const ByteData& signature,
      const Pubkey& pubkey, const Txid& prev_tx_id, uint32_t prev_tx_vout);

  /**
   * @brief Verify that a signature for a fund transaction is valid.
   *
   * @param fund_tx the transaction for which the signature was made.
   * @param signature the signature to verify.
   * @param pubkey the public key to verify the signature against.
   * @param prev_txid the id of the previous transaction.
   * @param prev_vout the index of the output in the previous transaction.
   * @param input_amount the amount in the previous transaction output.
   * @return true if the signature is valid.
   * @return false if the signature is invalid.
   */
  static bool VerifyFundTxSignature(const TransactionController& fund_tx,
                                    const ByteData& signature,
                                    const Pubkey& pubkey, const Txid& prev_txid,
                                    uint32_t prev_vout,
                                    const Amount& input_amount);

  /**
   * @brief
   *
   * @param cet the transaction to verify the signature against.
   * @param signature the signature to verify.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param input_amount the input amount.
   * @param fund_txid the id of the fund transaction
   * @param fund_vout the vout of the fund output.
   * @param verify_remote whether to verify the signature for the remote party
   * (if true) of the local party (if false).
   * @return true
   * @return false
   */
  static bool VerifyCetSignature(const TransactionController& cet,
                                 const ByteData& signature,
                                 const Pubkey& local_fund_pubkey,
                                 const Pubkey& remote_fund_pubkey,
                                 const Amount& input_amount,
                                 const Txid& fund_txid, uint32_t fund_vout = 0,
                                 bool verify_remote = true);

  /**
   * @brief
   *
   * @param cets the transactions to verify the signatures against.
   * @param signatures the signatures to verify.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param input_amount the input amount.
   * @param fund_txid the id of the fund transaction
   * @param fund_vout the vout of the fund output.
   * @param verify_remote whether to verify the signature for the remote party
   * (if true) of the local party (if false).
   * @return true
   * @return false
   */
  static bool VerifyCetSignatures(
      const std::vector<TransactionController>& cets,
      const std::vector<ByteData>& signatures, const Pubkey& local_fund_pubkey,
      const Pubkey& remote_fund_pubkey, const Amount& input_amount,
      const Txid& fund_txid, uint32_t fund_vout = 0, bool verify_remote = true);

  /**
   * @brief
   *
   * @param cet the transaction for which the signature must be verified.
   * @param signature the signature to verify.
   * @param pubkey the public key to verify the signature against.
   * @param lock_script the lock script of the fund transaction.
   * @param input_amount the amount locked in the fund transaction output.
   * @param fund_txid the id of the fund transaction.
   * @param fund_vout the vout of the fund transaction output (defaults to
   * 0).
   * @return true if the signature is valid.
   * @return false otherwise.
   */
  static bool VerifyCetSignature(const TransactionController& cet,
                                 const ByteData& signature,
                                 const Pubkey& pubkey,
                                 const Script& lock_script,
                                 const Amount& input_amount,
                                 const Txid& fund_txid, uint32_t fund_vout = 0);

  /**
   * @brief Get the Raw Refund Tx Signature object
   *
   * @param refund_tx transaction for which to produce a signature.
   * @param privkey the private key to produce the signature.
   * @param fund_lockscript the locking script of the fund transaction
   * output.
   * @param input_amount the amount locked in the fund transaction output.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the fund transaction output (defaults to
   * 0).
   * @return ByteData the produced raw signature.
   */
  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const Privkey& privkey,
      const Script& fund_lockscript, const Amount& input_amount,
      const Txid& fund_tx_id, const uint32_t fund_vout = 0);

  /**
   * @brief Get the Raw Refund Tx Signature object
   *
   * @param refund_tx transaction for which to produce a signature.
   * @param privkey the private key to produce the signature.
   * @param local_fund_pubkey the fund public key of local party.
   * @param remote_fund_pubkey the fund public key of remote party.
   * @param input_amount the amount locked in the fund transaction output.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the fund transaction output (defaults to
   * 0).
   * @return ByteData the produced raw signature.
   */
  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const Privkey& privkey,
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& input_amount, const Txid& fund_tx_id,
      const uint32_t fund_vout = 0);

  /**
   * @brief
   *
   * @param refund_tx the transaction to add the signatures to.
   * @param fund_lockscript the locking script of the fund transaction.
   * @param signatures the signatures to add.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_tx_vout the vout of the fund transaction output.
   */
  static void AddSignaturesToRefundTx(TransactionController* refund_tx,
                                      const Script& fund_lockscript,
                                      const std::vector<ByteData>& signatures,
                                      const Txid& fund_tx_id,
                                      const uint32_t fund_tx_vout = 0);

  /**
   * @brief
   *
   * @param refund_tx the transaction to add the signatures to.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param signatures the signatures to add.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_tx_vout the vout of the fund transaction output.
   */
  static void AddSignaturesToRefundTx(TransactionController* refund_tx,
                                      const Pubkey& local_fund_pubkey,
                                      const Pubkey& remote_fund_pubkey,
                                      const std::vector<ByteData>& signatures,
                                      const Txid& fund_tx_id,
                                      const uint32_t fund_tx_vout);

  /**
   * @brief
   *
   * @param refund_tx the transaction for which to verify the signature.
   * @param signature the signature to verify.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param input_amount the amount locked in the fund transcation output.
   * @param verify_remote whether to verify the signature using the remote
   * party public key (if true) or the local party public key (if false).
   * @param fund_txid the id of the fund transaction.
   * @param fund_vout the vout of the fund transcation output.
   * @return true if the signature is valid.
   * @return false otherwise.
   */
  static bool VerifyRefundTxSignature(const TransactionController& refund_tx,
                                      const ByteData& signature,
                                      const Pubkey& local_fund_pubkey,
                                      const Pubkey& remote_fund_pubkey,
                                      const Amount& input_amount,
                                      bool verify_remote, const Txid& fund_txid,
                                      uint32_t fund_vout = 0);

  /**
   * @brief
   *
   * @param refund_tx the transaction for which to verify the signature.
   * @param signature the signature to verify.
   * @param pubkey the public key to verify the signature against.
   * @param lock_script the locking script of the fund transaction.
   * @param input_amount the amount locked in the fund transcation output.
   * @param fund_txid the id of the fund transaction.
   * @param fund_vout the vout of the fund transcation output.
   * @return true if the signature is valid.
   * @return false otherwise.
   */
  static bool VerifyRefundTxSignature(const TransactionController& refund_tx,
                                      const ByteData& signature,
                                      const Pubkey& pubkey,
                                      const Script& lock_script,
                                      const Amount& input_amount,
                                      const Txid& fund_txid,
                                      uint32_t fund_vout = 0);

  /**
   * @brief
   *
   * @param cet the transaction to add signatures to.
   * @param fund_lock_script the locking script of the fund transaction
   * output.
   * @param signatures the signatures to add.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_tx_vout the vout of the fund transaction output (defaults
   * to 0).
   */
  static void AddSignaturesToCet(TransactionController* cet,
                                 const Script& fund_lock_script,
                                 const std::vector<ByteData>& signatures,
                                 const Txid& fund_tx_id,
                                 uint32_t fund_tx_vout = 0);

  /**
   * @brief
   *
   * @param cet the transaction to add signatures to.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param signatures the signatures to add.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_tx_vout the vout of the fund transaction output (defaults
   * to 0).
   */
  static void AddSignaturesToCet(TransactionController* cet,
                                 const Pubkey& local_fund_pubkey,
                                 const Pubkey& remote_fund_pubkey,
                                 const std::vector<ByteData>& signatures,
                                 const Txid& fund_tx_id,
                                 uint32_t fund_tx_vout = 0);

  /**
   * @brief Get the Raw Cet Signature object
   *
   * @param cet the transaction to get a signature for.
   * @param privkey the private key to sign with.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param fund_amount the amount locked in the fund transaction output.
   * @param fund_tx_id the fund transaction id.
   * @param fund_tx_vout the vout of the fund transaction output (defaults
   * to 0).
   * @return ByteData the produced signature.
   */
  static ByteData GetRawCetSignature(const TransactionController& cet,
                                     const Privkey& privkey,
                                     const Pubkey& local_fund_pubkey,
                                     const Pubkey& remote_fund_pubkey,
                                     const Amount& fund_amount,
                                     const Txid& fund_tx_id,
                                     uint32_t fund_tx_vout = 0);

  /**
   * @brief Get Raw Cet Signatures for the given set of Cet.
   *
   * @param cets the transactions to get a signature for.
   * @param privkey the private key to sign with.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param fund_amount the amount locked in the fund transaction output.
   * @param fund_tx_id the fund transaction id.
   * @param fund_tx_vout the vout of the fund transaction output (defaults
   * to 0).
   * @return ByteData the produced signature.
   */
  static std::vector<ByteData> GetRawCetSignatures(
      const std::vector<TransactionController>& cets, const Privkey& privkey,
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& fund_amount, const Txid& fund_tx_id,
      uint32_t fund_tx_vout = 0);

  /**
   * @brief Get the Raw Cet Signature object
   *
   * @param cet the transaction to get a signature for.
   * @param privkey the private key to sign with.
   * @param fund_tx_lockscript the locking script of the fund transaction.
   * @param fund_amount the amount locked in the fund transaction output.
   * @param fund_tx_id the fund transaction id.
   * @param fund_tx_vout the vout of the fund transaction output (defaults
   * to 0).
   * @return ByteData the produced signature.
   */
  static ByteData GetRawCetSignature(const TransactionController& cet,
                                     const Privkey& privkey,
                                     const Script& fund_tx_lockscript,
                                     const Amount& fund_amount,
                                     const Txid& fund_tx_id,
                                     uint32_t fund_tx_vout = 0);

  /**
   * @brief Get the Raw Funding Transaction Input Signature object
   *
   * @param funding_transaction the transaction for which to get a signature
   * for.
   * @param privkey the private key to sign with.
   * @param prev_tx_id the id of the transaction being spent.
   * @param prev_tx_vout the vout of the output being spent.
   * @param value the value being spent.
   * @return ByteData the produced signature.
   */
  static ByteData GetRawFundingTransactionInputSignature(
      const TransactionController& funding_transaction, const Privkey& privkey,
      const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value);
  /**
   * @brief Create a set of DLC transactions based on the given parameters.
   * Note that proper fee should be computed ahead of using this function.
   *
   * @param outcomes the possible outcome values.
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the set of R points given by the oracle.
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param local_sweep_pubkey the sweep public key of the local party.
   * @param remote_sweep_pubkey the sweep public key of the remote party.
   * @param local_change_address the change address of the local party.
   * @param remote_change_address the change address of the remote party.
   * @param local_final_address the final address of the local party.
   * @param remote_final_address the final address of the remote party.
   * @param local_input_amount the sum of the local party's input value.
   * @param local_collateral_amount the value of the local party's
   * collateral.
   * @param remote_input_amount the sum of the remote party's input value.
   * @param remote_collateral_amount the value of the remote party's
   * collateral.
   * @param refund_locktime the unix time or block number after which the
   * refund transaction can be used.
   * @param csv_delay the csv delay after which the penalty transaction can be
   * used.
   * @param local_inputs the utxos to use for the local party.
   * @param remote_inputs the utxos to use for the remote party.
   * @param fee_rate the fee rate to compute the fees.
   * @param maturity_time the expiration date of the contract.
   * @return DlcTransactions a struct containing the necessary transaction
   * to establish a DLC.
   */
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome>& outcomes, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Pubkey& local_sweep_pubkey, const Pubkey& remote_sweep_pubkey,
      const Address& local_change_address, const Address& remote_change_address,
      const Address& local_final_address, const Address& remote_final_address,
      const Amount& local_input_amount, const Amount& local_collateral_amount,
      const Amount& remote_input_amount, const Amount& remote_collateral_amount,
      uint64_t refund_locktime, uint64_t csv_delay,
      const std::vector<TxIn>& local_inputs,
      const std::vector<TxIn>& remote_inputs, uint32_t fee_rate,
      uint32_t maturity_time);

  /**
   * @brief Create a Cet Redeem Script object
   *
   * @param local_fund_pubkey the fund public key of the local party.
   * @param local_sweep_pubkey the sweep public key of the local party.
   * @param remote_sweep_pubkey the sweep public key of the remote party.
   * @param oracle_pubkey the public key of the oracle.
   * @param oracle_r_points the R points for the particular event.
   * @param messages the set of messages for the outcome represented by the
   * CET.
   * @param csv_delay the time after which the remote party can claim the "to
   * local" party's output.
   * @return Script
   */
  static Script CreateCetRedeemScript(
      const Pubkey& local_fund_pubkey, const Pubkey& local_sweep_pubkey,
      const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string> messages, uint64_t csv_delay);

 private:
  /**
   * @brief Create a Fund Transaction object
   *
   * @param local_fund_pubkey the fund public key of the local party.
   * @param remote_fund_pubkey the fund public key of the remote party.
   * @param local_input_amount the amount input by the local party.
   * @param local_collateral_amount the collateral amount for the local
   * party.
   * @param remote_input_amount the amount input by the remote party.
   * @param remote_collateral_amount the collateral amount for the remote
   * party.
   * @param local_inputs the inputs for the local party.
   * @param local_change_address the change address for the local party.
   * @param remote_inputs the inputs for the remote party.
   * @param remote_change_address the change address for the remote party.
   * @param fee_rate the fee rate.
   * @return TransactionController the created transaction.
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& local_input_amount, const Amount& local_collateral_amount,
      const Amount& remote_input_amount, const Amount& remote_collateral_amount,
      const std::vector<TxIn>& local_inputs,
      const Address& local_change_address,
      const std::vector<TxIn>& remote_inputs,
      const Address& remote_change_address, uint32_t fee_rate);

  /**
   * @brief Get the total VSize for the given inputs.
   *
   * @param inputs the set of inputs to compute the size of.
   * @return uint32_t the size.
   */
  static uint32_t GetTotalInputVSize(const std::vector<TxIn>& inputs);

  /**
   * @brief Determines whether the given output is a dust output at the given
   * fee rate.
   *
   * @param output the output.
   * @param fee_rate the fee rate to consider.
   * @param extra_size additional size to take into account in the decision
   * (mainly used to add the cost of closing transaction when deciding for a CET
   * output).
   * @return true if the output is dust.
   * @return false otherwise.
   */
  static bool IsDustOutput(const TxOut& output, uint32_t fee_rate,
                           uint32_t extra_size = 0);

  /**
   * @brief Get a raw signature for the given transaction.
   *
   * @param transaction the transaction to get a signature for.
   * @param privkey the private key to sign with.
   * @param prev_tx_id the transaction id of the output being spent.
   * @param prev_tx_vout the vout of the output being spent.
   * @param lockscript the lockscript of the output.
   * @param amount the amount being spent.
   * @return ByteData the raw signature.
   */
  static ByteData GetRawTxWitSigAllSignature(
      const TransactionController& transaction, const Privkey& privkey,
      const Txid& prev_tx_id, uint32_t prev_tx_vout, const Script& lockscript,
      const Amount& amount);

  /**
   * @brief Add signature parameters for an input spending from a multi sig
   * locked output.
   *
   * @param transaction the transaction containing the input.
   * @param prev_tx_id the id of the transaction of the output being spent.
   * @param prev_tx_vout the vout of the output being spent.
   * @param multisig_script the multi sig script.
   * @param signatures the signatures to add.
   */
  static void AddSignaturesForMultiSigInput(
      TransactionController* transaction, const Txid& prev_tx_id,
      uint32_t prev_tx_vout, const Script& multisig_script,
      const std::vector<ByteData>& signatures);
};

}  // namespace dlc
}  // namespace cfd

#endif  // CFD_DLC_INCLUDE_CFDDLC_CFDDLC_TRANSACTIONS_H_
