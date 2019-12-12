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

/**
 * @brief A structure representing a single outcome of a DLC.
 *
 */
struct DlcOutcome {
  std::vector<std::string> messages;
  Amount local_payout;
  Amount remote_payout;
};

/**
 * @brief Class providing utility functions to create DLC transactions.
 *
 */
class DlcManager {
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
   * @param delay the number of blocks after which the penalty transaction can
   * be used.
   * @param local_payout the payout to the local party.
   * @param remote_payout the payout the the remote party.
   * @param maturity_time the maturity time of the contract before which the
   * created CET cannot be broadcast.
   * @param fund_tx_id the ID of the fund transaction.
   * @param fund_vout the vout of the fund transaction output.
   * @return TransactionController the created CET.
   */
  static TransactionController CreateCet(
      const Pubkey& local_fund_pubkey, const Pubkey& local_sweep_pubkey,
      const Pubkey& remote_sweep_pubkey, const Address& remote_final_address,
      const Pubkey& oracle_pubkey, const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint64_t delay,
      const Amount& local_payout, const Amount& remote_payout,
      uint32_t maturity_time, const Txid& fund_tx_id, uint32_t fund_vout = 0);

  /**
   * @brief Create a Cet object
   *
   * @param cet_script the cet script.
   * @param remote_final_address the address for the remote payout.
   * @param local_payout the local payout.
   * @param remote_payout the remote payout.
   * @param fund_txid the ID of the fund transaction.
   * @param fund_vout the output number within the fund transaction.
   * @param maturity_time the maturity time of the contract before which the
   * created CET cannot be broadcast.
   * @return TransactionController the created CET
   */
  static TransactionController CreateCet(
      const Script& cet_script, const Address& remote_final_address,
      const Amount& local_payout, const Amount& remote_payout,
      const Txid& fund_txid, uint32_t fund_vout, uint32_t maturity_time);

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
   * @return TransactionController the created fund transaction.
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& output_amount, const std::vector<TxIn>& local_inputs,
      const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
      const TxOut& remote_change_output);

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
      uint32_t lock_time, const Txid& fund_tx_id, uint32_t fund_vout);

  /**
   * @brief Create a Mutual Closing Transaction
   *
   * @param local_final_address the address of the local party.
   * @param remote_final_address the public key of the counter party.
   * @param local_amount the amount to the local party.
   * @param remote_amount the amount to the counter party.
   * @param fund_tx_id the id of the fund transaction.
   * @param fund_vout the vout of the multisig output in the fund transaction.
   * @return TransactionController the mutual closing transaction.
   */
  static TransactionController CreateMutualClosingTransaction(
      const Address& local_final_address, const Address& remote_final_address,
      const Amount& local_amount, const Amount& remote_amount,
      const Txid& fund_tx_id, uint32_t fund_vout);

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
   * @return ByteData a raw signature.
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
   * @return ByteData a raw signature.
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
      const Txid& fund_txid, uint32_t fund_vout, const Amount& input_amount,
      bool verify_remote);

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
      const Pubkey& pubkey, const Script& lock_script, const Txid& fund_txid,
      uint32_t fund_vout, const Amount& input_amount);

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
   * @param delay the delay after which the remote party can take over the
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
      const std::vector<std::string>& messages, uint32_t delay,
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
   * @param delay the delay after which the remote party can claim the local
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
      const std::vector<std::string>& messages, uint32_t delay,
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
   * @param delay the delay after which the remote party can claim the local
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
      const std::vector<std::string>& messages, uint32_t delay,
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
   * @param delay the delay after which the remote party can claim the local
   * party output.
   * @param value the value in the CET output.
   * @param cet_tx_id the id of the CET.
   * @param cet_vout the index of the CET output.
   * @return ByteData
   */
  static ByteData GetRawPenaltyTransactionSignature(
      const TransactionController& penalty_transaction,
      const Privkey& remote_sweep_privkey, const Pubkey& local_fund_pubkey,
      const Pubkey& local_sweep_pubkey, const Pubkey& oracle_public_key,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string>& messages, uint32_t delay,
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
   * @param funding_transaction the funding transaction to sign.
   * @param privkey the private key to sign with.
   * @param prev_tx_id the id of the previous transaction.
   * @param prev_tx_vout the index of the previous transaction output.
   * @param value the value of the previous transaction output.
   */
  static void SignFundingTransactionInput(
      TransactionController* funding_transaction, const Privkey& privkey,
      const Txid& prev_tx_id, uint32_t prev_tx_vout, const Amount& value);

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
   * @param cet
   * @param signature
   * @param local_fund_pubkey
   * @param remote_fund_pubkey
   * @param input_amount
   * @param fund_txid
   * @param fund_vout
   * @param verify_remote
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
   * @param cet
   * @param signature
   * @param pubkey
   * @param lock_script
   * @param input_amount
   * @param fund_txid
   * @param fund_vout
   * @return true
   * @return false
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
   * @param refund_tx
   * @param privkey
   * @param fund_lockscript
   * @param input_amount
   * @param fund_tx_id
   * @param fund_vout
   * @return ByteData
   */
  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const Privkey& privkey,
      const Script& fund_lockscript, const Amount& input_amount,
      const Txid& fund_tx_id, const uint32_t fund_vout = 0);

  /**
   * @brief Get the Raw Refund Tx Signature object
   *
   * @param refund_tx
   * @param privkey
   * @param local_fund_pubkey
   * @param remote_fund_pubkey
   * @param input_amount
   * @param fund_tx_id
   * @param fund_vout
   * @return ByteData
   */
  static ByteData GetRawRefundTxSignature(
      const TransactionController& refund_tx, const Privkey& privkey,
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& input_amount, const Txid& fund_tx_id,
      const uint32_t fund_vout = 0);

  /**
   * @brief
   *
   * @param refund_tx
   * @param fund_lockscript
   * @param signatures
   * @param fund_tx_id
   * @param fund_tx_vout
   */
  static void AddSignaturesToRefundTx(TransactionController* refund_tx,
                                      const Script& fund_lockscript,
                                      const std::vector<ByteData>& signatures,
                                      const Txid& fund_tx_id,
                                      const uint32_t fund_tx_vout = 0);

  /**
   * @brief
   *
   * @param refund_tx
   * @param local_fund_pubkey
   * @param remote_fund_pubkey
   * @param signatures
   * @param fund_tx_id
   * @param fund_tx_vout
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
   * @param refund_tx
   * @param signature
   * @param local_fund_pubkey
   * @param remote_fund_pubkey
   * @param input_amount
   * @param verify_remote
   * @param fund_txid
   * @param fund_vout
   * @return true
   * @return false
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
   * @param refund_tx
   * @param signature
   * @param pubkey
   * @param lock_script
   * @param input_amount
   * @param fund_txid
   * @param fund_vout
   * @return true
   * @return false
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
   * @param cet
   * @param fund_lock_script
   * @param signatures
   * @param fund_tx_id
   * @param fund_tx_vout
   */
  static void AddSignaturesToCet(TransactionController* cet,
                                 const Script& fund_lock_script,
                                 const std::vector<ByteData>& signatures,
                                 const Txid& fund_tx_id,
                                 uint32_t fund_tx_vout = 0);

  /**
   * @brief
   *
   * @param cet
   * @param local_fund_pubkey
   * @param remote_fund_pubkey
   * @param signatures
   * @param fund_tx_id
   * @param fund_tx_vout
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
   * @param cet
   * @param privkey
   * @param local_fund_pubkey
   * @param remote_fund_pubkey
   * @param fund_amount
   * @param fund_tx_id
   * @param fund_tx_vout
   * @return ByteData
   */
  static ByteData GetRawCetSignature(const TransactionController& cet,
                                     const Privkey& privkey,
                                     const Pubkey& local_fund_pubkey,
                                     const Pubkey& remote_fund_pubkey,
                                     const Amount& fund_amount,
                                     const Txid& fund_tx_id,
                                     uint32_t fund_tx_vout = 0);

  /**
   * @brief Get the Raw Cet Signature object
   *
   * @param cet
   * @param privkey
   * @param fund_tx_lockscript
   * @param fund_amount
   * @param fund_tx_id
   * @param fund_tx_vout
   * @return ByteData
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
   * @param funding_transaction
   * @param privkey
   * @param prev_tx_id
   * @param prev_tx_vout
   * @param value
   * @return ByteData
   */
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
   * @return DlcTransactions a struct containing the necessary transaction to
   * establish a DLC.
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
      int64_t timeout, const std::vector<TxIn>& local_inputs,
      const std::vector<TxIn>& remote_inputs, uint32_t fee_rate,
      uint32_t maturity_time);

  /**
   * @brief Create a Cet Redeem Script object
   *
   * @param local_fund_pubkey
   * @param local_sweep_pubkey
   * @param remote_sweep_pubkey
   * @param oracle_pubkey
   * @param oracle_r_points
   * @param messages
   * @param delay
   * @return Script
   */
  static Script CreateCetRedeemScript(
      const Pubkey& local_fund_pubkey, const Pubkey& local_sweep_pubkey,
      const Pubkey& remote_sweep_pubkey, const Pubkey& oracle_pubkey,
      const std::vector<Pubkey>& oracle_r_points,
      const std::vector<std::string> messages, uint64_t delay);

 private:
  static TransactionController CreateFundTransaction(
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& local_input_amount, const Amount& local_collateral_amount,
      const Amount& remote_input_amount, const Amount& remote_collateral_amount,
      const std::vector<TxIn>& local_inputs,
      const Address& local_change_address,
      const std::vector<TxIn>& remote_inputs,
      const Address& remote_change_address, uint32_t fee_rate);

  static uint32_t GetTotalInputVSize(const std::vector<TxIn>& inputs);
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
