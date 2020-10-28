// Copyright 2019 CryptoGarage

#ifndef CFD_DLC_INCLUDE_CFDDLC_CFDDLC_TRANSACTIONS_H_
#define CFD_DLC_INCLUDE_CFDDLC_CFDDLC_TRANSACTIONS_H_

#include <string>
#include <tuple>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_ecdsa_adaptor.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfddlc/cfddlc_common.h"

namespace cfd {
namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::Txid;
using cfd::TxIn;
using cfd::TxOut;
using cfd::core::AdaptorPair;
using cfd::core::AdaptorProof;
using cfd::core::AdaptorSignature;
using cfd::core::Address;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::NetType;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::SchnorrSignature;

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
   * @brief The set of CETs
   *
   */
  std::vector<TransactionController> cets;
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
 * @brief Contain a transaction input together with the maximum witness length
 * for this input.
 *
 */
struct TxInputInfo {
  /**
   * @brief The transaction input.
   *
   */
  TxIn input;
  /**
   * @brief The maximum length of the witness stack.
   *
   */
  uint32_t max_witness_length;
};

/**
 * @brief Contains the parameters required for creating DLC transactions for a
 * single party. Specifically these are the common fields between Offer and
 * Accept messages.
 *
 */
struct PartyParams {
  /**
   * @brief The public key for the fund multisig script
   *
   */
  Pubkey fund_pubkey;
  /**
   * @brief The script pubkey for the change output.
   *
   */
  Script change_script_pubkey;
  /**
   * @brief The script pubkey for the final output.
   *
   */
  Script final_script_pubkey;
  /**
   * @brief A list of inputs to fund the contract
   *
   */
  std::vector<TxInputInfo> inputs_info;
  /**
   * @brief The total value of the provided inputs
   *
   */
  Amount input_amount;
  /**
   * @brief The collateral put in the contract by the party
   *
   */
  Amount collateral;
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
   * @param local_output the output paying the local party
   * @param remote_output the output paying the remote party
   * @param fund_tx_id the tx id of the funding transaction
   * @param fund_vout the vout of the fund output
   * @param lock_time lock time (optional)
   * @return TransactionController created CET
   */
  static TransactionController CreateCet(const TxOut& local_output,
                                         const TxOut& remote_output,
                                         const Txid& fund_tx_id,
                                         const uint32_t fund_vout,
                                         uint32_t lock_time = 0);
  /**
   * @brief Create a Cets object
   *
   * @param fund_tx_id the tx id of the funding transaction
   * @param fund_vout the vout of the fund output
   * @param local_final_script_pubkey the script for the local payout output.
   * @param remote_final_script_pubkey the script for the remote payout output.
   * @param outcomes the list of possible payouts, one for each possible outcome
   * @param lock_time lock time (optional)
   * @return TransactionController created CETs
   */
  static std::vector<TransactionController> CreateCets(
      const Txid& fund_tx_id, const uint32_t fund_vout,
      const Script& local_final_script_pubkey,
      const Script& remote_final_script_pubkey,
      const std::vector<DlcOutcome> outcomes, uint32_t lock_time = 0);

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
   * @param option_dest (optional) destination address for the payment of the
   * option premium
   * @param option_premium (optional) value for the option premium
   * @param lock_time (optional) the lock time to use
   * @note If option_premium is non zero, the premium_dest value is required, or
   * an exception will be thrown.
   * @return TransactionController the created fund transaction.
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& output_amount, const std::vector<TxIn>& local_inputs,
      const TxOut& local_change_output, const std::vector<TxIn>& remote_inputs,
      const TxOut& remote_change_output, const Address& option_dest = Address(),
      const Amount& option_premium = Amount::CreateBySatoshiAmount(0),
      const uint64_t lock_time = 0);

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
      const Script& local_final_address, const Script& remote_final_address,
      const Amount& local_amount, const Amount& remote_amount,
      uint32_t lock_time, const Txid& fund_tx_id, uint32_t fund_vout = 0);

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
   * @brief Create an Adaptor Signature for a given cet using the provided
   * private key.
   *
   * @param cet the CET to generate the signature for.
   * @param oracle_pubkey the pubkey of the oracle for the associated event.
   * @param oracle_r_values the set of r values that the oracle will use for the
   * associated event.
   * @param funding_sk the private key to generate the signature with.
   * @param funding_script_pubkey the script pubkey of the fund output.
   * @param fund_output_amount the value of the fund output.
   * @param msgs the set of messages for the outcome corresponding to the given
   * CET.
   * @return AdaptorPair an adaptor signature and its dleq proof.
   */
  static AdaptorPair CreateCetAdaptorSignature(
      const TransactionController& cet, const SchnorrPubkey& oracle_pubkey,
      const std::vector<SchnorrPubkey>& oracle_r_values,
      const Privkey& funding_sk, const Script& funding_script_pubkey,
      const Amount& fund_output_amount, const std::vector<ByteData256>& msgs);

  /**
   * @brief Create a Cet Adaptor Signatures object
   *
   * @param cets the cets to generate adaptor signatures for.
   * @param oracle_pubkey the pubkey of the oracle for the associated event.
   * @param oracle_r_values the set of r value that the oracle will use for the
   * associated event.
   * @param funding_sk the private key to generate the signature with.
   * @param funding_script_pubkey the script pubkey of the fund output.
   * @param fund_output_amount the value of the fund output.
   * @param msgs the messages for the outcomes corresponding to the given CETs.
   * @return std::vector<AdaptorPair> a set of signature together with their
   * DLEq proofs.
   */
  static std::vector<AdaptorPair> CreateCetAdaptorSignatures(
      const std::vector<TransactionController>& cets,
      const SchnorrPubkey& oracle_pubkey,
      const std::vector<SchnorrPubkey>& oracle_r_values,
      const Privkey& funding_sk, const Script& funding_script_pubkey,
      const Amount& fund_output_amount,
      const std::vector<std::vector<ByteData256>>& msgs);

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
   * @param adaptor_pair the adaptor signature and its DLEq proof to verify.
   * @param cet the transaction to verify the signature against.
   * @param pubkey the public key to verify the signature against.
   * @param oracle_pubkey the public key of the oracle used for the associated
   * event.
   * @param oracle_r_values the r_values that the oracle will used to create
   * signatures over the outcome of the associated event.
   * @param funding_script_pubkey the script pubkey of the fund output.
   * @param fund_output_amount the value of the fund output.
   * @param msgs the hashes of the value representing the event outcome for the
   * given CET.
   * @return true
   * @return false
   */
  static bool VerifyCetAdaptorSignature(
      const AdaptorPair& adaptor_pair, const TransactionController& cet,
      const Pubkey& pubkey, const SchnorrPubkey& oracle_pubkey,
      const std::vector<SchnorrPubkey>& oracle_r_values,
      const Script& funding_script_pubkey, const Amount& fund_output_amount,
      const std::vector<ByteData256>& msgs);

  /**
   * @brief Sign a CET transaction using a counter party adaptor signature that
   * will be decrypted using the provided oracle signature, and own signature
   * generated using the provided private key.
   *
   * @param cet the CET to which the signatures will be added.
   * @param adaptor_sig the adaptor signature of the counterparty.
   * @param oracle_signatures the set of signatures from the oracle over the
   * corresponding event outcome.
   * @param funding_sk the private key to generate own signature with.
   * @param funding_script_pubkey the script pubkey of the fund output.
   * @param fund_tx_id the transaction id of the fund transactions.
   * @param fund_vout the vout of the fund output.
   * @param fund_output_amount the value of the fund output.
   */
  static void SignCet(TransactionController* cet,
                      const AdaptorSignature& adaptor_sig,
                      const std::vector<SchnorrSignature>& oracle_signatures,
                      const Privkey funding_sk,
                      const Script& funding_script_pubkey,
                      const Txid& fund_tx_id, uint32_t fund_vout,
                      const Amount& fund_output_amount);

  /**
   * @brief
   *
   * @param cets the transactions to verify the signatures against.
   * @param signature_and_proofs the adaptor signatures and their proofs to
   * verify.
   * @param msgs the hash of the events outcome for the given CETs.
   * @param pubkey the public key to verify the signature against.
   * @param oracle_pubkey the public key of the oracle used for the associated
   * event.
   * @param oracle_r_value the r_value that the oracle will used to create a
   * signature over the outcome of the associated event.
   * @param funding_script_pubkey the script pubkey of the fund output.
   * @param fund_output_amount the value of the fund output.
   * @return true
   * @return false
   */
  static bool VerifyCetAdaptorSignatures(
      const std::vector<TransactionController>& cets,
      const std::vector<AdaptorPair>& signature_and_proofs,
      const std::vector<std::vector<ByteData256>>& msgs, const Pubkey& pubkey,
      const SchnorrPubkey& oracle_pubkey,
      const std::vector<SchnorrPubkey>& oracle_r_value,
      const Script& funding_script_pubkey, const Amount& fund_output_amount);

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
   * @param local_params the parameters for the local party.
   * @param remote_params the parameters for the remote party.
   * @param refund_locktime the unix time or block number after which the
   * refund transaction can be used.
   * @param fee_rate the fee rate to compute the fees.
   * @param option_dest (optional) destination address for the payment of the
   * option premium
   * @param option_premium (optional) value for the option premium
   * @param fund_lock_time the lock time to use for the fund transaction
   * (optional)
   * @param cet_lock_time the lock time to use for the cet transactions
   * (optional)
   * @return DlcTransactions a struct containing the necessary transaction
   * to establish a DLC.
   */
  static DlcTransactions CreateDlcTransactions(
      const std::vector<DlcOutcome>& outcomes, const PartyParams& local_params,
      const PartyParams& remote_params, uint64_t refund_locktime,
      uint32_t fee_rate, const Address& option_dest = Address(),
      const Amount& option_premium = Amount::CreateBySatoshiAmount(0),
      const uint64_t fund_lock_time = 0, const uint64_t cet_lock_time = 0);

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
   * @param option_dest (optional) destination address for the payment of the
   * option premium
   * @param option_premium (optional) value for the option premium
   * @return TransactionController the created transaction.
   */
  static TransactionController CreateFundTransaction(
      const Pubkey& local_fund_pubkey, const Pubkey& remote_fund_pubkey,
      const Amount& local_input_amount, const Amount& local_collateral_amount,
      const Amount& remote_input_amount, const Amount& remote_collateral_amount,
      const std::vector<TxIn>& local_inputs,
      const Address& local_change_address,
      const std::vector<TxIn>& remote_inputs,
      const Address& remote_change_address, uint32_t fee_rate,
      const Address& option_dest = Address(),
      const Amount& option_premium = Amount::CreateBySatoshiAmount(0));

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
   * @return true if the output is dust.
   * @return false otherwise.
   */
  static bool IsDustOutput(const TxOut& output);

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

  /**
   * @brief Get the Change Output And Fee for a party.
   *
   * @param params the party parameters
   * @param fee_rate the fee rate to apply
   * @param option_premium the option premium value (optional)
   * @param premium_dest the address where the premium should be sent to.
   * @note If option_premium is non zero, the premium_dest value is required, or
   * an exception will be thrown.
   * @return std::tuple<TxOut, uint64_t, uint64_t>
   */
  static std::tuple<TxOut, uint64_t, uint64_t> GetChangeOutputAndFees(
      const PartyParams& params, uint64_t fee_rate,
      Amount option_premium = Amount::CreateBySatoshiAmount(0),
      Address premium_dest = Address());

  /**
   * @brief Computes an adaptor point from a set of messages, r_values and a
   * public key.
   *
   * @param msgs the messages to use to compute the signature points.
   * @param r_values the r_values to use to compute the signature points.
   * @param pubkey the public key to use to compute the signature points.
   * @return Pubkey the adaptor point corresponding to the sum of the computed
   * signature points.
   */
  static Pubkey ComputeAdaptorPoint(const std::vector<ByteData256>& msgs,
                                    const std::vector<SchnorrPubkey>& r_values,
                                    const SchnorrPubkey& pubkey);
};

}  // namespace dlc
}  // namespace cfd

#endif  // CFD_DLC_INCLUDE_CFDDLC_CFDDLC_TRANSACTIONS_H_
