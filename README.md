# cfd-dlc

Library for creating, signing and verifying signatures for Discrete Logarithm Contracts (DLC).

## Building

### Full build

```
./scripts/build.sh
```

### Building using installed cfd library

(Faster build)
Requires package config

1. Install cfd. (on initial or update only.)

#### Manual install:

```bash
$git clone git@github.com:cryptogarageinc/cfd.git v0.0.24
$cmake -S . -B build
$cmake -DENABLE_SHARED=on -DENABLE_JS_WRAPPER=off -DENABLE_TESTS=off -DTARGET_RPATH=/usr/local/lib -DCMAKE_BUILD_TYPE=Release --build build
$cmake --build build --parallel 4 --config Release
$cd build && sudo make install -j 4
```

Run the following script to cleanup the install files:
`https://github.com/cryptogarageinc/cfd/blob/master/tools/cleanup_install_files.sh`

#### Using released package (faster):

Find the appropriate release for you platform [here](https://github.com/cryptogarageinc/cfd/releases)

```bash
wget https://github.com/cryptogarageinc/cfd/releases/download/v0.0.24/cfd-v0.0.24-{yourplatform}.zip
unzip -d / cfd-v0.0.24-{yourplatform}.zip
```

2. build cfd-dlc (on clean state)

```
./scripts/build.sh
```

## Usage

The library includes two classes.
The first and main one is `DlcManager`, that can be used to create, sign and verify the signatures of transactions for a DLC.
The second one is `DlcUtils` that contain utility functions, including the ability to create oracle signatures using the Schnorr signature scheme.

## Example

### Preliminaries

We first start by defining all the parameters for the contract:

```cpp
const Privkey ORACLE_PRIVKEY(
    "ded9a76a0a77399e1c2676324118a0386004633f16245ad30d172b15c1f9e2d3");
const Pubkey ORACLE_PUBKEY = ORACLE_PRIVKEY.GeneratePubkey();
const Privkey ORACLE_K_VALUE(
    "be3cc8de25c50e25f69e2f88d151e3f63e99c3a44fed2bdd2e3ee70fe141c5c3");
const std::vector<Pubkey> ORACLE_R_POINTS = {
    DlcUtil::GetSchnorrPublicNonce(ORACLE_K_VALUE)};
const ByteData ORACLE_SIGNATURE(
    "8a820c2a94e3f85362c457b80cff914b13fbbd67df49df24181f3b916331a2e6");
const Privkey LOCAL_FUND_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000001");
const Pubkey LOCAL_FUND_PUBKEY = LOCAL_FUND_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_FUND_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000002");
const Pubkey REMOTE_FUND_PUBKEY = REMOTE_FUND_PRIVKEY.GeneratePubkey();
const Privkey LOCAL_SWEEP_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000003");
const Pubkey LOCAL_SWEEP_PUBKEY = LOCAL_SWEEP_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_SWEEP_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000004");
const Pubkey REMOTE_SWEEP_PUBKEY = REMOTE_SWEEP_PRIVKEY.GeneratePubkey();
const Privkey LOCAL_INPUT_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000005");
const Pubkey LOCAL_INPUT_PUBKEY = LOCAL_INPUT_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_INPUT_PRIVKEY(
    "0000000000000000000000000000000000000000000000000000000000000006");
const Pubkey REMOTE_INPUT_PUBKEY = REMOTE_INPUT_PRIVKEY.GeneratePubkey();
const Amount LOCAL_INPUT_AMOUNT = Amount::CreateByCoinAmount(50);
const Amount REMOTE_INPUT_AMOUNT = Amount::CreateByCoinAmount(50);
const Amount LOCAL_COLLATERAL_AMOUNT = Amount::CreateBySatoshiAmount(100000000);
const Amount REMOTE_COLLATERAL_AMOUNT =
    Amount::CreateBySatoshiAmount(100000000);
const Amount FUND_OUTPUT = Amount::CreateBySatoshiAmount(200000312);
const Amount WIN_AMOUNT = Amount::CreateBySatoshiAmount(199900000);
const Amount LOSE_AMOUNT = Amount::CreateBySatoshiAmount(100000);
const std::vector<std::string> WIN_MESSAGES = {"WIN"};
const std::vector<std::string> LOSE_MESSAGES = {"LOSE"};
const std::vector<TxIn> LOCAL_INPUTS = {TxIn(
    Txid("83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"), 0,
    0)};
const std::vector<TxIn> REMOTE_INPUTS = {TxIn(
    Txid("bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"), 0,
    0)};
const Address LOCAL_CHANGE_ADDRESS(
    "bcrt1qlgmznucxpdkp5k3ktsct7eh6qrc4tju7ktjukn");
const Address REMOTE_CHANGE_ADDRESS(
    "bcrt1qvh2dvgjctwh4z5w7sc93u7h4sug0yrdz2lgpqf");
const Address LOCAL_FINAL_ADDRESS(
    NetType::kRegtest, WitnessVersion::kVersion0,
    Privkey("0000000000000000000000000000000000000000000000000000000000000007")
        .GeneratePubkey());
const Address REMOTE_FINAL_ADDRESS(
    NetType::kRegtest, WitnessVersion::kVersion0,
    Privkey("0000000000000000000000000000000000000000000000000000000000000008")
        .GeneratePubkey());
const uint32_t MATURITY_TIME = 1579072156;
const std::vector<DlcOutcome> OUTCOMES = {{WIN_MESSAGES, WIN_AMOUNT, LOSE_AMOUNT},
                                    {LOSE_MESSAGES, LOSE_AMOUNT, WIN_AMOUNT}};
const uint32_t FEE_RATE = 1
```

### Transactions creation

We can then generate the fund transaction, Contract Execution Transactions (CETs) and the refund transaction:

```cpp
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
      OUTCOMES, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
      LOCAL_CHANGE_ADDRESS, REMOTE_CHANGE_ADDRESS, LOCAL_FINAL_ADDRESS,
      REMOTE_FINAL_ADDRESS, LOCAL_INPUT_AMOUNT, LOCAL_COLLATERAL_AMOUNT,
      REMOTE_INPUT_AMOUNT, REMOTE_COLLATERAL_AMOUNT, DELAY, LOCAL_INPUTS,
      REMOTE_INPUTS, FEE_RATE, MATURITY_TIME);
```

### Signing

Next both parties sign the refund transaction:

```cpp
  auto refund_tx = dlc_transactions.refund_transaction;
  auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);

  auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);

  DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_refund_signature, remote_refund_signature}, FUND_TX_ID, 0);
```

Both parties also sign all the CETs:

```cpp
  for (auto cet : dlc_transactions.cets) {
    auto local_cet_signature = DlcManager::GetRawCetSignature(
        cet, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
        FUND_OUTPUT, FUND_TX_ID, 0);
    auto remote_cet_signature = DlcManager::GetRawCetSignature(
        cet, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
        FUND_OUTPUT, FUND_TX_ID, 0);
    DlcManager::AddSignaturesToCet(
        &cet, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
        {local_cet_signature, remote_cet_signature}, FUND_TX_ID, 0);
  }
```

And finally they sign the fund transaction:

```cpp
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundingTransactionInput(&fund_tx, LOCAL_INPUT_PRIVKEY,
                                          LOCAL_INPUTS[0].GetTxid(), 0,
                                          LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundingTransactionInput(&fund_tx, REMOTE_INPUT_PRIVKEY,
                                          REMOTE_INPUTS[0].GetTxid(), 0,
                                          REMOTE_INPUT_AMOUNT);
```

Note that the `GetRawFundingTransactionInputSignature` method can be used to get the raw signature instead of signing the transaction directly.

### Mutual Closing

At contract maturity, they can chose to create and sign a mutual closing transaction:

```cpp
  auto mutual_closing_tx = DlcManager::CreateMutualClosingTransaction(
      LOCAL_FINAL_ADDRESS, REMOTE_FINAL_ADDRESS,
      Amount::CreateBySatoshiAmount(WIN_AMOUNT),
      Amount::CreateBySatoshiAmount(LOSE_AMOUNT), FUND_TX_ID, 0);
  auto local_signature = DlcManager::GetRawMutualClosingTxSignature(
      mutual_closing_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_signature = DlcManager::GetRawMutualClosingTxSignature(
      mutual_closing_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY,
      REMOTE_FUND_PUBKEY, FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToMutualClosingTx(
      &mutual_closing_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_signature, remote_signature}, FUND_TX_ID, 0);
```

Note that they can recover some unspent fee by using the mutual closing transaction, we ignored this here.

### Refund Case

If the oracle doesn't publish the outcome, they can sign the refund transaction:

```cpp
  auto local_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_signature, remote_signature}, FUND_TX_ID, 0);
```

### Unilateral Close

Finally, in case of a unilateral close of the contract, the party closing will need to create and sign a closing transaction corresponding to the outcome signed by the oracle.

```cpp
  auto closing_tx = DlcManager::CreateClosingTransaction(
      LOCAL_FINAL_ADDRESS, WIN_AMOUNT, CET_ID, 0);

  DlcManager::SignClosingTransactionInput(
      &closing_tx, LOCAL_FUND_PRIVKEY, LOCAL_SWEEP_PUBKEY, REMOTE_SWEEP_PUBKEY,
      ORACLE_PUBKEY, ORACLE_R_POINTS, WIN_MESSAGES, DELAY, {ORACLE_SIGNATURE},
      input_amount, CET_ID, 0);
```

Note that you can generate an oracle signature using `DlcUtil::SchnorrSign` function.
