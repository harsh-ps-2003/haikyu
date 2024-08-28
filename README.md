# Haikyu

Haikyu is a Bitcoin miner simulation that demonstrates the process of mining a block, including transaction validation and selection from a mempool.

## Quick Setup Guide

### Prerequisites
- Go 1.16 or later
- SQLite3

### Setup
Run the following script:
```shell
chmod +x run.sh
./run.sh 
#check info.log for results
```

# Workflow explanation
This project has 3 phases of execution in total as described below
### Initialize and Load Txs into [mempool](./internal/mempool/mempool.go)  
entrypoint `main.go` starts by initializing a progressBar which logs number of files processed to stdout, a logger[info level] which is passed down to `miner` and `mempool` services. `main.go` panics on any error occurred during intilizalitation processes. Initialization creates 3 SQL tables For `Transactions` `Inputs` and `OutPoints`

Once mempool is Loaded, entrypoints spins up several `go routines` to load transactions concurrently and save it to db, mempool does several checks on transaction data followed by putting tx into db, these checks are described as below
1. Computes `Txhash` of entire transaction. by `SHA256(SHA256(legacy_tx_serialization))` in Little Endian Format.  legacy_tx_serialization is just a tx serialized without `marker` `flag` and `witness`.
2. Computes `Wtxid` of entire transaction. by `SHA256(SHA256(wtxid serialization))`.
3. Computes `Weight` and `FeeCollected` of entire transaction. by 
    - `weight = legacy bytes * 4 + witness bytes * 1`
    - `fee_collected = SUM(input.value) - SUM(output.value)`
4. if FeeCollected < 546 sats (dust fee limit) then tx is rejected.
5. inputs and outputs are separated from transaction, validated and stored respective tables [batch db writes]
    - validates sequence number if it is less than `absolute` 0xffffffff  then it is marked as RBF.
    - if an outpoint already exists in db then it is ignored.
6. Input and output validation include.
    - For every outpoint assembly Script, it is converted into its Byte representation and validated against. ScriptPubKey_HEX.
    - further script_pubkey is converted into following format and validated with its address
        - `base58` address if it is a legacy outpoint `p2pk` `p2ms` `p2pkh` `p2sh` 
        - `Bech32` format if it is a segwit outpoint `p2wpkh` `p2wsh` `p2tr`
    - For every input basic scriptSig_asm to scriptSig_hex validation is done.
7. For every `tx` it also undergoes sanity checks like valid `sequence` , `version` etc numbers

    ### Block Building with [Miner](./internal/miner/miner.go) service
    Now that we have all transactions loaded into database we could use [Miner](./internal/miner/miner.go) for transaction selection and block Building. here are steps taking in order to build a block
1. A miner is initialized with following config 
    - `MAX_BLOCK_SIZE` = 4MB 
    - `difficulty` = 0x0000ffff00000000000000000000000000000000000000000000000000000000
    - `[]wtxids` = [bytes32(0x0)] - coinbase wtxid
2. miner keeps picking best tx from mempool, a tx which hash highest fee/weight ratio [`knapsack greedy approach`]. until it reaches `MAX_BLOCK_SIZE` it will continue.
3. upon selection of tx we fetch its inputs and outputs and Validate wholeTx, these validations are transaction specific based on its types.
    - `p2pk` :  extract uncompressed/compressed public key from     `ScriptPubKey`. extract `Signature` from `ScriptSig`. construct trimmed serialized transaction for specific input based on `SIGHASH`. compute it's HASH256 which produces digest which user might have signed for a specific input. validate signature with go `ecdsa` library, providing it pubkey and digest accordingly.
    - `p2pkh`: extract  uncompressed/compressed public key from     `ScriptPubKey` compute its HASH160, validate if HASH160 in script is equal and HASH160 computed. if equal continue with signature validation just like in `p2pk` case.
    - `p2sh` : obtain `redeemScript` from `ScriptSig` validate its opcodes and convert it to byte representation. compute HASH160 of redeemscript, verify it with HASH160 in scriptPubKey.
    - `p2wkh` : witness would have 2 stack elements for p2wpkh, first one being signature and other being pubkey. we extract them and compute trimmed tx for specific input based on `SIGHASH`. validate signature with go `ecdsa` library, providing it pubkey and digest accordingly.
    - `p2wsh` : we do same as `p2sh` but the only changing part is location of witness_redeem_script and use of SHA256 to hash redeemscript.
    - `p2ms` : we do same as `p2pk` but since it is m-out-of-n multiSignature. we hence accumulate all signatures and public Keys and validate it. for every success verification we increment threshold to`. if threshold reaches m then we mark tx as valid and continue with next tx.
4. Once we conclude a Transaction is valid we check if its outpoints are already used. if already used then it might be double spending or RBF hence we move on to next transaction, else we mark outpoints as spent and include in block.
5. once tx is included in block we delete tx from mempool db and proceed further.
6. we stop adding transactions to block once we reach its limit.

    ### Coinbase tx construction and Block Mining.
    Now that we have block full of transactions its time we add coinbase transaction to block. and mine the block such that it reaches enough target difficulty. here are steps involved in block mining and coinbase.
1. we construct vin for coinbase tx as follows
    -  prev_out_txId = bytes32(0x0) 
    -  prev_out_vout = 0
    -  scriptSig = current block height in HEX
    -  Sequence = u32.MAX
    -  witness = [bytes32(0x0)]
2. its time we contruct vouts for coinbase tx, our coinbase has two vouts. one that pays out fee collected to us and second that store witness commitment.
    - In my case out[0] = p2pkh + fee collected
    - out[1] consists of scriptPubKey which has witness commitment
    - witnessCommitment = `OP_RETURN OP_PUSHBYTES_36 aa21a9ed + HASH256((MerkleRoot of wtxids) + bytes32(0x0))`
3. now that we have our inputs and outputs ready we can construct coinbase with tx version 2 and Locktime 0 and above inputs and outputs.
4. we compute coinbaseTxHash and append it to beginning of txId array
5. since we have all transactions sorted out we can build block header with following setup
    - block version = 4 [blocks after segwit upgrade]
    - previous block hash = bytes32(0x0)
    - merkleRoot = merkleRoot of txId array
    - time = current unix time
    - bits = target difficulty `0x1f00ffff`
    - nonce = 0 [param: used to mine other are immutable]
6. now that we have block header we can mine until we reach target difficulty.
7. mining a block is generally find a nonce such that. `Hash256(block_header) < target difficulty`
8. we spin up 10 go routines to mine each block concurrently. each routine atomically increments a global nonce variable and then checks if it is less than target difficulty. if it is less then we break and return the nonce.
9. finally now that we reached target difficulty we store results in `output.txt` file as follows
```
+---------------------------------+
| SERIALIZED BLOCK HEADER         |
+---------------------------------+
| SERIALIZED COINBASE TRANSACTION |
+---------------------------------+
| LIST OF ALL TXIDS               |
+---------------------------------+
```

## why and how of Sqlite
here are list of benefits for choosing sqlite.
- fast processing and retrieval time.
- divided whole Tx into 3 tables
    - `txs` : stores based metadata about transaction
        - `fee` , `weight` , `wtxid` , `txid` are additionally computed and added.
    - `inputs`: inputs are stored referencing to `outputs` and `spending tx`
    - `outputs`: outputs are segregated from input and tx and stored, referencing `funding tx`
- can be used to built further like a `UTXO` database. 
- easy to segregate `double spending` and RBF txs. also helps in CPFP.
- easier to implement `Greedy knapsack algorithm` to select best tx.
- provides good binging with golang.
- store computed values avoid re-computations.


## Terminology
Below are short hand representations of functions,equations and abbreviations

- `H160` or `HASH160` : RIPMOD160(SHA256(messageDigest))
- `HASH256` : SHA256(SHA256(messageDigest))
- `RBF` : REPLACE BY FEE
- `CPFP` : CHILD PAY FOR PARENT
