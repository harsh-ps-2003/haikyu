#get all possible opcodes in the mempool

import os
import json

op_codes = set()

for filename in os.listdir("./data/mempool"):
    if filename.endswith(".json"):
        # open file and read json
        with open(os.path.join("./data/mempool", filename)) as json_file:
            tx = json.load(json_file)
            for vin in tx["vin"]:
                for op_code in vin["prevout"]["scriptpubkey_asm"].split(" "):
                    if op_code.startswith("OP_"):
                        op_codes.add(op_code)
                for op_code in vin["scriptsig_asm"].split(" "):
                    if op_code.startswith("OP_"):
                        op_codes.add(op_code)
            for vout in tx["vout"]:
                for op_code in vout["scriptpubkey_asm"].split(" "):
                    if op_code.startswith("OP_"):
                        op_codes.add(op_code)
print(op_codes)

# got the following op_codes
{'OP_HASH160', 'OP_PUSHBYTES_5', 'OP_DUP', 'OP_PUSHBYTES_4', 'OP_PUSHBYTES_72', 'OP_0', 'OP_PUSHBYTES_67', 'OP_RETURN', 'OP_PUSHBYTES_22', 'OP_PUSHBYTES_12', 'OP_EQUALVERIFY', 'OP_PUSHBYTES_13', 'OP_PUSHNUM_3', 'OP_PUSHBYTES_68', 'OP_PUSHBYTES_69', 'OP_PUSHBYTES_42', 'OP_PUSHBYTES_71', 'OP_CHECKSIG', 'OP_PUSHBYTES_20', 'OP_PUSHBYTES_64', 'OP_CHECKMULTISIG', 'OP_PUSHBYTES_31', 'OP_PUSHBYTES_11', 'OP_PUSHBYTES_10', 'OP_PUSHBYTES_73', 'OP_EQUAL', 'OP_PUSHDATA2', 'OP_PUSHBYTES_74', 'OP_PUSHBYTES_32', 'OP_PUSHBYTES_54', 'OP_PUSHBYTES_65', 'OP_PUSHBYTES_33', 'OP_PUSHBYTES_46', 'OP_PUSHNUM_1', 'OP_PUSHBYTES_34', 'OP_PUSHDATA1', 'OP_PUSHBYTES_70', 'OP_PUSHBYTES_9', 'OP_PUSHBYTES_1', 'OP_PUSHBYTES_17', 'OP_PUSHBYTES_63'}
