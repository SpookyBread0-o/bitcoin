import unittest
from .address import key_to_p2sh_p2wpkh as key_to_p2sh_p2wpkh, key_to_p2wpkh as key_to_p2wpkh, script_to_p2sh_p2wsh as script_to_p2sh_p2wsh, script_to_p2wsh as script_to_p2wsh
from .messages import CBlock as CBlock, COIN as COIN, COutPoint as COutPoint, CTransaction as CTransaction, CTxIn as CTxIn, CTxInWitness as CTxInWitness, CTxOut as CTxOut, FromHex as FromHex, ToHex as ToHex, hash256 as hash256, hex_str_to_bytes as hex_str_to_bytes, ser_uint256 as ser_uint256, sha256 as sha256, uint256_from_str as uint256_from_str
from .script import CScript as CScript, CScriptNum as CScriptNum, CScriptOp as CScriptOp, OP_0 as OP_0, OP_1 as OP_1, OP_CHECKMULTISIG as OP_CHECKMULTISIG, OP_CHECKSIG as OP_CHECKSIG, OP_RETURN as OP_RETURN, OP_TRUE as OP_TRUE, hash160 as hash160
from .util import assert_equal as assert_equal
from typing import Any, Optional

MAX_BLOCK_SIGOPS: int
TIME_GENESIS_BLOCK: int
WITNESS_COMMITMENT_HEADER: bytes

def create_block(hashprev: Any, coinbase: Any, ntime: Optional[Any] = ..., *, version: int = ...): ...
def get_witness_script(witness_root: Any, witness_nonce: Any): ...
def add_witness_commitment(block: Any, nonce: int = ...) -> None: ...
def script_BIP34_coinbase_height(height: Any): ...
def create_coinbase(height: Any, pubkey: Optional[Any] = ...): ...
def create_tx_with_script(prevtx: Any, n: Any, script_sig: bytes = ..., amount: Any, *, script_pub_key: Any = ...): ...
def create_transaction(node: Any, txid: Any, to_address: Any, amount: Any): ...
def create_raw_transaction(node: Any, txid: Any, to_address: Any, amount: Any): ...
def get_legacy_sigopcount_block(block: Any, accurate: bool = ...): ...
def get_legacy_sigopcount_tx(tx: Any, accurate: bool = ...): ...
def witness_script(use_p2wsh: Any, pubkey: Any): ...
def create_witness_tx(node: Any, use_p2wsh: Any, utxo: Any, pubkey: Any, encode_p2sh: Any, amount: Any): ...
def send_to_witness(use_p2wsh: Any, node: Any, utxo: Any, pubkey: Any, encode_p2sh: Any, amount: Any, sign: bool = ..., insert_redeem_script: str = ...): ...

class TestFrameworkBlockTools(unittest.TestCase):
    def test_create_coinbase(self) -> None: ...
