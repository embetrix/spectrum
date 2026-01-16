import logging
import time
import threading
from unittest.mock import MagicMock

from flask import Flask
from cryptoadvance.spectrum.db import Descriptor, Script, Wallet
from cryptoadvance.spectrum.spectrum import Spectrum
from embit.descriptor.checksum import add_checksum
from embit.bip32 import NETWORKS

logger = logging.getLogger("cryptoadvance")


def test_chain_detection_uses_server_features_genesis_hash():
    spectrum = Spectrum.__new__(Spectrum)
    spectrum.roothash = ""
    spectrum.chain = "regtest"
    spectrum._chain_detection_lock = threading.Lock()
    spectrum._last_chain_detection_attempt_ts = 0.0

    sock = MagicMock()
    sock.status = "ok"

    def fake_call(method, params=None):
        if method == "server.features":
            return {
                "genesis_hash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            }
        raise AssertionError(f"Unexpected electrum call: {method}")

    sock.call = fake_call
    spectrum.sock = sock

    spectrum._maybe_detect_chain(force=True)

    assert spectrum.chain == "main"
    assert spectrum.roothash == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def test_chain_hint_does_not_prevent_detection():
    spectrum = Spectrum.__new__(Spectrum)
    spectrum.roothash = ""
    spectrum.chain = "main"  # operator hint
    spectrum._chain_detection_lock = threading.Lock()
    spectrum._last_chain_detection_attempt_ts = 0.0

    sock = MagicMock()
    sock.status = "ok"

    def fake_call(method, params=None):
        if method == "server.features":
            return {
                "genesis_hash": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
            }
        raise AssertionError(f"Unexpected electrum call: {method}")

    sock.call = fake_call
    spectrum.sock = sock

    spectrum._maybe_detect_chain(force=True)
    assert spectrum.chain == "test"


def test_chain_detection_retries_if_regtest_is_only_fallback():
    spectrum = Spectrum.__new__(Spectrum)
    # Simulate a previous failed/unknown detection that left us on the default
    spectrum.roothash = "deadbeef" * 8
    spectrum.chain = "regtest"
    spectrum._chain_detection_lock = threading.Lock()
    spectrum._last_chain_detection_attempt_ts = 0.0

    sock = MagicMock()
    sock.status = "ok"

    def fake_call(method, params=None):
        if method == "server.features":
            return {
                "genesis_hash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            }
        raise AssertionError(f"Unexpected electrum call: {method}")

    sock.call = fake_call
    spectrum.sock = sock

    spectrum._maybe_detect_chain(force=False)
    assert spectrum.chain == "main"


def test_chain_hint_parsed_from_node_json(tmp_path):
    node_json = tmp_path / "spectrum_node.json"
    node_json.write_text('{"host":"127.0.0.1","port":50001,"ssl":false,"network":"main"}', encoding="utf-8")
    assert Spectrum._chain_hint_from_node_json(str(node_json)) == "main"

def test_importdescriptor(app: Flask, rootkey_hold_accident, acc0key0addr_hold_accident):
    ''' THis does:
        * Creating a wallet
        * importing a descriptor
        * load the script with index 0 
        * compare the address with the expected one
    '''
    spectrum: Spectrum = app.spectrum
    # calculate the descriptor
    tpriv = rootkey_hold_accident.to_base58(
        version=NETWORKS["regtest"]["xprv"]
    )
    desc = add_checksum("wpkh(" + tpriv + "/84'/1'/0'/0/*)")
    desc = desc.replace("'","h")
    logger.info(f"TEST: created desc: {desc}")
    logger.info(f"TEST: expecting address: {acc0key0addr_hold_accident}")
    # Now let's derive the first address from this.


    with app.test_request_context():
        # Create a wallet
        spectrum.createwallet("bob_the_wallet", disable_private_keys=True) # not a hotwallet!
        wallet: Wallet = Wallet.query.filter_by(name="bob_the_wallet").first()
        logger.info("TEST: Import descriptor")
        spectrum.importdescriptor(wallet, desc)
        descriptor: Descriptor = Descriptor.query.filter_by(wallet=wallet).all() # could use first() but let's assert!
        assert len(descriptor) == 1
        descriptor = descriptor[0]
        logger.info(f"TEST: descriptor {descriptor}")
        assert spectrum.getbalances(wallet) == {'mine': {'immature': 0.0, 'trusted': 0.0, 'untrusted_pending': 0.0}, 'watchonly': {'immature': 0.0, 'trusted': 0.0, 'untrusted_pending': 0.0}}
        # Load the script with index 0
        script: Script = Script.query.filter_by(wallet=wallet, index=0).all() # could use first() but let's assert!
        assert len(script) == 1
        script = script[0]
        logger.info(f"TEST: scripthash {script.scripthash} ")
        logger.info(f"TEST: script address {script.address(network=NETWORKS['test'])}")
        # compare the address with the expected one
        assert acc0key0addr_hold_accident == script.address(network=NETWORKS['test'])
        # Depending on the state of electrs, it might take 5 seconds for the sync-thread to finish
        # It does not change anything on the result of the test, though
    
    spectrum.stop()
    del spectrum

