"""Le bug d'origine (Jour 18) : E2EEServer n'était qu'une classe SQLite
locale — deux processus séparés ne pouvaient jamais échanger de message,
malgré le nom "messagerie". Ce test démarre un vrai relais HTTP dans un
thread et fait dialoguer deux E2EEClient à travers lui, comme le
feraient deux machines réelles.
"""

import threading
import time

import pytest
from e2ee_messaging import E2EEClient, E2EERemoteServer, start_e2ee_server


@pytest.fixture
def running_relay(tmp_path):
    httpd = start_e2ee_server(port=0, db_path=str(tmp_path / "relay.db"))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def test_message_round_trips_through_a_real_http_relay(running_relay):
    remote = E2EERemoteServer(running_relay)
    alice = E2EEClient("alice", remote, key_file="/tmp/test_e2ee_alice.key")
    bob = E2EEClient("bob", remote, key_file="/tmp/test_e2ee_bob.key")

    alice.register()
    bob.register()
    alice.send("bob", "message secret via HTTP")

    received = bob.receive()

    assert len(received) == 1
    assert received[0]["decrypted"] is True
    assert received[0]["text"] == "message secret via HTTP"


def test_relay_never_stores_plaintext_or_private_keys(tmp_path, running_relay):
    remote = E2EERemoteServer(running_relay)
    alice = E2EEClient("alice2", remote, key_file="/tmp/test_e2ee_alice2.key")
    bob = E2EEClient("bob2", remote, key_file="/tmp/test_e2ee_bob2.key")
    alice.register()
    bob.register()
    alice.send("bob2", "ne doit jamais apparaître en clair sur le relais")

    stored = remote.get_all_messages("bob2")
    assert len(stored) == 1
    raw_payload = str(stored[0]["payload"])
    assert "ne doit jamais apparaître en clair" not in raw_payload
