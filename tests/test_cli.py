import json
import logging
import sys
from unittest.mock import MagicMock, patch

import pytest

import SnifferAPI.cli as cli_module
from SnifferAPI.cli import main
from SnifferAPI.client.filter import FilterSet
from SnifferAPI.client.tools import address_to_string, hex_to_bytes, normalize_address


def run_main(*argv: str) -> int:
    """Invoke main() with the given argv and return its exit code."""
    with patch.object(sys, "argv", ["nrf-sniffer-cli", *argv]):
        try:
            return main()
        except SystemExit as exc:
            return int(exc.code) if exc.code is not None else 0


def make_device(address, name="Dev", rssi=-50):
    dev = MagicMock()
    dev.address = address
    dev.name = f'"{name}"'
    dev.RSSI = rssi
    return dev


# ---------------------------------------------------------------------------
# tools: hex_to_bytes / normalize_address / address_to_string
# ---------------------------------------------------------------------------


class TestHexToBytes:
    def test_plain_hex(self):
        assert hex_to_bytes("deadbeef") == [0xDE, 0xAD, 0xBE, 0xEF]

    def test_prefix(self):
        assert hex_to_bytes("0xDEADBEEF") == [0xDE, 0xAD, 0xBE, 0xEF]

    def test_odd_length(self):
        assert hex_to_bytes("123") == [0x01, 0x23]

    def test_invalid(self):
        with pytest.raises(ValueError):
            hex_to_bytes("GGGG")

    def test_empty(self):
        assert hex_to_bytes("") == []


class TestNormalizeAddress:
    def test_colons(self):
        assert normalize_address("AA:BB:CC:DD:EE:FF") == "aabbccddeeff"

    def test_dashes(self):
        assert normalize_address("AA-BB-CC-DD-EE-FF") == "aabbccddeeff"

    def test_plain(self):
        assert normalize_address("aabbccddeeff") == "aabbccddeeff"


class TestAddressToString:
    def test_six_bytes(self):
        dev = make_device([1, 2, 3, 4, 5, 6])
        assert address_to_string(dev) == "010203040506"

    def test_truncate(self):
        dev = make_device([1, 2, 3, 4, 5, 6, 255])
        assert address_to_string(dev) == "010203040506"


# ---------------------------------------------------------------------------
# FilterSet
# ---------------------------------------------------------------------------


class TestFilterSet:
    def _pkt(self, *, channel=37, rssi=-50, pkt_id=None, adv_address=None):
        p = MagicMock()
        p.channel = channel
        p.RSSI = rssi
        p.id = pkt_id
        bp = MagicMock()
        bp.advAddress = adv_address
        p.blePacket = bp
        return p

    def test_match_all(self):
        assert FilterSet().match(self._pkt())

    def test_channel_pass(self):
        assert FilterSet(channel=37).match(self._pkt(channel=37))

    def test_channel_fail(self):
        assert not FilterSet(channel=37).match(self._pkt(channel=38))

    def test_rssi_pass(self):
        assert FilterSet(min_rssi=-60).match(self._pkt(rssi=-50))

    def test_rssi_fail(self):
        assert not FilterSet(min_rssi=-60).match(self._pkt(rssi=-70))

    def test_pdu_adv(self):
        from SnifferAPI.Types import EVENT_PACKET_ADV_PDU

        assert FilterSet(pdu_type="adv").match(self._pkt(pkt_id=EVENT_PACKET_ADV_PDU))

    def test_pdu_adv_fail(self):
        from SnifferAPI.Types import EVENT_PACKET_DATA_PDU

        assert not FilterSet(pdu_type="adv").match(
            self._pkt(pkt_id=EVENT_PACKET_DATA_PDU)
        )

    def test_adv_address_pass(self):
        fs = FilterSet(adv_address="aabbccddeeff")
        pkt = self._pkt(adv_address=[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        assert fs.match(pkt)

    def test_adv_address_fail(self):
        fs = FilterSet(adv_address="ffffffffffff")
        pkt = self._pkt(adv_address=[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        assert not fs.match(pkt)


# ---------------------------------------------------------------------------
# SnifferClient mocking
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_client(monkeypatch):
    instance = MagicMock()
    instance.scan.return_value = []
    instance.stop.return_value = None
    monkeypatch.setattr(cli_module, "SnifferClient", lambda capture_file: instance)
    return instance


# ---------------------------------------------------------------------------
# CLI: list
# ---------------------------------------------------------------------------


class TestList:
    def test_list_ports(self, monkeypatch, capsys):
        monkeypatch.setattr(cli_module.UART, "find_sniffer", lambda: ["COM1", "COM2"])
        assert run_main("list") == 0
        out = capsys.readouterr().out
        assert "COM1" in out
        assert "COM2" in out

    def test_list_none(self, monkeypatch):
        monkeypatch.setattr(cli_module.UART, "find_sniffer", lambda: [])
        assert run_main("list") != 0


# ---------------------------------------------------------------------------
# CLI: scan
# ---------------------------------------------------------------------------


class TestScan:
    def test_scan_text(self, mock_client, capsys):
        mock_client.scan.return_value = [make_device([10, 11, 12, 13, 14, 15], "Dev")]
        assert run_main("scan") == 0
        out = capsys.readouterr().out
        assert "0a0b0c0d0e0f" in out
        assert "Dev" in out

    def test_scan_json(self, mock_client, capsys):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6], "Test", -42)]
        assert run_main("scan", "--json") == 0
        data = json.loads(capsys.readouterr().out)
        assert data[0]["address"] == "010203040506"
        assert data[0]["name"] == "Test"
        assert data[0]["rssi"] == -42

    def test_scan_empty(self, mock_client, capsys):
        mock_client.scan.return_value = []
        assert run_main("scan") == 0
        assert capsys.readouterr().out.strip() == ""

    def test_scan_empty_json(self, mock_client, capsys):
        mock_client.scan.return_value = []
        assert run_main("scan", "--json") == 0
        assert json.loads(capsys.readouterr().out) == []


# ---------------------------------------------------------------------------
# CLI: sniff
# ---------------------------------------------------------------------------


class TestSniff:
    def test_sniff_by_address(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        assert run_main("sniff", "--address", "01:02:03:04:05:06") == 0
        mock_client.follow.assert_called_once()

    def test_sniff_by_name(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6], "MyDev")]
        assert run_main("sniff", "--name", "MyDev") == 0
        mock_client.follow.assert_called_once()

    def test_sniff_not_found(self, mock_client, caplog):
        mock_client.scan.return_value = []
        with caplog.at_level(logging.ERROR):
            rc = run_main("sniff", "--address", "00:00:00:00:00:00")
        assert rc != 0
        assert "not found" in caplog.text.lower()

    def test_sniff_by_irk(self, mock_client):
        assert run_main("sniff", "--irk", "0x11223344556677889900AABBCCDDEEFF") == 0
        mock_client.follow_by_irk.assert_called_once()

    def test_sniff_invalid_irk(self, mock_client):
        assert run_main("sniff", "--irk", "GGGG") != 0

    @pytest.mark.parametrize(
        "flag,value",
        [
            ("--channel", "37"),
            ("--min-rssi", "-60"),
            ("--type", "adv"),
            ("--type", "data"),
            ("--type", "all"),
        ],
    )
    def test_filter_flags(self, mock_client, flag, value):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        assert run_main("sniff", "--address", "01:02:03:04:05:06", flag, value) == 0

    def test_live_flag(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        assert run_main("sniff", "--address", "01:02:03:04:05:06", "--live") == 0

    def test_decode_flag(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        assert run_main("sniff", "--address", "01:02:03:04:05:06", "--decode") == 0

    def test_record_json(self, mock_client, tmp_path):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        path = tmp_path / "log.json"
        assert (
            run_main(
                "sniff", "--address", "01:02:03:04:05:06", "--record-json", str(path)
            )
            == 0
        )
        assert path.exists()
