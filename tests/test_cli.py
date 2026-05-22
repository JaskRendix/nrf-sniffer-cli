import json
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


def make_device(address: list[int], name: str = "Dev", rssi: int = -50) -> MagicMock:
    dev = MagicMock()
    dev.address = address
    dev.name = f'"{name}"'
    dev.RSSI = rssi
    return dev


class TestHexToBytes:
    def test_plain_hex(self):
        assert hex_to_bytes("deadbeef") == [0xDE, 0xAD, 0xBE, 0xEF]

    def test_0x_prefix(self):
        assert hex_to_bytes("0xDEADBEEF") == [0xDE, 0xAD, 0xBE, 0xEF]

    def test_odd_length_padded(self):
        assert hex_to_bytes("123") == [0x01, 0x23]

    def test_invalid_chars_raise(self):
        with pytest.raises(ValueError, match="hexadecimal"):
            hex_to_bytes("GGGGGG")

    def test_empty_string(self):
        assert hex_to_bytes("") == []


class TestNormalizeAddress:
    def test_strips_colons(self):
        assert normalize_address("AA:BB:CC:DD:EE:FF") == "aabbccddeeff"

    def test_strips_dashes(self):
        assert normalize_address("AA-BB-CC-DD-EE-FF") == "aabbccddeeff"

    def test_already_plain(self):
        assert normalize_address("aabbccddeeff") == "aabbccddeeff"


class TestAddressToString:
    def test_formats_six_bytes(self):
        dev = make_device([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        assert address_to_string(dev) == "010203040506"

    def test_truncates_to_six(self):
        dev = make_device([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF])
        assert address_to_string(dev) == "010203040506"


class TestFilterSet:
    def _make_packet(self, *, channel=37, rssi=-50, pkt_id=None, adv_address=None):
        p = MagicMock()
        p.channel = channel
        p.RSSI = rssi
        p.id = pkt_id
        bp = MagicMock()
        bp.advAddress = adv_address
        p.blePacket = bp
        return p

    def test_no_filters_matches_everything(self):
        fs = FilterSet()
        assert fs.match(self._make_packet()) is True

    def test_channel_filter_pass(self):
        fs = FilterSet(channel=37)
        assert fs.match(self._make_packet(channel=37)) is True

    def test_channel_filter_fail(self):
        fs = FilterSet(channel=37)
        assert fs.match(self._make_packet(channel=38)) is False

    def test_min_rssi_pass(self):
        fs = FilterSet(min_rssi=-60)
        assert fs.match(self._make_packet(rssi=-50)) is True

    def test_min_rssi_fail(self):
        fs = FilterSet(min_rssi=-60)
        assert fs.match(self._make_packet(rssi=-70)) is False

    def test_pdu_type_adv_pass(self):
        from SnifferAPI.Types import EVENT_PACKET_ADV_PDU

        fs = FilterSet(pdu_type="adv")
        assert fs.match(self._make_packet(pkt_id=EVENT_PACKET_ADV_PDU)) is True

    def test_pdu_type_adv_fail(self):
        from SnifferAPI.Types import EVENT_PACKET_DATA_PDU

        fs = FilterSet(pdu_type="adv")
        assert fs.match(self._make_packet(pkt_id=EVENT_PACKET_DATA_PDU)) is False


@pytest.fixture()
def mock_client(monkeypatch):
    """
    Replace SnifferClient in the cli module with a MagicMock instance.
    All tests that need a client use this fixture; no subprocess is spawned.
    """
    instance = MagicMock()
    instance.scan.return_value = []
    instance.stop.return_value = None
    monkeypatch.setattr(cli_module, "SnifferClient", lambda capture_file: instance)
    return instance


class TestArgParsing:
    def test_help_exits_zero(self):
        assert run_main("--help") == 0

    def test_sniff_help_exits_zero(self):
        assert run_main("sniff", "--help") == 0

    def test_no_command_exits_nonzero(self):
        assert run_main() != 0

    def test_invalid_command_exits_nonzero(self):
        assert run_main("invalid") != 0

    def test_sniff_requires_address_or_name_or_irk(self):
        assert run_main("sniff") != 0

    def test_sniff_address_and_name_mutually_exclusive(self):
        assert run_main("sniff", "--address", "AA:BB:CC:DD:EE:FF", "--name", "foo") != 0


class TestListCommand:
    def test_prints_ports(self, monkeypatch, capsys):
        monkeypatch.setattr(cli_module.UART, "find_sniffer", lambda: ["COM3", "COM4"])
        rc = run_main("list")
        assert rc == 0
        out = capsys.readouterr().out
        assert "COM3" in out
        assert "COM4" in out

    def test_no_ports_returns_nonzero(self, monkeypatch):
        monkeypatch.setattr(cli_module.UART, "find_sniffer", lambda: [])
        assert run_main("list") != 0


class TestScanCommand:
    def test_text_output(self, mock_client, capsys):
        mock_client.scan.return_value = [
            make_device([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], "Dev")
        ]
        rc = run_main("scan")
        assert rc == 0
        out = capsys.readouterr().out
        assert "0a0b0c0d0e0f" in out
        assert "Dev" in out

    def test_json_output(self, mock_client, capsys):
        mock_client.scan.return_value = [
            make_device([1, 2, 3, 4, 5, 6], "Test", rssi=-42)
        ]
        rc = run_main("scan", "--json")
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["address"] == "010203040506"
        assert data[0]["name"] == "Test"
        assert data[0]["rssi"] == -42

    def test_no_devices_empty_output(self, mock_client, capsys):
        mock_client.scan.return_value = []
        rc = run_main("scan")
        assert rc == 0
        assert capsys.readouterr().out.strip() == ""

    def test_no_devices_json_empty_list(self, mock_client, capsys):
        mock_client.scan.return_value = []
        rc = run_main("scan", "--json")
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == []


class TestSniffCommand:
    def test_sniff_by_address(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        rc = run_main("sniff", "--address", "01:02:03:04:05:06")
        assert rc == 0
        mock_client.follow.assert_called_once()

    def test_sniff_by_name(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6], "MyDevice")]
        rc = run_main("sniff", "--name", "MyDevice")
        assert rc == 0
        mock_client.follow.assert_called_once()

    def test_device_not_found_returns_nonzero(self, mock_client, caplog):
        import logging

        mock_client.scan.return_value = []
        with caplog.at_level(logging.ERROR):
            rc = run_main("sniff", "--address", "00:00:00:00:00:00")
        assert rc != 0
        assert "not found" in caplog.text.lower()

    def test_sniff_by_irk(self, mock_client):
        rc = run_main("sniff", "--irk", "0x11223344556677889900AABBCCDDEEFF")
        assert rc == 0
        mock_client.follow_by_irk.assert_called_once()

    def test_invalid_irk_nonzero(self, mock_client):
        rc = run_main("sniff", "--irk", "GGGGGG")
        assert rc != 0

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
    def test_filter_flags_accepted(self, mock_client, flag, value):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        rc = run_main("sniff", "--address", "01:02:03:04:05:06", flag, value)
        assert rc == 0

    def test_live_flag_accepted(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        rc = run_main("sniff", "--address", "01:02:03:04:05:06", "--live")
        assert rc == 0

    def test_decode_flag_accepted(self, mock_client):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        rc = run_main("sniff", "--address", "01:02:03:04:05:06", "--decode")
        assert rc == 0

    def test_record_json_opens_file(self, mock_client, tmp_path):
        mock_client.scan.return_value = [make_device([1, 2, 3, 4, 5, 6])]
        json_file = tmp_path / "log.json"
        rc = run_main(
            "sniff", "--address", "01:02:03:04:05:06", "--record-json", str(json_file)
        )
        assert rc == 0
        assert json_file.exists()
