from unittest.mock import MagicMock, patch

import pytest

import SnifferAPI.UART as uart_module


class DummyReader:
    """Fake PacketReader used to simulate decode behavior."""

    def __init__(self, *, should_pass=True):
        self.should_pass = should_pass
        self.closed = False

    def sendPingReq(self):
        pass

    def decodeFromSLIP(self, *args, **kwargs):
        if not self.should_pass:
            raise uart_module.Exceptions.SnifferTimeout()

    def doExit(self):
        self.closed = True


def test_find_sniffer_detects_ports(monkeypatch):
    # Fake serial ports
    fake_ports = [MagicMock(device="COM1"), MagicMock(device="COM2")]
    monkeypatch.setattr(uart_module.list_ports, "comports", lambda: fake_ports)

    # Fake PacketReader always succeeds
    monkeypatch.setattr(
        uart_module.Packet,
        "PacketReader",
        lambda portnum, baudrate: DummyReader(should_pass=True),
    )

    sniffers = uart_module.find_sniffer()
    assert sniffers == ["COM1", "COM2"]


def test_find_sniffer_skips_invalid(monkeypatch):
    fake_ports = [MagicMock(device="COM1")]
    monkeypatch.setattr(uart_module.list_ports, "comports", lambda: fake_ports)

    # Fake PacketReader always fails
    def failing_reader(*args, **kwargs):
        raise uart_module.Exceptions.LockedException("locked")

    monkeypatch.setattr(uart_module.Packet, "PacketReader", failing_reader)

    sniffers = uart_module.find_sniffer()
    assert sniffers == []


def test_find_sniffer_baudrates_success(monkeypatch):
    monkeypatch.setattr(
        uart_module.Packet,
        "PacketReader",
        lambda portnum, baudrate: DummyReader(should_pass=True),
    )

    result = uart_module.find_sniffer_baudrates("COM1")
    assert result == {"default": uart_module.SNIFFER_BAUDRATES[0], "other": []}


def test_find_sniffer_baudrates_none(monkeypatch):
    monkeypatch.setattr(
        uart_module.Packet,
        "PacketReader",
        lambda portnum, baudrate: DummyReader(should_pass=False),
    )

    result = uart_module.find_sniffer_baudrates("COM1")
    assert result is None


def test_list_serial_ports(monkeypatch):
    fake_ports = [MagicMock(device="COM1")]
    monkeypatch.setattr(uart_module.list_ports, "comports", lambda: fake_ports)

    ports = uart_module.list_serial_ports()
    assert ports == fake_ports


class FakeSerial:
    """Minimal fake serial port for Uart tests."""

    def __init__(self):
        self.in_waiting = 0
        self.data = bytearray()
        self.baudrate = 9600
        self.closed = False

    def reset_input_buffer(self):
        pass

    def read(self, n):
        if not self.data:
            return b""
        b = bytes([self.data.pop(0)])
        return b

    def write(self, arr):
        return len(arr)

    def close(self):
        self.closed = True

    def cancel_read(self):
        pass


def test_uart_read_queue(monkeypatch):
    fake_serial = FakeSerial()
    fake_serial.data.extend([1, 2, 3])

    monkeypatch.setattr(uart_module.Uart, "_read_worker", lambda self: None)

    monkeypatch.setattr(
        uart_module.serial,
        "Serial",
        lambda *args, **kwargs: fake_serial,
    )

    u = uart_module.Uart(portnum="COM1", baudrate=uart_module.SNIFFER_BAUDRATES[0])

    u._read_queue_extend(b"\x01\x02\x03")

    assert u.readByte(timeout=0.01) == 1
    assert u.readByte(timeout=0.01) == 2
    assert u.readByte(timeout=0.01) == 3
    assert u.readByte(timeout=0.01) is None

    u.close()


def test_uart_write_list(monkeypatch):
    fake_serial = FakeSerial()

    monkeypatch.setattr(
        uart_module.serial,
        "Serial",
        lambda *args, **kwargs: fake_serial,
    )

    u = uart_module.Uart(portnum="COM1", baudrate=uart_module.SNIFFER_BAUDRATES[0])
    u.writeList([1, 2, 3])  # Should not raise
    u.close()


def test_uart_invalid_baudrate(monkeypatch):
    fake_serial = FakeSerial()

    monkeypatch.setattr(
        uart_module.serial,
        "Serial",
        lambda *args, **kwargs: fake_serial,
    )

    with pytest.raises(Exception):
        uart_module.Uart(portnum="COM1", baudrate=12345)
