from pathlib import Path
from unittest.mock import MagicMock, patch

from SnifferAPI.CaptureFiles import (
    DEFAULT_CAPTURE_FILE_NAME,
    CaptureFileHandler,
    get_capture_file_path,
)


def test_get_capture_file_path_none(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "SnifferAPI.CaptureFiles.DEFAULT_CAPTURE_FILE_DIR", str(tmp_path)
    )
    expected = tmp_path / DEFAULT_CAPTURE_FILE_NAME
    assert get_capture_file_path(None) == str(expected)


def test_get_capture_file_path_invalid_extension(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "SnifferAPI.CaptureFiles.DEFAULT_CAPTURE_FILE_DIR", str(tmp_path)
    )
    invalid = tmp_path / "wrong.txt"
    expected = tmp_path / DEFAULT_CAPTURE_FILE_NAME
    assert get_capture_file_path(str(invalid)) == str(expected)


def test_get_capture_file_path_valid(tmp_path):
    p = tmp_path / "valid.pcap"
    assert get_capture_file_path(str(p)) == str(p.resolve())


def test_handler_creates_directory(tmp_path):
    target = tmp_path / "nested" / "dir" / "capture.pcap"
    CaptureFileHandler(str(target))
    assert target.exists()
    assert target.stat().st_size > 0  # global header written


def test_handler_rollover_on_large_file(tmp_path):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"x" * 25_000_000)  # >20MB

    CaptureFileHandler(str(p))
    backup = tmp_path / "capture.pcap.1"

    assert backup.exists()
    assert p.exists()
    assert p.stat().st_size > 0  # new header written


def test_handler_clear_forces_new_file(tmp_path):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"old data")

    CaptureFileHandler(str(p), clear=True)
    assert p.stat().st_size > 0
    assert p.read_bytes() != b"old data"


def test_start_new_file_writes_global_header(tmp_path):
    p = tmp_path / "capture.pcap"
    handler = CaptureFileHandler(str(p), clear=True)

    data = p.read_bytes()
    assert len(data) >= 24  # PCAP global header
    assert data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")  # magic number


def test_rollover_replaces_backup(tmp_path):
    p = tmp_path / "capture.pcap"
    b = tmp_path / "capture.pcap.1"

    p.write_bytes(b"old")
    b.write_bytes(b"backup")

    handler = CaptureFileHandler(str(p))
    handler.doRollover()

    assert b.exists()
    assert p.exists()
    assert p.stat().st_size > 0


def test_rollover_handles_missing_backup(tmp_path):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"old")

    handler = CaptureFileHandler(str(p))
    handler.doRollover()

    assert (tmp_path / "capture.pcap.1").exists()
    assert p.exists()


def test_rollover_logs_backup_delete_failure(tmp_path, caplog):
    p = tmp_path / "capture.pcap"
    b = tmp_path / "capture.pcap.1"

    p.write_bytes(b"old")
    b.write_bytes(b"backup")

    handler = CaptureFileHandler(str(p))

    with patch.object(Path, "unlink", side_effect=OSError("fail")):
        handler.doRollover()

    assert "capture file rollover remove backup failed" in caplog.text


def test_rollover_logs_rename_failure(tmp_path, caplog):
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"old")

    handler = CaptureFileHandler(str(p))

    with patch.object(Path, "rename", side_effect=OSError("fail")):
        handler.doRollover()

    assert "capture file rollover failed" in caplog.text


def test_write_packet_appends_data(tmp_path):
    p = tmp_path / "capture.pcap"
    handler = CaptureFileHandler(str(p), clear=True)

    pkt = MagicMock()
    pkt.boardId = 7
    pkt.getList.return_value = [1, 2, 3, 4]
    pkt.time = 123.456

    before = p.stat().st_size
    handler.writePacket(pkt)
    after = p.stat().st_size

    assert after > before


def test_write_packet_creates_valid_pcap_packet(tmp_path):
    p = tmp_path / "capture.pcap"
    handler = CaptureFileHandler(str(p), clear=True)

    pkt = MagicMock()
    pkt.boardId = 1
    pkt.getList.return_value = [10, 20, 30]
    pkt.time = 100.0

    handler.writePacket(pkt)

    data = p.read_bytes()
    assert len(data) > 24
    assert data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4")
