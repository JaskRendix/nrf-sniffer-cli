from unittest.mock import MagicMock

import pytest

from SnifferAPI.Devices import Device, DeviceList, listToString


def test_device_repr():
    d = Device([1, 2, 3], "Test", -50)
    r = repr(d)
    assert "Test" in r
    assert "[1, 2, 3]" in r


def test_list_to_string():
    assert listToString([65, 66, 67]) == "ABC"


@pytest.fixture
def devlist():
    return DeviceList()


def make_dev(addr=[1, 2, 3, 4, 5, 6], name="Test", RSSI=-50):
    return Device(addr, name, RSSI)


def test_initial_state(devlist):
    assert len(devlist) == 0
    assert devlist.asList() == []


def test_append_adds_device_and_notifies(devlist):
    cb = MagicMock()
    devlist.subscribe("DEVICE_ADDED", cb)

    d = make_dev()
    devlist.append(d)

    assert len(devlist) == 1
    cb.assert_called_once()
    assert cb.call_args[0][0].msg == d


def test_clear_removes_all_devices_and_notifies(devlist):
    cb = MagicMock()
    devlist.subscribe("DEVICES_CLEARED", cb)

    devlist.append(make_dev())
    devlist.append(make_dev([9, 9, 9, 9, 9, 9]))

    devlist.clear()

    assert len(devlist) == 0
    cb.assert_called_once()


def test_appendOrUpdate_adds_new_device(devlist):
    cb = MagicMock()
    devlist.subscribe("DEVICE_ADDED", cb)

    d = make_dev()
    devlist.appendOrUpdate(d)

    assert len(devlist) == 1
    cb.assert_called_once()


def test_appendOrUpdate_updates_name_if_unknown(devlist):
    d1 = make_dev(name='""')
    d2 = make_dev(name="RealName")

    devlist.append(d1)

    cb = MagicMock()
    devlist.subscribe("DEVICE_UPDATED", cb)

    devlist.appendOrUpdate(d2)

    assert devlist.devices[0].name == "RealName"
    cb.assert_called_once()


def test_appendOrUpdate_updates_RSSI_when_significant(devlist):
    d1 = make_dev(RSSI=-80)
    d2 = make_dev(RSSI=-60)

    devlist.append(d1)

    cb = MagicMock()
    devlist.subscribe("DEVICE_UPDATED", cb)

    devlist.appendOrUpdate(d2)

    assert devlist.devices[0].RSSI == -60
    cb.assert_called_once()


def test_appendOrUpdate_does_not_update_RSSI_when_small_change(devlist):
    d1 = make_dev(RSSI=-50)
    d2 = make_dev(RSSI=-49)  # small change

    devlist.append(d1)

    cb = MagicMock()
    devlist.subscribe("DEVICE_UPDATED", cb)

    devlist.appendOrUpdate(d2)

    assert devlist.devices[0].RSSI == -50
    cb.assert_not_called()


def test_find_by_address(devlist):
    d = make_dev([1, 2, 3])
    devlist.append(d)

    assert devlist.find([1, 2, 3]) is d


def test_find_by_index(devlist):
    d1 = make_dev([1])
    d2 = make_dev([2])
    devlist.append(d1)
    devlist.append(d2)

    assert devlist.find(1) is d2
    assert devlist.find(5) is None


def test_find_by_name(devlist):
    d = make_dev([1], name="Beacon")
    devlist.append(d)

    assert devlist.find("Beacon") is d
    assert devlist.find("Unknown") is None


def test_find_by_device_instance(devlist):
    d = make_dev([1])
    devlist.append(d)

    assert devlist.find(d) is d


def test_remove_by_address(devlist):
    d = make_dev([1])
    devlist.append(d)

    cb = MagicMock()
    devlist.subscribe("DEVICE_REMOVED", cb)

    devlist.remove([1])

    assert len(devlist) == 0
    cb.assert_called_once()


def test_remove_by_index(devlist):
    d1 = make_dev([1])
    d2 = make_dev([2])
    devlist.append(d1)
    devlist.append(d2)

    cb = MagicMock()
    devlist.subscribe("DEVICE_REMOVED", cb)

    devlist.remove(0)

    assert len(devlist) == 1
    assert devlist.devices[0] is d2
    cb.assert_called_once()


def test_remove_by_device_instance(devlist):
    d = make_dev([1])
    devlist.append(d)

    cb = MagicMock()
    devlist.subscribe("DEVICE_REMOVED", cb)

    devlist.remove(d)

    assert len(devlist) == 0
    cb.assert_called_once()


def test_remove_invalid_key_does_nothing(devlist):
    devlist.append(make_dev())
    devlist.remove("invalid")  # should not crash
    assert len(devlist) == 1


def test_index_returns_correct_index(devlist):
    d1 = make_dev([1])
    d2 = make_dev([2])
    devlist.append(d1)
    devlist.append(d2)

    assert devlist.index(d2) == 1


def test_index_returns_none_for_missing(devlist):
    d = make_dev([1])
    assert devlist.index(d) is None


def test_setFollowed_marks_only_one(devlist):
    d1 = make_dev([1])
    d2 = make_dev([2])
    devlist.append(d1)
    devlist.append(d2)

    cb = MagicMock()
    devlist.subscribe("DEVICE_FOLLOWED", cb)

    devlist.setFollowed(d2)

    assert d1.followed is False
    assert d2.followed is True
    cb.assert_called_once()


def test_setFollowed_ignores_unknown_device(devlist):
    d1 = make_dev([1])
    d2 = make_dev([2])
    devlist.append(d1)

    cb = MagicMock()
    devlist.subscribe("DEVICE_FOLLOWED", cb)

    devlist.setFollowed(d2)  # not in list

    assert d1.followed is False
    assert d2.followed is False
    cb.assert_called_once()  # still notifies
