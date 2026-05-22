from unittest.mock import MagicMock

import pytest

from SnifferAPI.Notifications import Notification, Notifier


def test_notification_valid():
    n = Notification("TEST", {"a": 1})
    assert n.key == "TEST"
    assert n.msg == {"a": 1}
    assert "TEST" in repr(n)


def test_notification_invalid_key_type():
    with pytest.raises(TypeError):
        Notification(123, "msg")


def test_notifier_initial_empty():
    n = Notifier()
    assert n.getCallbacks("X") == []


def test_subscribe_and_notify_specific_key():
    n = Notifier()
    cb = MagicMock()

    n.subscribe("HELLO", cb)
    n.notify("HELLO", msg=123)

    cb.assert_called_once()
    call_arg = cb.call_args[0][0]
    assert isinstance(call_arg, Notification)
    assert call_arg.key == "HELLO"
    assert call_arg.msg == 123


def test_subscribe_prevents_duplicates():
    n = Notifier()
    cb = MagicMock()

    n.subscribe("A", cb)
    n.subscribe("A", cb)  # duplicate should be ignored

    n.notify("A", msg=1)
    cb.assert_called_once()


def test_unsubscribe():
    n = Notifier()
    cb = MagicMock()

    n.subscribe("A", cb)
    n.unSubscribe("A", cb)
    n.notify("A", msg=1)

    cb.assert_not_called()


def test_unsubscribe_nonexistent_does_not_crash():
    n = Notifier()
    cb = MagicMock()

    # Should not raise
    n.unSubscribe("A", cb)


def test_wildcard_receives_all_notifications():
    n = Notifier()
    cb = MagicMock()

    n.subscribe("*", cb)
    n.notify("X", msg=10)
    n.notify("Y", msg=20)

    assert cb.call_count == 2
    keys = [call[0][0].key for call in cb.call_args_list]
    assert keys == ["X", "Y"]


def test_specific_and_wildcard_both_fire():
    n = Notifier()
    cb_specific = MagicMock()
    cb_wild = MagicMock()

    n.subscribe("A", cb_specific)
    n.subscribe("*", cb_wild)

    n.notify("A", msg=99)

    cb_specific.assert_called_once()
    cb_wild.assert_called_once()


def test_pass_on_notification():
    n = Notifier()
    cb = MagicMock()

    n.subscribe("HELLO", cb)

    notif = Notification("HELLO", 42)
    n.passOnNotification(notif)

    cb.assert_called_once_with(notif)


def test_callbacks_are_called_in_subscription_order():
    n = Notifier()
    order = []

    def cb1(_):
        order.append("cb1")

    def cb2(_):
        order.append("cb2")

    n.subscribe("A", cb1)
    n.subscribe("A", cb2)

    n.notify("A")

    assert order == ["cb1", "cb2"]


def test_callback_exception_does_not_stop_others():
    n = Notifier()
    cb1 = MagicMock(side_effect=RuntimeError("boom"))
    cb2 = MagicMock()

    n.subscribe("A", cb1)
    n.subscribe("A", cb2)

    # notify should not raise
    n.notify("A")

    cb2.assert_called_once()


def test_thread_safety_subscribe_and_notify():
    """
    This is not a full concurrency test, but ensures that
    locking does not deadlock under rapid subscribe/notify.
    """
    n = Notifier()
    cb = MagicMock()

    def worker():
        for _ in range(200):
            n.subscribe("A", cb)
            n.notify("A", msg=1)

    import threading

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Should not deadlock or crash
    assert cb.call_count > 0


def test_clear_callbacks():
    n = Notifier()
    cb = MagicMock()

    n.subscribe("A", cb)
    n.subscribe("*", cb)

    n.clearCallbacks()
    n.notify("A")

    cb.assert_not_called()
