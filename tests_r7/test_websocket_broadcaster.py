"""Tests verifying the in-memory AlertBroadcaster for WebSocket delivery:
- Multiple subscribers per tenant
- Cross-tenant isolation (zero leakage)
- Device-specific alert filtering
- Disconnect and cleanup
- Bounded queue overflow protection
"""
import asyncio
import pytest
from src.backend.platform_ext.services.broadcaster import AlertBroadcaster


def test_multiple_subscribers_same_org():
    """Multiple subscribers for the same organization must all receive published alerts."""
    async def _test():
        bc = AlertBroadcaster(max_queue_size=5)
        q1 = bc.subscribe(org_id="org-1")
        q2 = bc.subscribe(org_id="org-1")
        assert bc.subscriber_count("org-1") == 2

        alert = {"alert_id": "ALT-1", "label": "PortScan", "threat_level": "HIGH"}
        delivered = bc.publish_alert(org_id="org-1", alert_data=alert)
        assert delivered == 2

        item1 = await asyncio.wait_for(q1.get(), timeout=1.0)
        item2 = await asyncio.wait_for(q2.get(), timeout=1.0)
        assert item1 == alert
        assert item2 == alert
        bc.clear()

    asyncio.run(_test())


def test_strict_cross_tenant_isolation():
    """Subscribers from Org B must NEVER receive alerts published for Org A."""
    async def _test():
        bc = AlertBroadcaster(max_queue_size=5)
        q_org_a = bc.subscribe(org_id="org-a")
        q_org_b = bc.subscribe(org_id="org-b")

        alert_a = {"alert_id": "ALT-A", "label": "Infiltration", "org_id": "org-a"}
        bc.publish_alert(org_id="org-a", alert_data=alert_a)

        # Org A gets the alert
        rec_a = await asyncio.wait_for(q_org_a.get(), timeout=1.0)
        assert rec_a["alert_id"] == "ALT-A"

        # Org B queue must remain empty
        assert q_org_b.empty()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(q_org_b.get(), timeout=0.1)
        bc.clear()

    asyncio.run(_test())


def test_device_filter_delivery():
    """Subscribers with device_id filter only receive alerts for their assigned device."""
    async def _test():
        bc = AlertBroadcaster(max_queue_size=5)
        q_all = bc.subscribe(org_id="org-1", device_id=None)
        q_dev1 = bc.subscribe(org_id="org-1", device_id="dev-1")
        q_dev2 = bc.subscribe(org_id="org-1", device_id="dev-2")

        alert_dev1 = {"alert_id": "ALT-D1", "device_id": "dev-1", "threat_level": "HIGH"}
        bc.publish_alert(org_id="org-1", alert_data=alert_dev1, device_id="dev-1")

        # q_all receives it
        assert (await asyncio.wait_for(q_all.get(), timeout=1.0))["alert_id"] == "ALT-D1"
        # q_dev1 receives it
        assert (await asyncio.wait_for(q_dev1.get(), timeout=1.0))["alert_id"] == "ALT-D1"
        # q_dev2 does NOT receive it
        assert q_dev2.empty()
        bc.clear()

    asyncio.run(_test())


def test_disconnect_and_unsubscribe_cleanup():
    """Unsubscribing drops the subscriber from active tracking."""
    async def _test():
        bc = AlertBroadcaster(max_queue_size=5)
        q = bc.subscribe(org_id="org-temp")
        assert bc.subscriber_count("org-temp") == 1

        bc.unsubscribe(org_id="org-temp", queue=q)
        assert bc.subscriber_count("org-temp") == 0

        alert = {"alert_id": "ALT-DROP"}
        delivered = bc.publish_alert(org_id="org-temp", alert_data=alert)
        assert delivered == 0
        assert q.empty()
        bc.clear()

    asyncio.run(_test())


def test_bounded_queue_overflow_protection():
    """When a consumer stalls, the oldest message is dropped and delivery remains non-blocking."""
    async def _test():
        bc = AlertBroadcaster(max_queue_size=5)
        q = bc.subscribe(org_id="org-slow")
        # Queue maxsize is 5
        for i in range(7):
            bc.publish_alert(org_id="org-slow", alert_data={"idx": i})

        await asyncio.sleep(0.01)
        assert q.qsize() == 5
        # Oldest (0, 1) were dropped; queue starts from index 2
        first = await q.get()
        assert first["idx"] == 2
        bc.clear()

    asyncio.run(_test())
