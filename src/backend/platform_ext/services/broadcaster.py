"""In-memory event broadcaster for authenticated, multi-tenant WebSocket alert delivery.
Avoids per-client database polling while maintaining strict organization isolation.
"""
from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from typing import Dict, NamedTuple, Optional, Set

log = logging.getLogger("neural_breach.broadcaster")


class Subscriber(NamedTuple):
    queue: asyncio.Queue
    device_id: Optional[str]
    loop: asyncio.AbstractEventLoop


class AlertBroadcaster:
    """Thread-safe fan-out broadcaster delivering alerts to active WebSocket queues."""

    def __init__(self, max_queue_size: int = 500):
        self._max_queue_size = max_queue_size
        self._subscribers: Dict[str, Set[Subscriber]] = defaultdict(set)
        self._lock = asyncio.Lock()

    def subscribe(self, org_id: str, device_id: Optional[str] = None) -> asyncio.Queue:
        """Register a new WebSocket client for real-time alert push."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue_size)
        sub = Subscriber(queue=queue, device_id=device_id, loop=loop)
        self._subscribers[org_id].add(sub)
        log.debug("Subscribed client for org=%s device=%s (total=%d)", org_id, device_id, len(self._subscribers[org_id]))
        return queue

    def unsubscribe(self, org_id: str, queue: asyncio.Queue) -> None:
        """Unregister a disconnected WebSocket client."""
        if org_id not in self._subscribers:
            return
        to_remove = {s for s in self._subscribers[org_id] if s.queue is queue}
        self._subscribers[org_id].difference_update(to_remove)
        if not self._subscribers[org_id]:
            self._subscribers.pop(org_id, None)
        log.debug("Unsubscribed client for org=%s", org_id)

    def publish_alert(self, org_id: str, alert_data: dict, device_id: Optional[str] = None) -> int:
        """Publish an alert to all active subscribers for the given organization.
        Thread-safe: can be called from worker threads or async tasks.
        """
        subs = list(self._subscribers.get(org_id, set()))
        if not subs:
            return 0

        target_device = device_id or alert_data.get("device_id")
        delivered = 0

        for sub in subs:
            # Device filter check: deliver if subscriber did not filter or filter matches
            if sub.device_id and target_device and sub.device_id != target_device:
                continue

            def _enqueue(q: asyncio.Queue = sub.queue, data: dict = alert_data):
                try:
                    q.put_nowait(data)
                except asyncio.QueueFull:
                    # Drop oldest message to prevent stalled consumers from exhausting memory
                    try:
                        q.get_nowait()
                        q.put_nowait(data)
                    except Exception:
                        pass

            try:
                if sub.loop.is_running():
                    sub.loop.call_soon_threadsafe(_enqueue)
                    delivered += 1
                else:
                    _enqueue()
                    delivered += 1
            except Exception as e:
                log.warning("Failed to dispatch alert to subscriber in org=%s: %s", org_id, e)

        return delivered

    def subscriber_count(self, org_id: Optional[str] = None) -> int:
        """Return the number of active subscribers."""
        if org_id:
            return len(self._subscribers.get(org_id, set()))
        return sum(len(subs) for subs in self._subscribers.values())

    def clear(self) -> None:
        """Clear all active subscriptions (used for testing teardown)."""
        self._subscribers.clear()


# Global shared singleton
broadcaster = AlertBroadcaster()
