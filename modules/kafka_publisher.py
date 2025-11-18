"""
Kafka publisher utility for the tenants service.
Provides a reusable, optional producer that can be toggled via environment variables.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

try:
    from confluent_kafka import Producer  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    Producer = None  # type: ignore

logger = logging.getLogger(__name__)


class KafkaPublisher:
    """Thin wrapper around confluent_kafka Producer with graceful degradation."""

    def __init__(self) -> None:
        self.enabled = os.getenv("KAFKA_ENABLE", "false").lower() == "true"
        self.bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        self.client_id = os.getenv("KAFKA_CLIENT_ID", "tenants-service")
        self.default_topic = os.getenv("TENANT_EVENTS_TOPIC", "tenant.events.v1")
        self._producer: Optional[Producer] = None
        self._lock = asyncio.Lock()

    async def startup(self) -> None:
        """Initialize the producer if Kafka is enabled."""
        if not self.enabled:
            logger.info("KafkaPublisher disabled via KAFKA_ENABLE=false")
            return

        if Producer is None:
            logger.warning("KafkaPublisher enabled but confluent-kafka is not installed")
            return

        async with self._lock:
            if self._producer:
                return

            logger.info(
                "Initializing Kafka producer (client_id=%s, bootstrap=%s)",
                self.client_id,
                self.bootstrap_servers,
            )
            conf = {
                "bootstrap.servers": self.bootstrap_servers,
                "client.id": self.client_id,
            }
            self._producer = Producer(conf)

    async def shutdown(self) -> None:
        """Flush any pending messages."""
        if not self._producer:
            return
        async with self._lock:
            if not self._producer:
                return
            logger.info("Flushing Kafka producer buffers")
            self._producer.flush(5)
            self._producer = None

    async def publish_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        topic: Optional[str] = None,
        key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Publish a JSON event if Kafka is available."""
        if not self.enabled or Producer is None:
            logger.debug("Kafka disabled; skipping event %s", event_type)
            return False
        if not self._producer:
            await self.startup()
        if not self._producer:
            return False

        envelope = {
            "event": event_type,
            "service": "tenants-service",
            "timestamp": datetime.utcnow().isoformat(),
            "payload": payload,
        }
        message = json.dumps(envelope, default=str).encode("utf-8")
        headers_list = (
            [(k, v.encode("utf-8")) for k, v in headers.items()] if headers else None
        )

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._produce,
            topic or self.default_topic,
            key,
            message,
            headers_list,
        )

    def _produce(
        self,
        topic: str,
        key: Optional[str],
        value: bytes,
        headers: Optional[list[tuple[str, bytes]]],
    ) -> bool:
        """Synchronous producer call executed in a thread executor."""
        if not self._producer:
            return False
        try:
            self._producer.produce(
                topic=topic,
                key=key.encode("utf-8") if key else None,
                value=value,
                headers=headers,
            )
            self._producer.poll(0)
            return True
        except BufferError as exc:
            logger.warning("Kafka buffer full: %s", exc)
            self._producer.poll(1)
            return False
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to publish Kafka event: %s", exc)
            return False


kafka_publisher = KafkaPublisher()


async def emit_kafka_event(
    event_type: str,
    payload: Dict[str, Any],
    *,
    topic: Optional[str] = None,
    key: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> bool:
    """Helper exposed to the rest of the app."""
    return await kafka_publisher.publish_event(
        event_type,
        payload,
        topic=topic,
        key=key,
        headers=headers,
    )
