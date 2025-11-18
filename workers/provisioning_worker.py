"""
Lightweight Kafka consumer that reacts to tenant app enable/disable events
and updates provisioning metadata. Acts as a placeholder for real DNS/Ingress
automation until full data-plane integration is built.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from confluent_kafka import Consumer  # type: ignore  # noqa: E402

from shared.database import SessionLocal  # noqa: E402
from shared.models import TenantAppAccess  # noqa: E402
from modules.kafka_publisher import emit_kafka_event  # noqa: E402
from modules.provisioning_engine import ProvisioningContext, ProvisioningEngine  # noqa: E402

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class EventEnvelope:
    event: str
    payload: dict

    @staticmethod
    def from_message(raw: bytes) -> "EventEnvelope":
        data = json.loads(raw.decode("utf-8"))
        return EventEnvelope(event=data.get("event", ""), payload=data.get("payload", {}))


class ProvisioningWorker:
    def __init__(self) -> None:
        self.enabled = os.getenv("PROVISIONING_WORKER_ENABLE", "false").lower() == "true"
        self.bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        self.events_topic = os.getenv("TENANT_EVENTS_TOPIC", "tenant.events.v1")
        self.consumer_group = os.getenv("PROVISIONING_CONSUMER_GROUP", "tenants-provisioner")
        self.provisioning_topic = os.getenv("TENANT_PROVISIONING_TOPIC", "tenant.provisioning.v1")
        self.running = False
        self.consumer: Optional[Consumer] = None

    def start(self) -> None:
        if not self.enabled:
            logger.info("Provisioning worker disabled (PROVISIONING_WORKER_ENABLE=false)")
            return
        conf = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.consumer_group,
            "auto.offset.reset": "earliest",
        }
        logger.info(
            "Starting provisioning worker (topic=%s, group=%s)", self.events_topic, self.consumer_group
        )
        self.consumer = Consumer(conf)
        self.consumer.subscribe([self.events_topic])
        self.running = True
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        while self.running:
            msg = self.consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                logger.error("Kafka error: %s", msg.error())
                continue
            try:
                envelope = EventEnvelope.from_message(msg.value())
                self._handle_event(envelope)
                self.consumer.commit(msg)
            except Exception as exc:
                logger.exception("Failed to process provisioning event: %s", exc)

        logger.info("Provisioning worker stopped")
        self.consumer.close()

    def stop(self, *args, **kwargs) -> None:  # type: ignore[override]
        self.running = False

    def _handle_event(self, envelope: EventEnvelope) -> None:
        if envelope.event == "tenant.app.enabled":
            self._provision_app(envelope.payload)
        elif envelope.event == "tenant.app.disabled":
            self._deprovision_app(envelope.payload)

    def _provision_app(self, payload: dict) -> None:
        tenant_id = payload.get("tenant_id")
        app_name = payload.get("app_name")
        if not tenant_id or not app_name:
            logger.warning("Skipping malformed provisioning payload: %s", payload)
            return
        with self._get_db_session() as db:
            app_access = self._get_app_access(db, tenant_id, app_name)
            if not app_access:
                logger.warning("Tenant %s app %s not found for provisioning", tenant_id, app_name)
                return
            logger.info("Provisioning app %s for tenant %s", app_name, tenant_id)
            context = ProvisioningContext(
                tenant_id=tenant_id,
                tenant_domain=payload.get("tenant_domain"),
                plan_id=payload.get("plan_id"),
                app_name=app_name,
                ingress_hostname=payload.get("ingress_hostname"),
                network_tier=payload.get("network_tier") or app_access.network_tier or "shared",
            )
            engine = ProvisioningEngine()
            engine.provision_app(db, app_access, context)
        asyncio.run(
            emit_kafka_event(
                "tenant.app.provisioned",
                {
                    "tenant_id": tenant_id,
                    "app_name": app_name,
                    "ingress_hostname": payload.get("ingress_hostname"),
                },
                topic=self.provisioning_topic,
            )
        )

    def _deprovision_app(self, payload: dict) -> None:
        tenant_id = payload.get("tenant_id")
        app_name = payload.get("app_name")
        if not tenant_id or not app_name:
            return
        with self._get_db_session() as db:
            app_access = self._get_app_access(db, tenant_id, app_name)
            if not app_access:
                return
            logger.info("Deprovisioning app %s for tenant %s", app_name, tenant_id)
            context = ProvisioningContext(
                tenant_id=tenant_id,
                tenant_domain=payload.get("tenant_domain"),
                plan_id=payload.get("plan_id"),
                app_name=app_name,
                ingress_hostname=payload.get("ingress_hostname") or app_access.ingress_hostname,
                network_tier=payload.get("network_tier") or app_access.network_tier or "shared",
            )
            engine = ProvisioningEngine()
            engine.deprovision_app(db, app_access, context)
        asyncio.run(
            emit_kafka_event(
                "tenant.app.deprovisioned",
                {
                    "tenant_id": tenant_id,
                    "app_name": app_name,
                },
                topic=self.provisioning_topic,
            )
        )

    @staticmethod
    def _get_db_session():
        db = SessionLocal()

        class _SessionContext:
            def __enter__(self):
                return db

            def __exit__(self, exc_type, exc, tb):
                if exc_type:
                    db.rollback()
                else:
                    db.commit()
                db.close()

        return _SessionContext()

    @staticmethod
    def _get_app_access(db: Session, tenant_id: str, app_name: str) -> Optional[TenantAppAccess]:
        return db.query(TenantAppAccess).filter(
            TenantAppAccess.tenant_id == tenant_id,
            TenantAppAccess.app_name == app_name
        ).first()


if __name__ == "__main__":
    ProvisioningWorker().start()
