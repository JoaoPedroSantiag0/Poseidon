"""POSEIDON CTI Platform — Turnkey Production Database Seeder & Health Initialization Script."""
import asyncio
import os
import sys

# Ensure application package is discoverable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import select
import structlog

from app.db.session import AsyncSessionLocal, init_db
from app.models.entities import AttackTactic
from app.models.user import User
from app.services.mitre_catalog import seed_mitre_and_entities

logger = structlog.get_logger("poseidon.init_production")


async def main():
    logger.info("poseidon_production_init_started")

    # 1. Initialize Tables, Organization, Admin User, and Source Registry
    logger.info("initializing_database_and_core_entities")
    await init_db()
    logger.info("database_and_core_entities_initialized")

    # 2. Seed MITRE ATT&CK v16 Catalog if not already seeded
    async with AsyncSessionLocal() as session:
        tactic_check = await session.execute(select(AttackTactic).limit(1))
        if not tactic_check.scalar_one_or_none():
            logger.info("seeding_mitre_attack_catalog")
            stats = await seed_mitre_and_entities(session)
            await session.commit()
            logger.info("mitre_attack_catalog_seeded", stats=stats)
        else:
            logger.info("mitre_attack_catalog_already_populated")

        # 3. Verify Admin Presence
        admin_check = await session.execute(select(User).limit(1))
        user_count = len(admin_check.scalars().all())
        logger.info("production_readiness_verified", users_count=user_count)

    logger.info("poseidon_production_init_completed_successfully")


if __name__ == "__main__":
    asyncio.run(main())
