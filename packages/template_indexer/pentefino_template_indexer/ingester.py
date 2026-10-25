from datetime import datetime, timezone
from typing import Any
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.models.template import TemplateCatalog
from pentefino_template_indexer.classifier import TemplateMetadata


class TemplateCatalogIngester:
    """Batches and upserts parsed TemplateMetadata into PostgreSQL template_catalog table."""

    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def ingest_batch(
        self,
        templates: list[TemplateMetadata],
        upstream_revision: str,
        batch_size: int = 500,
    ) -> int:
        """
        Persist a list of TemplateMetadata into template_catalog in batches.

        Uses PostgreSQL ON CONFLICT (id) DO UPDATE to perform idempotent upserts.
        Returns the total number of ingested/updated templates.
        """
        if not templates:
            return 0

        total_ingested = 0

        # Chunk templates
        for i in range(0, len(templates), batch_size):
            chunk = templates[i : i + batch_size]
            batch_data: list[dict[str, Any]] = []

            for t in chunk:
                impact_val = (
                    t.impact_class.value
                    if hasattr(t.impact_class, "value")
                    else str(t.impact_class)
                )
                batch_data.append(
                    {
                        "id": t.id,
                        "file_path": t.file_path,
                        "upstream_revision": upstream_revision,
                        "bundle_hash": t.bundle_hash,
                        "name": t.name,
                        "protocol": t.protocol,
                        "http_methods": t.http_methods if t.http_methods else None,
                        "impact_class": impact_val,
                        "cve_id": t.cve_id,
                        "cwe_id": t.cwe_id,
                        "severity": t.severity,
                        "technologies": t.technologies if t.technologies else None,
                        "tags": t.tags if t.tags else None,
                        "raw_yaml": t.raw_yaml,
                    }
                )

            await self._upsert_chunk(batch_data)
            total_ingested += len(chunk)

        await self.db_session.commit()
        return total_ingested

    async def _upsert_chunk(self, batch_data: list[dict[str, Any]]) -> None:
        if not batch_data:
            return

        bind = self.db_session.bind
        dialect_name = bind.dialect.name if bind else "postgresql"

        if dialect_name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = pg_insert(TemplateCatalog).values(batch_data)
            stmt = stmt.on_conflict_do_update(
                index_elements=[TemplateCatalog.id],
                set_={
                    "file_path": stmt.excluded.file_path,
                    "upstream_revision": stmt.excluded.upstream_revision,
                    "bundle_hash": stmt.excluded.bundle_hash,
                    "name": stmt.excluded.name,
                    "protocol": stmt.excluded.protocol,
                    "http_methods": stmt.excluded.http_methods,
                    "impact_class": stmt.excluded.impact_class,
                    "cve_id": stmt.excluded.cve_id,
                    "cwe_id": stmt.excluded.cwe_id,
                    "severity": stmt.excluded.severity,
                    "technologies": stmt.excluded.technologies,
                    "tags": stmt.excluded.tags,
                    "raw_yaml": stmt.excluded.raw_yaml,
                    "updated_at": func.now(),
                },
            )
            await self.db_session.execute(stmt)

        elif dialect_name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = sqlite_insert(TemplateCatalog).values(batch_data)
            stmt = stmt.on_conflict_do_update(
                index_elements=[TemplateCatalog.id],
                set_={
                    "file_path": stmt.excluded.file_path,
                    "upstream_revision": stmt.excluded.upstream_revision,
                    "bundle_hash": stmt.excluded.bundle_hash,
                    "name": stmt.excluded.name,
                    "protocol": stmt.excluded.protocol,
                    "http_methods": stmt.excluded.http_methods,
                    "impact_class": stmt.excluded.impact_class,
                    "cve_id": stmt.excluded.cve_id,
                    "cwe_id": stmt.excluded.cwe_id,
                    "severity": stmt.excluded.severity,
                    "technologies": stmt.excluded.technologies,
                    "tags": stmt.excluded.tags,
                    "raw_yaml": stmt.excluded.raw_yaml,
                    "updated_at": func.now(),
                },
            )
            await self.db_session.execute(stmt)

        else:
            # Generic fallback
            for item in batch_data:
                obj = await self.db_session.get(TemplateCatalog, item["id"])
                if obj:
                    for k, v in item.items():
                        setattr(obj, k, v)
                    obj.updated_at = datetime.now(timezone.utc)
                else:
                    self.db_session.add(TemplateCatalog(**item))
