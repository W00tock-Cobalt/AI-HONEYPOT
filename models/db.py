"""
Database models and async SQLAlchemy setup for honeypot logging.

Includes automatic schema migration for SQLite databases.
"""

import hashlib
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    DateTime,
    Index,
    JSON,
    Float,
    Boolean,
    select,
    func,
    text,
    inspect,
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from rich.console import Console

console = Console()

Base = declarative_base()

# Schema version - increment when adding new columns
SCHEMA_VERSION = 2

# New columns added in each version (for migration)
SCHEMA_MIGRATIONS = {
    2: [
        # AI Analysis columns (Groq integration)
        ("threat_level", "VARCHAR(20)"),
        ("threat_type", "VARCHAR(50)"),
        ("ai_summary", "TEXT"),
        ("ai_details", "TEXT"),
        ("ai_recommendations", "JSON"),
        ("ai_iocs", "JSON"),
        ("ai_confidence", "FLOAT"),
        ("ai_analyzed_at", "DATETIME"),
    ],
}


class Request(Base):
    """Logged honeypot request."""

    __tablename__ = "requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Source identification
    source_ip = Column(String(45), nullable=False, index=True)  # IPv6 max length
    source_port = Column(Integer, nullable=True)

    # Geolocation
    country_code = Column(String(2), nullable=True, index=True)
    country_name = Column(String(100), nullable=True)
    city = Column(String(200), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String(300), nullable=True, index=True)

    # Request details
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False, index=True)
    query_string = Column(Text, nullable=True)
    headers = Column(JSON, nullable=True)
    body_raw = Column(Text, nullable=True)
    body_parsed = Column(JSON, nullable=True)

    # OpenAI-specific extracted fields
    auth_header = Column(String(500), nullable=True, index=True)
    api_key = Column(String(200), nullable=True, index=True)
    model_requested = Column(String(100), nullable=True, index=True)
    messages = Column(JSON, nullable=True)
    prompt = Column(Text, nullable=True)

    # Response sent
    response_status = Column(Integer, nullable=False, default=200)
    response_body = Column(Text, nullable=True)
    response_time_ms = Column(Float, nullable=True)

    # Fingerprinting and classification
    session_fingerprint = Column(String(64), nullable=True, index=True)
    user_agent = Column(String(500), nullable=True)
    classification = Column(String(50), nullable=True, index=True)
    classification_confidence = Column(Float, nullable=True)
    classification_reasons = Column(JSON, nullable=True)

    # Metadata
    is_flagged = Column(Boolean, default=False, index=True)
    notes = Column(Text, nullable=True)

    # AI Analysis (Groq)
    threat_level = Column(String(20), nullable=True, index=True)  # low, medium, high, critical
    threat_type = Column(String(50), nullable=True, index=True)
    ai_summary = Column(Text, nullable=True)
    ai_details = Column(Text, nullable=True)
    ai_recommendations = Column(JSON, nullable=True)
    ai_iocs = Column(JSON, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index('idx_timestamp_ip', 'timestamp', 'source_ip'),
        Index('idx_api_key_timestamp', 'api_key', 'timestamp'),
        Index('idx_classification_timestamp', 'classification', 'timestamp'),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "headers": self.headers,
            "body_raw": self.body_raw,
            "body_parsed": self.body_parsed,
            "auth_header": self.auth_header,
            "api_key": self.api_key,
            "model_requested": self.model_requested,
            "messages": self.messages,
            "prompt": self.prompt,
            "response_status": self.response_status,
            "response_body": self.response_body,
            "response_time_ms": self.response_time_ms,
            "session_fingerprint": self.session_fingerprint,
            "user_agent": self.user_agent,
            "classification": self.classification,
            "classification_confidence": self.classification_confidence,
            "classification_reasons": self.classification_reasons,
            "is_flagged": self.is_flagged,
            "notes": self.notes,
            "threat_level": self.threat_level,
            "threat_type": self.threat_type,
            "ai_summary": self.ai_summary,
            "ai_details": self.ai_details,
            "ai_recommendations": self.ai_recommendations,
            "ai_iocs": self.ai_iocs,
            "ai_confidence": self.ai_confidence,
            "ai_analyzed_at": self.ai_analyzed_at.isoformat() if self.ai_analyzed_at else None,
        }


class Database:
    """Async database manager."""

    def __init__(self, database_url: str):
        self.engine = create_async_engine(
            database_url,
            echo=False,
            pool_pre_ping=True,
        )
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def init_db(self):
        """Create all tables and run migrations."""
        async with self.engine.begin() as conn:
            # Create tables if they don't exist
            await conn.run_sync(Base.metadata.create_all)

            # Run migrations for existing tables
            await self._migrate_schema(conn)

    async def _migrate_schema(self, conn):
        """Check and apply schema migrations for existing databases."""
        try:
            # Get existing columns
            result = await conn.execute(text("PRAGMA table_info(requests)"))
            existing_columns = {row[1] for row in result.fetchall()}

            if not existing_columns:
                # Table doesn't exist yet, will be created by create_all
                return

            migrations_applied = 0

            # Apply missing columns from all versions
            for version, columns in SCHEMA_MIGRATIONS.items():
                for col_name, col_type in columns:
                    if col_name not in existing_columns:
                        try:
                            await conn.execute(
                                text(f"ALTER TABLE requests ADD COLUMN {col_name} {col_type}")
                            )
                            console.print(f"[green]Migration: Added column '{col_name}'[/green]")
                            migrations_applied += 1
                        except Exception as e:
                            # Column might already exist or other error
                            console.print(f"[yellow]Migration warning for '{col_name}': {e}[/yellow]")

            if migrations_applied > 0:
                console.print(f"[green]Applied {migrations_applied} schema migrations[/green]")

        except Exception as e:
            console.print(f"[yellow]Migration check skipped: {e}[/yellow]")

    async def close(self):
        """Close database connections."""
        await self.engine.dispose()

    def get_session(self) -> AsyncSession:
        """Get a new async session."""
        return self.async_session()

    async def log_request(self, request_data: dict) -> Request:
        """Log a request to the database."""
        async with self.async_session() as session:
            request = Request(**request_data)
            session.add(request)
            await session.commit()
            await session.refresh(request)
            return request

    async def get_recent_requests(self, limit: int = 100) -> list[Request]:
        """Get most recent requests."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Request)
                .order_by(Request.timestamp.desc())
                .limit(limit)
            )
            return result.scalars().all()

    async def get_stats(self) -> dict:
        """Get aggregated statistics."""
        async with self.async_session() as session:
            # Total requests
            total = await session.execute(select(func.count(Request.id)))
            total_count = total.scalar() or 0

            # Unique IPs
            unique_ips = await session.execute(
                select(func.count(func.distinct(Request.source_ip)))
            )
            unique_ip_count = unique_ips.scalar() or 0

            # Unique API keys
            unique_keys = await session.execute(
                select(func.count(func.distinct(Request.api_key)))
                .where(Request.api_key.isnot(None))
            )
            unique_key_count = unique_keys.scalar() or 0

            # Top countries
            countries = await session.execute(
                select(Request.country_code, func.count(Request.id).label('count'))
                .where(Request.country_code.isnot(None))
                .group_by(Request.country_code)
                .order_by(func.count(Request.id).desc())
                .limit(10)
            )
            top_countries = [{"code": r[0], "count": r[1]} for r in countries.all()]

            # Classifications breakdown
            classifications = await session.execute(
                select(Request.classification, func.count(Request.id).label('count'))
                .group_by(Request.classification)
                .order_by(func.count(Request.id).desc())
            )
            classification_breakdown = {
                r[0] or "unclassified": r[1] for r in classifications.all()
            }

            # Top paths
            paths = await session.execute(
                select(Request.path, func.count(Request.id).label('count'))
                .group_by(Request.path)
                .order_by(func.count(Request.id).desc())
                .limit(10)
            )
            top_paths = [{"path": r[0], "count": r[1]} for r in paths.all()]

            # Top ASN orgs
            asn_orgs = await session.execute(
                select(Request.asn_org, func.count(Request.id).label('count'))
                .where(Request.asn_org.isnot(None))
                .group_by(Request.asn_org)
                .order_by(func.count(Request.id).desc())
                .limit(10)
            )
            top_asn_orgs = [{"org": r[0], "count": r[1]} for r in asn_orgs.all()]

            # Requests per hour (last 24 hours)
            from datetime import timedelta
            day_ago = datetime.utcnow() - timedelta(hours=24)
            hourly = await session.execute(
                select(
                    func.strftime('%Y-%m-%d %H:00', Request.timestamp).label('hour'),
                    func.count(Request.id).label('count')
                )
                .where(Request.timestamp >= day_ago)
                .group_by(func.strftime('%Y-%m-%d %H:00', Request.timestamp))
                .order_by(func.strftime('%Y-%m-%d %H:00', Request.timestamp))
            )
            requests_per_hour = [{"hour": r[0], "count": r[1]} for r in hourly.all()]

            return {
                "total_requests": total_count,
                "unique_ips": unique_ip_count,
                "unique_api_keys": unique_key_count,
                "top_countries": top_countries,
                "classification_breakdown": classification_breakdown,
                "top_paths": top_paths,
                "top_asn_orgs": top_asn_orgs,
                "requests_per_hour": requests_per_hour,
            }

    async def get_map_data(self) -> list[dict]:
        """Get location data for map visualization."""
        async with self.async_session() as session:
            result = await session.execute(
                select(
                    Request.latitude,
                    Request.longitude,
                    Request.city,
                    Request.country_name,
                    Request.source_ip,
                    func.count(Request.id).label('count')
                )
                .where(Request.latitude.isnot(None))
                .where(Request.longitude.isnot(None))
                .group_by(
                    Request.latitude,
                    Request.longitude,
                    Request.city,
                    Request.country_name,
                    Request.source_ip
                )
            )
            return [
                {
                    "lat": r[0],
                    "lng": r[1],
                    "city": r[2],
                    "country": r[3],
                    "ip": r[4],
                    "count": r[5],
                }
                for r in result.all()
            ]

    async def update_analysis(
        self,
        request_id: int,
        threat_level: str,
        threat_type: str,
        ai_summary: str,
        ai_details: str,
        ai_recommendations: list,
        ai_iocs: list,
        ai_confidence: float,
    ):
        """Update a request with AI analysis results."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Request).where(Request.id == request_id)
            )
            request = result.scalar_one_or_none()
            if request:
                request.threat_level = threat_level
                request.threat_type = threat_type
                request.ai_summary = ai_summary
                request.ai_details = ai_details
                request.ai_recommendations = ai_recommendations
                request.ai_iocs = ai_iocs
                request.ai_confidence = ai_confidence
                request.ai_analyzed_at = datetime.utcnow()
                await session.commit()

    async def get_request(self, request_id: int) -> Optional[Request]:
        """Get a single request by ID."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Request).where(Request.id == request_id)
            )
            return result.scalar_one_or_none()

    async def export_requests(
        self,
        format: str = "json",
        limit: Optional[int] = None,
        classification: Optional[str] = None,
    ) -> list[dict]:
        """Export requests for download."""
        async with self.async_session() as session:
            query = select(Request).order_by(Request.timestamp.desc())

            if classification:
                query = query.where(Request.classification == classification)
            if limit:
                query = query.limit(limit)

            result = await session.execute(query)
            return [r.to_dict() for r in result.scalars().all()]

    async def get_threat_stats(self) -> dict:
        """Get threat level statistics."""
        async with self.async_session() as session:
            # Threat level breakdown
            threat_levels = await session.execute(
                select(Request.threat_level, func.count(Request.id).label('count'))
                .where(Request.threat_level.isnot(None))
                .group_by(Request.threat_level)
                .order_by(func.count(Request.id).desc())
            )
            threat_breakdown = {r[0]: r[1] for r in threat_levels.all()}

            # Threat type breakdown
            threat_types = await session.execute(
                select(Request.threat_type, func.count(Request.id).label('count'))
                .where(Request.threat_type.isnot(None))
                .group_by(Request.threat_type)
                .order_by(func.count(Request.id).desc())
            )
            type_breakdown = {r[0]: r[1] for r in threat_types.all()}

            # High/critical threats
            critical_count = await session.execute(
                select(func.count(Request.id))
                .where(Request.threat_level.in_(['high', 'critical']))
            )

            return {
                "threat_levels": threat_breakdown,
                "threat_types": type_breakdown,
                "critical_threats": critical_count.scalar() or 0,
            }


def generate_session_fingerprint(
    user_agent: str,
    accept_language: str,
    accept_encoding: str,
) -> str:
    """Generate a session fingerprint from request headers."""
    data = f"{user_agent}|{accept_language}|{accept_encoding}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]
