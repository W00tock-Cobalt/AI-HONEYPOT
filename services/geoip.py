"""
GeoIP lookup service using MaxMind GeoLite2 database.
"""

import os
from typing import Optional
from dataclasses import dataclass

import geoip2.database
import geoip2.errors
from rich.console import Console

console = Console()


@dataclass
class GeoIPResult:
    """Geolocation lookup result."""
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None


class GeoIPService:
    """Service for IP geolocation lookups."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.city_reader: Optional[geoip2.database.Reader] = None
        self.asn_reader: Optional[geoip2.database.Reader] = None
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize the GeoIP database readers."""
        try:
            if os.path.exists(self.db_path):
                self.city_reader = geoip2.database.Reader(self.db_path)
                self._initialized = True
                console.print(f"[green]GeoIP database loaded: {self.db_path}[/green]")
                return True
            else:
                console.print(
                    f"[yellow]GeoIP database not found at {self.db_path}[/yellow]"
                )
                console.print("[yellow]Run setup.sh to download the database[/yellow]")
                return False
        except Exception as e:
            console.print(f"[red]Failed to load GeoIP database: {e}[/red]")
            return False

    def close(self):
        """Close database readers."""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()

    def lookup(self, ip_address: str) -> GeoIPResult:
        """Look up geolocation for an IP address."""
        result = GeoIPResult()

        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return result

        if not self._initialized or not self.city_reader:
            return result

        try:
            response = self.city_reader.city(ip_address)

            result.country_code = response.country.iso_code
            result.country_name = response.country.name
            result.city = response.city.name
            result.latitude = response.location.latitude
            result.longitude = response.location.longitude

            # ASN info is included in GeoLite2-City
            if hasattr(response, 'traits') and response.traits:
                result.asn = getattr(response.traits, 'autonomous_system_number', None)
                result.asn_org = getattr(
                    response.traits, 'autonomous_system_organization', None
                )

        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            console.print(f"[yellow]GeoIP lookup error for {ip_address}: {e}[/yellow]")

        return result

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private/local (RFC-1918 + loopback + link-local)."""
        if ip.startswith(('10.', '192.168.', '127.', 'fe80:')):
            return True
        if ip in ('localhost', '::1'):
            return True
        # 172.16.0.0/12 — only 172.16.x.x through 172.31.x.x are private
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (IndexError, ValueError):
                pass
        return False


# Singleton instance
_geoip_service: Optional[GeoIPService] = None


def get_geoip_service(db_path: Optional[str] = None) -> GeoIPService:
    """Get or create GeoIP service singleton."""
    global _geoip_service
    if _geoip_service is None:
        if db_path is None:
            db_path = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")
        _geoip_service = GeoIPService(db_path)
        _geoip_service.initialize()
    return _geoip_service
