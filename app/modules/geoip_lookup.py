import geoip2.database
import os
import geoip2.errors
import logging

from .utils import get_resource_path

logger = logging.getLogger(__name__)


def geoip_lookup(ip, db_path=None):
    if db_path is None:
        db_path = get_resource_path("data/GeoLite2-City.mmdb")

    if not os.path.exists(db_path):
        logger.error(f"GeoLite2 database not found. Looked at: {db_path}")
        return {"error": f"GeoLite2 database not found. Looked at: {db_path}"}

    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)

            # Extracting safely, handling potential None values
            country_name = response.country.name if response.country else None
            region_name = (
                response.subdivisions.most_specific.name
                if response.subdivisions.most_specific
                else None
            )
            city_name = response.city.name if response.city else None
            latitude = response.location.latitude if response.location else None
            longitude = response.location.longitude if response.location else None

            result = {
                "ip": ip,
                "country": country_name,
                "region": region_name,
                "city": city_name,
                "latitude": latitude,
                "longitude": longitude,
            }
            logger.info(
                f"GeoIP lookup successful for {ip}: {country_name}, {city_name}"
            )
            return result
    except geoip2.errors.AddressNotFoundError:
        logger.warning(f"IP address {ip} not found in GeoLite2 database.")
        return {
            "note": f"IP address {ip} not found in database (likely a CDN or private range)."
        }
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip}: {str(e)}", exc_info=True)
        return {"error": f"GeoIP lookup failed for {ip}: {str(e)}"}
