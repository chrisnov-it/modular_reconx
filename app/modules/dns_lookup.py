# modules/dns_lookup.py (Versi Final)

import dns.resolver
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.TXT
import logging
from typing import Dict, List, Any

# Import cache decorator
from .cache import cache_result

logger = logging.getLogger(__name__)


@cache_result(timeout=3600)  # Cache for 1 hour
def get_dns(domain: str) -> Dict[str, Any]:
    """
    Fetches common DNS records using a custom resolver and robust per-record-type handling.
    """
    # 1. Membuat instance resolver kita sendiri
    my_resolver = dns.resolver.Resolver()

    # 2. Menetapkan server DNS publik yang andal untuk ditanyai
    my_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS
    my_resolver.timeout = 5
    my_resolver.lifetime = 5

    result: Dict[str, List[str]] = {"A": [], "MX": [], "NS": [], "TXT": []}

    for record_type in result.keys():
        try:
            # 3. Menggunakan resolver kustom kita untuk setiap query
            answers = my_resolver.resolve(domain, record_type)

            # 4. Parsing spesifik untuk setiap tipe record agar hasilnya bersih
            for rdata in answers:
                if record_type == "A":
                    result[record_type].append(rdata.to_text())
                elif record_type == "MX" and isinstance(rdata, dns.rdtypes.ANY.MX.MX):
                    result[record_type].append(
                        f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True)}"
                    )
                elif record_type == "NS" and isinstance(rdata, dns.rdtypes.ANY.NS.NS):
                    result[record_type].append(
                        rdata.target.to_text(omit_final_dot=True)
                    )
                elif record_type == "TXT" and isinstance(
                    rdata, dns.rdtypes.ANY.TXT.TXT
                ):
                    full_txt = b"".join(rdata.strings).decode("utf-8").strip('"')
                    result[record_type].append(full_txt)
                elif record_type in ["MX", "NS", "TXT"]:
                    # Fallback for other record types
                    result[record_type].append(rdata.to_text())

        except Exception as e:
            # Jika ada error apa pun (timeout, no answer, etc.), catat dan lanjutkan
            logger.warning(f"Could not resolve {record_type} for {domain}: {e}")
            result[record_type] = []  # Pastikan hasilnya list kosong

    return result
