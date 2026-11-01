import socket
import concurrent.futures
import logging  # Import logging module here
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)  # Initialize logger for this module

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    119,
    123,
    143,
    161,
    194,
    443,
    445,
    465,
    587,
    993,
    995,
    1080,
    1194,
    1433,
    1521,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    8888,
    9090,
    27017,
]


def _scan_single_port(ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)

            # Use connect() and then getpeername() for more explicit connection success
            # Or stick with connect_ex for non-blocking error handling
            # if s.connect_ex((ip, port)) == 0:
            s.connect(
                (ip, port)
            )  # This will raise timeout or ConnectionRefusedError if fails

            # Port is open, try to receive a banner
            banner = ""
            try:
                # Set a shorter timeout for receiving data specifically
                s.settimeout(0.5)

                # For HTTP/HTTPS, send a simple GET request to potentially get a banner
                if port in [80, 443]:
                    s.sendall(
                        b"GET / HTTP/1.0\\r\\nHost: example.com\\r\\nUser-Agent: OSINT-Scanner\\r\n\\r\n"
                    )  # Replace example.com with actual domain if available

                banner_bytes = s.recv(4096)  # Try to receive more data
                banner = banner_bytes.decode("utf-8", errors="ignore").strip()
                if not banner:  # If initial receive is empty, try again briefly
                    banner_bytes = s.recv(4096)
                    banner = banner_bytes.decode("utf-8", errors="ignore").strip()

            except socket.timeout:
                logger.debug(f"Timeout while receiving banner from {ip}:{port}")
                banner = "No banner (timeout)"
            except Exception as receive_e:
                logger.debug(f"Error receiving banner from {ip}:{port}: {receive_e}")
                banner = f"No banner (error: {receive_e})"

            logger.info(f"Port {ip}:{port} is OPEN. Banner: '{banner}'")
            return {
                "port": port,
                "banner": banner if banner else "N/A",
            }  # Ensure "N/A" for consistency
    except (socket.timeout, ConnectionRefusedError, socket.error) as e:
        logger.debug(f"Port {ip}:{port} is CLOSED or unreachable: {e}")
        return None  # Port is closed or unreachable
    except Exception as e:
        logger.error(
            f"Unexpected error during port scan for {ip}:{port}: {e}", exc_info=True
        )
        return None


def scan_ports(
    ip: str, ports: Optional[List[int]] = None, timeout: float = 1.0, workers: int = 20
) -> Dict[str, Any]:
    if not ip:
        logger.error("Invalid IP address provided for port scan.")
        return {"ip": ip, "open_ports": {}, "error": "Invalid IP address provided."}

    ports_to_scan = ports if ports is not None else COMMON_PORTS

    open_ports_with_banners: Dict[
        str, str
    ] = {}  # Change key to str for port to match report
    logger.info(f"Starting port scan for IP: {ip} on {len(ports_to_scan)} ports.")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(_scan_single_port, ip, port, timeout): port
            for port in ports_to_scan
        }

        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports_with_banners[str(result["port"])] = result[
                        "banner"
                    ]  # Store port as string
            except Exception as e:
                logger.error(
                    f"Error retrieving result for port {port}: {e}", exc_info=True
                )
                # Decide if you want to store this error in the final output or just log it

    logger.info(
        f"Port scan completed for {ip}. Found {len(open_ports_with_banners)} open ports."
    )
    return {"ip": ip, "open_ports": open_ports_with_banners}
