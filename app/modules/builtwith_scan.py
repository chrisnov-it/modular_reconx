import builtwith
import logging  # Import logging module here

logger = logging.getLogger(__name__)  # Initialize logger for this module


def detect_builtwith(domain):
    try:
        if not domain.startswith(("http://", "https://")):
            domain = f"http://{domain}"

        logger.info(
            f"Attempting Builtwith scan for: {domain}"
        )  # Add logging for successful start
        results = builtwith.parse(domain)

        if not results:
            logger.info(
                f"No Builtwith results found for {domain}."
            )  # Log if no results
            return {}

        logger.info(f"Builtwith scan successful for {domain}.")  # Log success
        return results
    except Exception as e:
        logger.error(
            f"Builtwith scan failed for {domain}: {str(e)}", exc_info=True
        )  # Log the error
        return {"error": f"Builtwith scan failed for {domain}: {str(e)}"}
