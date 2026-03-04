import os
import asyncio
import logging
from dotenv import load_dotenv
from urllib.parse import urlencode
import aiohttp
from typing import Union

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FDP_API_URL = os.getenv("FDP_API_URL")
FDP_API_ACCESS = os.getenv("FDP_API_ACCESS")
FDP_API_SECRET = os.getenv("FDP_API_SECRET")

# API configuration
API_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 2  # exponential backoff: 1s, 2s, 4s

headers = {
    "fdp-access": FDP_API_ACCESS,
    "fdp-secret": FDP_API_SECRET
}


async def fetch_fdp_api(
    path: str,
    parameter: dict[str, str] = None,
    timeout: int = API_TIMEOUT,
    max_retries: int = MAX_RETRIES
) -> Union[dict, list]:
    """
    Fetch data from FDP API with retry mechanism and error handling.

    Args:
        path: API endpoint path
        parameter: Query parameters
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts

    Returns:
        API response data (dict or list)

    Raises:
        ValueError: If API returns error response
        aiohttp.ClientError: If network request fails after all retries
        asyncio.TimeoutError: If request times out after all retries
    """
    url = FDP_API_URL + path
    if parameter is not None:
        url += '?' + urlencode(parameter)

    last_exception = None

    for attempt in range(max_retries):
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)

            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                logger.debug(f"API request attempt {attempt + 1}/{max_retries}: {url}")

                async with session.get(url, headers=headers) as resp:
                    # Log response status
                    logger.debug(f"API response status: {resp.status}")

                    # Handle rate limiting (429)
                    if resp.status == 429:
                        retry_after = int(resp.headers.get('Retry-After', RETRY_BACKOFF_FACTOR ** attempt))
                        logger.warning(f"Rate limited. Waiting {retry_after}s before retry...")
                        await asyncio.sleep(retry_after)
                        continue

                    # Handle server errors (5xx) - retry
                    if 500 <= resp.status < 600:
                        logger.warning(f"Server error {resp.status}. Retrying...")
                        await asyncio.sleep(RETRY_BACKOFF_FACTOR ** attempt)
                        continue

                    # Handle client errors (4xx) - don't retry
                    if 400 <= resp.status < 500:
                        error_text = await resp.text()
                        logger.error(f"Client error {resp.status}: {error_text}")
                        raise ValueError(f"API request failed with status {resp.status}: {error_text}")

                    # Parse JSON response
                    try:
                        data = await resp.json()
                    except aiohttp.ContentTypeError as e:
                        logger.error(f"Invalid JSON response: {e}")
                        raise ValueError(f"Invalid JSON response from API: {e}")

                    # Check API-level error codes
                    if data.get('code') == 200 or data.get('status') == "ok":
                        logger.debug(f"API request successful")
                        return data["data"]
                    else:
                        error_msg = data.get('message', 'Unknown error')
                        logger.error(f"API error: {error_msg}")
                        raise ValueError(f"Request API: {url} trigger error: {error_msg}")

        except asyncio.TimeoutError as e:
            last_exception = e
            logger.warning(f"Request timeout (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                await asyncio.sleep(RETRY_BACKOFF_FACTOR ** attempt)
                continue
            else:
                logger.error(f"Request failed after {max_retries} attempts due to timeout")

        except aiohttp.ClientError as e:
            last_exception = e
            logger.warning(f"Network error (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(RETRY_BACKOFF_FACTOR ** attempt)
                continue
            else:
                logger.error(f"Request failed after {max_retries} attempts due to network error")

        except ValueError:
            # Don't retry on ValueError (API-level errors)
            raise

        except Exception as e:
            last_exception = e
            logger.error(f"Unexpected error (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(RETRY_BACKOFF_FACTOR ** attempt)
                continue
            else:
                logger.error(f"Request failed after {max_retries} attempts due to unexpected error")

    # If we get here, all retries failed
    if last_exception:
        raise last_exception
    else:
        raise RuntimeError(f"API request failed after {max_retries} attempts")
