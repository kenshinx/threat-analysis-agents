import os
from dotenv import load_dotenv
from urllib.parse import urlencode
import aiohttp
from typing import Union
load_dotenv()

FDP_API_URL = os.getenv("FDP_API_URL")
FDP_API_ACCESS = os.getenv("FDP_API_ACCESS")
FDP_API_SECRET = os.getenv("FDP_API_SECRET")

headers = {
    "fdp-access": FDP_API_ACCESS,
    "fdp-secret": FDP_API_SECRET
}


async def fetch_fdp_api(path: str, parameter: dict[str, str] = None) -> Union[dict, list]:
    url = FDP_API_URL + path
    if parameter is not None:
        url += '?' + urlencode(parameter)
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            data = await resp.json()
            if data.get('code') == 200 or data.get('status') == "ok":
                return data["data"]
            else:
                raise ValueError(
                    f"Request API: {url} trigger error: {data['message']}")
