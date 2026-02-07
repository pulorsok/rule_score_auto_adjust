import os
import dotenv
import diskcache
import enum
import requests
from threading import Timer
from typing import Any
from threading import BoundedSemaphore
import time
import re


class RatedSemaphore(BoundedSemaphore):
    """Limit to 1 request per `period / value` seconds (over long run)."""

    def __init__(self, value=1, period=1):
        BoundedSemaphore.__init__(self, value)
        t = Timer(period, self._add_token_loop, kwargs=dict(time_delta=float(period) / value))
        t.daemon = True
        t.start()

    def _add_token_loop(self, time_delta):
        """Add token every time_delta seconds."""
        while True:
            try:
                BoundedSemaphore.release(self)
            except ValueError:  # ignore if already max possible value
                pass
            time.sleep(time_delta)  # ignore ENTER

    def release(self):
        pass  # do nothing (only time-based release() is allowed)


class Status(enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    NO_REPORT = "no_report"


dotenv.load_dotenv()
cache = diskcache.FanoutCache(f"{os.getenv('CACHE_FOLDER')}/vt_report")
lock = RatedSemaphore(4, 60)


@cache.memoize()
def get_virus_total_report(
    sha256: str, api_key: str | None = os.getenv("VIRUS_TOTAL_API_KEY")
) -> tuple[dict[str, Any], Status]:
    with lock:
        print(f"Requesting VirusTotal report for {sha256}")
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"

        headers = {
            "accept": "application/json",
            "x-apikey": api_key,
        }

        response = requests.get(url, headers=headers)

        json_rep = response.json()
        status = Status.SUCCESS if response.status_code == 200 else Status.FAILED

        cache.set(
            sha256,
            json_rep,
            tag=status.value,
        )

        return json_rep, status


def get_threat_label(sha256: str, api_key: str | None = os.getenv("VIRUS_TOTAL_API_KEY")) -> dict[str, str]:
    try:
        report, _ = get_virus_total_report(sha256, api_key)

        threat_label = (
            report.get("data", {})
            .get("attributes", {})
            .get("popular_threat_classification", {})
            .get("suggested_threat_label", "./")
        )

        parts = re.split("[./]", threat_label)
        major = parts[0] if len(parts) > 0 else ""
        middle = parts[1] if len(parts) > 1 else ""
        minor = parts[2] if len(parts) > 2 else ""

        return {
            "major_threat_label": major,
            "middle_threat_label": middle,
            "minor_threat_label": minor,
        }

    except BaseException as e:
        print(f"Error on {sha256}: {e}")
        return {
            "major_threat_label": "",
            "middle_threat_label": "",
            "minor_threat_label": "",
        }
