from __future__ import annotations

import urllib.error
import urllib.request
from typing import Dict, Iterator, Optional


class RequestException(Exception):
    """Fallback request exception when the real requests package is unavailable."""


class Response:
    """Minimal response object implementing the subset of the requests API we use."""

    def __init__(self, stream: object) -> None:
        self._stream = stream
        self.status_code = getattr(stream, "status", 200)
        raw_headers = getattr(stream, "headers", {})
        if hasattr(raw_headers, "items"):
            self.headers: Dict[str, str] = dict(raw_headers.items())
        else:
            self.headers = {}
        self._closed = False

    def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
        while True:
            chunk = self._stream.read(chunk_size)
            if not chunk:
                break
            yield chunk
        self.close()

    def raise_for_status(self) -> None:
        if 400 <= int(self.status_code):
            raise RequestException(f"HTTP {self.status_code}")

    def close(self) -> None:
        if not self._closed:
            try:
                self._stream.close()
            finally:
                self._closed = True


def get(url: str, timeout: Optional[int] = None, stream: bool = False) -> Response:
    try:
        response = urllib.request.urlopen(url, timeout=timeout)
        return Response(response)
    except urllib.error.HTTPError as error:
        raise RequestException(f"HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RequestException(str(error)) from error
