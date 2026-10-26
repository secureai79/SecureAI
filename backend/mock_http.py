"""
Minimal HTTP mocking for tests, built entirely on httpx.MockTransport (part
of the httpx package we already depend on). Avoids adding a dedicated mocking
library (e.g. respx) as a project dependency, since that's exactly the kind
of "uncommon package" that can go missing in a constrained CI/install
environment — see the README section on dependency hardening.
"""
import httpx


class MockRouter:
    def __init__(self):
        self._routes: list[tuple[str, str, dict | None, httpx.Response]] = []

    def add(self, method: str, url: str, response: httpx.Response, params: dict | None = None) -> None:
        """`url` is matched against the request URL with query string
        stripped (exact path match). If `params` is given, the request's
        query params must also match those key/value pairs — needed to
        distinguish e.g. the same path fetched with different `?ref=` values."""
        self._routes.append((method.upper(), url, params, response))

    def _handler(self, request: httpx.Request) -> httpx.Response:
        request_url = str(request.url)
        path = request_url.split("?")[0]
        query = dict(httpx.QueryParams(request.url.query))
        for method, url, params, response in self._routes:
            if request.method != method or path != url:
                continue
            if params is None or all(query.get(k) == v for k, v in params.items()):
                return response
        return httpx.Response(404, json={"mock_error": "no route registered", "url": str(request.url)})

    def client(self, **kwargs) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handler), **kwargs)
