from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler


def request_handler(
    req: BaseHTTPRequestHandler,
    req_body: str,
) -> str | bool | None:
    print("Request handler invoked, the url: ", req.address_string())
    ...


def response_handler(
    req: BaseHTTPRequestHandler,
    req_body: str,
    res: HTTPResponse,
    res_body: str,
) -> str | bool | None:
    print("Response handler invoked, status code: ", res.status)
    ...


def save_handler(
    req: BaseHTTPRequestHandler,
    req_body: str,
    res: HTTPResponse,
    res_body: str,
):
    ...
