

def request_handler(req, req_body: bytes) -> str | bool:
    ...


def response_handler(req, req_body, res, res_body) -> str | bool:
    ...


def save_handler(req, req_body, res, res_body):
    ...
