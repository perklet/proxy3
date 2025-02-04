import re
from collections import deque

replaced_urls = deque(maxlen=1024)


def request_handler(req, req_body):
    if req.path in replaced_urls:
        req.path = req.path.replace("http://", "https://")


def response_handler(req, req_body, res, res_body):
    def replacefunc(m):
        http_url = "http://" + m.group(1)
        replaced_urls.append(http_url)
        return http_url

    re_https_url = r"https://([-_.!~*'()a-zA-Z0-9;/?:@&=+$,%]+)"

    if "Location" in res.headers:
        res.headers["Location"] = re.sub(
            re_https_url, replacefunc, res.headers["Location"]
        )
    return re.sub(re_https_url, replacefunc, res_body)
