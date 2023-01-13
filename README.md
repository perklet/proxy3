# proxy3

Man-in-the-middle http/https proxy in a single python script

## Features

* easy to customize
* require no external modules
* support both of IPv4 and IPv6
* support HTTP/1.1 Persistent Connection
* support dynamic certificate generation for HTTPS intercept

This script works on Python 3.10+.
You need to install `openssl` to intercept HTTPS connections.


## Usage

Just clone and run as a script:

    $ python proxy3.py

Or, install using pip:

    $ pip install proxy3
    $ proxy3

Above command runs the proxy on localhost:7777. Verify it works by typing the below
command in another terminal of the same host.

    # test http proxy
    $ http_proxy=localhost:7777 curl http://www.example.com/

To bind to another host or port:

    $ python proxy3.py --host 0.0.0.0 --port 3128


## Enable HTTPS intercept

To intercept HTTPS connections, generate private keys and a private CA certificate:

    $ python proxy3.py --make-certs
    $ https_proxy=localhost:7777 curl https://www.example.com/

Through the proxy, you can access http://proxy3.test/ and install the CA certificate in the browsers.


## Detailed Usage

    $ python proxy3.py --help

    usage: proxy3.py [-h] [-H HOST] [-p PORT] [--timeout TIMEOUT] [--ca-key CA_KEY] [--c
    a-cert CA_CERT] [--ca-signing-key CA_SIGNING_KEY] [--cert-dir CERT_DIR] [--request-h
    andler REQUEST_HANDLER] [--response-handler RESPONSE_HANDLER] [--save-handler SAVE_H
    ANDLER] [--make-certs]

    options:
      -h, --help            show this help message and exit
      -H HOST, --host HOST  Host to bind (default: localhost)
      -p PORT, --port PORT  Port to bind (default: 7777)
      --timeout TIMEOUT     Timeout (default: 5)
      --ca-key CA_KEY       CA key file (default: ./ca-key.pem)
      --ca-cert CA_CERT     CA cert file (default: ./ca-cert.pem)
      --ca-signing-key CA_SIGNING_KEY
                            CA cert key file (default: ./ca-signing-key.pem)
      --cert-dir CERT_DIR   Site certs files (default: ./certs)
      --request-handler REQUEST_HANDLER
                            Request handler function (default: None)
      --response-handler RESPONSE_HANDLER
                            Response handler function (default: None)
      --save-handler SAVE_HANDLER
                            Save handler function, use 'off' to turn off (default: None)

## Customization

You can easily customize the proxy and modify the requests/responses or save something to the files.
The ProxyRequestHandler class has 3 methods to customize:

* request_handler: called before accessing the upstream server
* response_handler: called before responding to the client
* save_handler: called after responding to the client with the exclusive lock, so you can safely write out to the terminal or the file system

By default, only save_handler is implemented which outputs HTTP(S) headers and some useful data to the standard output.
