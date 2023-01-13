#!/usr/bin/env bash

trap 'kill $(jobs -p)' EXIT
export PYTHONPATH=.

python proxy3.py --request-handler examples.example:request_handler \
    --response-handler examples.example:response_handler \
    --save-handler off &
sleep 2
export http_proxy=localhost:7777
export https_proxy=localhost:7777
curl http://httpbin.org/get
curl https://httpbin.org/get -k
