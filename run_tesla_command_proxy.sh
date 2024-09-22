#!/bin/bash

cd /home/pi/tesla-command-proxy

/usr/local/go/bin/go run /home/pi/tesla-command-proxy/cmd/tesla-http-proxy -tls-key /home/pi/tesla/python/key.pem -cert /home/pi/tesla/python/cert.pem -port 4443 -key-file /home/pi/tesla/python/tesla_private_key.pem -mode owner $1 > tesla-command-proxy.log 2>&1 &
