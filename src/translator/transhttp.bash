#!/bin/bash
PORT="8080"
if [ "$1" != "" ]; then
    PORT=$1
fi
echo "port $PORT"
iptables -t nat -A OUTPUT -p tcp --dport 80 -m tcp --syn -j REDIRECT --to-ports $PORT
iptables -t nat -A OUTPUT -p tcp --dport 443 -m tcp --syn -j REDIRECT --to-ports $PORT
iptables -t nat -A OUTPUT -p tcp --dport 5001 -m tcp --syn -j REDIRECT --to-ports $PORT
