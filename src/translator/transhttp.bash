#!/bin/bash
PORT="8080"
if [ "$1" != "" ]; then
    PORT=$1
fi
echo "redirecting to $PORT"
iptables -F
iptables -t nat -F
iptables -t nat -A OUTPUT -p tcp --dport 80 -m tcp --syn -j REDIRECT --to-ports $PORT
iptables -t nat -A OUTPUT -p tcp --dport 443 -m tcp --syn -j REDIRECT --to-ports $PORT
iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 80 -j DROP
iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 443 -j DROP
iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -j ACCEPT
iptables -t nat -A POSTROUTING ! -o dummy0 -j MASQUERADE
