#!/bin/bash
iptables -t nat -A OUTPUT -p tcp --destination 127.0.0.1/255.255.255.255 --dport 80 -m tcp --syn -j REDIRECT --to-ports 8080
