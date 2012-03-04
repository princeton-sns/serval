#!/bin/bash
iptables -t nat -A OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 81 -m tcp --syn -j REDIRECT --to-ports 8080
