#!/bin/bash
iptables -t nat -A OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 80 -m tcp --syn -j REDIRECT --to-ports 8080
iptables -t nat -A OUTPUT -p tcp --destination 0.0.0.0/0.0.0.0 --dport 443 -m tcp --syn -j REDIRECT --to-ports 8080
