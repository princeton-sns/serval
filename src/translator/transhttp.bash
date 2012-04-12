#!/bin/bash
iptables -t nat -F
iptables -t nat -A OUTPUT -p tcp -m tcp --syn -j REDIRECT --to-ports 8080
iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -j DROP
iptables -t nat -A POSTROUTING -p udp -j MASQUERADE

