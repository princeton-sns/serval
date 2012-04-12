#!/bin/bash
ip rule add to 128.112.7.54 table main priority 10
ip rule add from 192.168.25.0/24 table main priority 20
ip rule add from all table priority 30
ip route add default via 192.168.25.25 dev dummy0
