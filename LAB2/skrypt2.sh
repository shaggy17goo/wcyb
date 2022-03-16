#!/bin/bash

iptables -F
iptables -A INPUT -p tcp -m multiport --dports 21,80 -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ACK -j DROP
