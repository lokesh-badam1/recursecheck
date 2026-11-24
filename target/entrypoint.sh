#!/bin/sh
mkdir -p /run/named /var/cache/bind
chown bind:bind /run/named /var/cache/bind
# optional per-target setup (packet loss / firewall drop)
[ -f /etc/bind/pre.sh ] && sh /etc/bind/pre.sh
exec named -g -u bind -c /etc/bind/named.conf
