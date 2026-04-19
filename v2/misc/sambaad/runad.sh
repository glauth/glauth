#!/usr/bin/env bash

for arg in "$@"; do
    if [[ "$arg" == *"="* ]]; then
        key="${arg%%=*}"
        value="${arg#*=}"
        eval "$key"="'$value'"
    else
        eval "$arg"=true
    fi
done

if [[ "$ipaddr" == "" ]]; then
    echo "Please provide ipaddr=<ip address> to create/use" >&2
    exit 1
fi

if [[ "$ipmask" == "" ]]; then
    ipmask=24
fi

eipaddr=$(echo "$ipaddr" | sed 's/\./\\./g')
ifname=$(ip -brief addr show | awk "/$eipaddr\// {print \$1}")
if [[ "$ifname" == "" ]]; then
    ping -c 1 $ipaddr &>/dev/null
    if [[ $? -eq 0 ]]; then
        echo "It looks like you specified an already allocated ip address." >&2
        exit 1
    fi
fi

if [[ "$ifname" == "" ]]; then
    passed=0
    if [[ "$ipmask" == "" ]]; then
        passed=1
    fi
    if [[ "$iface" == "" ]]; then
        passed=2
    fi
    if [[ $passed -ne 0 ]]; then
        echo "To create an interface, specify ipaddr=<ip address> ipmask=<mask> iface=<interface name>" >&2
        echo "Example: ipaddr=192.168.1.222 ipmask=24 iface=en0" >&2
        exit 1
    fi
    echo "Creating $ipaddr/$ipmask on interface $iface"
    sudo ip addr add $ipaddr/$ipmask dev $iface
fi

if [[ "$domain" == "" ]]; then
    domain="TEST.EXAMPLE.COM"
fi
if [[ "$defaultdns" == "" ]]; then
    defaultdns="192.168.1.1"
fi

echo "Running Samba AD, listening on $ipaddr for domain $domain"
docker run -d
    --name ad \
    --hostname DC1 \
    --restart unless-stopped \
    -e REALM='TEST.LOCAL' \
    -e DOMAIN='TEST' \
    -e ADMIN_PASS='MySecret2026!' \
    -e DNS_FORWARDER='8.8.8.8' \
    -v dc_etc:/usr/local/samba/etc \
    -v dc_private:/usr/local/samba/private \
    -v dc_var:/usr/local/samba/var \
    -p $ipaddr:53:53 \
    -p $ipaddr:53:53/udp \
    -p $ipaddr:88:88 \
    -p $ipaddr:88:88/udp \
    -p $ipaddr:135:135 \
    -p $ipaddr:137-138:137-138/udp \
    -p $ipaddr:139:139 \
    -p $ipaddr:389:389 \
    -p $ipaddr:389:389/udp \
    -p $ipaddr:445:445 \
    -p $ipaddr:464:464 \
    -p $ipaddr:464:464/udp \
    -p $ipaddr:636:636 \
    -p $ipaddr:1024-1044:1024-1044 \
    -p $ipaddr:3268-3269:3268-3269 \
    diegogslomp/samba-ad-dc
