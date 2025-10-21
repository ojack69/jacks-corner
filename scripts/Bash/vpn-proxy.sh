#!/bin/bash

# Based on: https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/
# This script setups a Wireguard server docker container.
# The traffic on configured ports (REDIRECTED_TCP_PORTS - expecting HTTP/HTTPS traffic) will be redirected to the container's listening proxy.
# The main purpose of this script is to allow intercepting HTTP/HTTPs traffic during security assessment on Flutter applications.


# Settings
VPN_SUBNET=10.80.80.0
VPN_UDP_PORT=51820 
VPN_PEER_DNS=1.1.1.1
REDIRECTED_TCP_PORTS="80,443"
LOCAL_INTERFACE="wlp1s0"
LOCAL_PORT=8080
LOCAL_HOST="$(ifconfig $LOCAL_INTERFACE | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
CONTAINER_NAME="wg-proxy-vpn-server"
CONFIG_PATH="/home/$(whoami)/.wg-proxy-vpn"

function get_config(){
    config_path="$CONFIG_PATH/config/peer1/peer1.conf"
    echo -e "\e[34m[!]\e[39m Use the following client config file: $config_path"

    echo -e "\n==========================================================="
    cat "$config_path" | sed -E 's/ListenPort = [0-9]+//g'
    echo -e "\n==========================================================="

    qrencode_exist=$(which qrencode)
    if [[ -n "$qrencode_exist" ]];then
        echo -e "\n==========================================================="
        cat "$config_path" | sed -E 's/ListenPort = [0-9]+//g' | qrencode -t ANSI
        echo -e "\n==========================================================="
    fi
}


printf "
 __     ______  _   _   ____                      
 \ \   / /  _ \| \ | | |  _ \ _ __ _____  ___   _ 
  \ \ / /| |_) |  \| | | |_) | '__/ _ \ \/ / | | |
   \ V / |  __/| |\  | |  __/| | | (_) >  <| |_| |
    \_/  |_|   |_| \_| |_|   |_|  \___/_/\_\\__, |
                                            |___/ 

"

# Action and Usage
action="$1"
if [[ "$action" != "start" && "$action" != "stop" && "$action" != "config" ]]; then
    echo "Usage: $0 [start|stop|config]"
    exit 1
fi

# Docker installed and running checks
check_docker_installed=$(which docker)
if [[ -z "$check_docker_installed" ]]; then
    echo -e "\e[31m[x]\e[39m Docker is not installed!"
    exit 1
fi

check_docker_running=$(docker ps)

if [[ -z "$check_docker_running" ]]; then
    echo -e "\e[31m[x]\e[39m Docker is not running!"
    exit 1
fi

# Wireguard container created and running checks
check_wireguard_container_exists=$(docker container ls -a | grep "$CONTAINER_NAME")

if [[ -z "$check_wireguard_container_exists" && "$action" == "start" ]]; then
    echo -e "\e[34m[!]\e[39m VPN container does not exists, creating it now..."
    
    mkdir -p "$CONFIG_PATH"

    docker run -d --name="$CONTAINER_NAME" --cap-add=NET_ADMIN --cap-add=SYS_MODULE -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC -e SERVERURL="$LOCAL_HOST" -e PEERS=1 -e PEERDNS="$VPN_PEER_DNS" -e PERSISTENTKEEPALIVE_PEERS=25 -e INTERNAL_SUBNET="$VPN_SUBNET" -e ALLOWEDIPS=0.0.0.0/0 -e LOG_CONFS=true -p "$VPN_UDP_PORT":51820/udp -v "$CONFIG_PATH/config":/config -v /lib/modules:/lib/modules --sysctl="net.ipv4.conf.all.src_valid_mark=1" lscr.io/linuxserver/wireguard:latest 1>/dev/null

    check_wireguard_container_exists=$(docker container ls -a | grep "$CONTAINER_NAME")
    if [[ -z "$check_wireguard_container_exists" ]]; then
        echo -e "\e[31m[x]\e[39m Failed to create the wireguard server container!"
        exit 1
    else
        get_config
    fi
fi

if [[ "$action" == "start" ]];then
    echo -e "\e[32m[>]\e[39m Starting the VPN server container..."
    docker container start "$CONTAINER_NAME" 1>/dev/null
    
    echo -e "\e[32m[>]\e[39m Setting up iptables..."
        
    # Redirect TCP traffic on specified ports from VPN clients to host
    docker exec "$CONTAINER_NAME" iptables -t nat -A PREROUTING -i wg0 -p tcp -m multiport --dports "$REDIRECTED_TCP_PORTS" -j DNAT --to-destination "$LOCAL_HOST:$LOCAL_PORT"

    # Allow forwarding
    docker exec "$CONTAINER_NAME" iptables -A FORWARD -i wg0 -p tcp -m multiport --dports "$REDIRECTED_TCP_PORTS" -d "$LOCAL_HOST" -j ACCEPT

    # Allow packets to get back to the client
    docker exec "$CONTAINER_NAME" iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
    
    echo -e "\e[34m[!]\e[39m Expecting listening port $LOCAL_PORT on host $LOCAL_HOST. Remember to enable invisible proxying when using Burp!"
    echo -e "\e[32m[>]\e[39m Done!"
elif [[ "$action" == "stop" ]]; then
    echo -e "\e[32m[>]\e[39m Stopping the VPN server container..."
    docker container stop "$CONTAINER_NAME" 1>/dev/null
    echo -e "\e[32m[>]\e[39m Done!"
    exit 0
else
    get_config
    exit 0
fi

