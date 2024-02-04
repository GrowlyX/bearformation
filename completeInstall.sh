#!/bin/bash

if [ ! "$EUID" -eq 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

clear
echo "Welcome to the bearformation script. This script will setup your system, which includes security and starship and other various things."
echo "This script will install the following:"
echo "1. Starship"
echo "2. SSH"
echo "3. UFW"
echo "4. Docker"
echo "5. Redis"
echo "6. MongoDB"
echo "7. Consul"
echo "Script by: GrowlyX and modified by Emily"
read -p "Do you want to continue with the script? [y/N] " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

# Function to update and upgrade
update_upgrade() {
    echo "[/] Checking for updates.."
    sudo apt-get update -y
    sudo apt-get upgrade -y
    echo "[+] Updates check/install complete"
}

# Function to install Starship
install_starship() {
    if ! command -v starship &> /dev/null; then
        echo "[/] Installing starship.. (Passing script to Starship installer)"
        echo "======"
        sh -c "$(curl -fsSL https://starship.rs/install.sh)" -- -f
        echo "======"
        echo 'eval "$(starship init bash)"' >> ~/.bashrc
        source ~/.bashrc
        echo "[+] [✓]  Starship installed and configured"
    fi
}

# Function to configure SSH
configure_ssh() {
    echo "[/] Configuring Users SSH.."
    mkdir -p ~/.ssh
    touch ~/.ssh/authorized_keys
    echo "[^] Please enter your SSH key:"
    read -r ssh_key
    echo "[+] Adding SSH key to authorized_keys"
    echo "$ssh_key" >> ~/.ssh/authorized_keys
    echo "[+] Added SSH key to authorized_keys"
    echo "[+] Configured Users SSH"
    echo "[/] Restarting SSHD.."
    systemctl restart sshd
    echo "[✓] Configured SSH (please test in a new ssh session to verify)"
}

# Function to configure SSH settings
configure_ssh_settings() { 
    echo "[/] Configuring SSH Server.."
    sshd_config="/etc/ssh/sshd_config"
    echo "[-] Backing up SSHD Config.."
    # Backup the original sshd_config file
    sudo cp "$sshd_config" "$sshd_config.bak"
    echo "[-] Backed up SSHD Config to $sshd_config.bak"

    echo "[-] Configuring SSHD Config.."
    echo "[-] Changing LogLevel to VERBOSE.."
    sudo sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' "$sshd_config"
    echo "[-] Changed LogLevel to VERBOSE"
    echo "[-] Changing Max Auth Tries to 2..."
    sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 2/' "$sshd_config"
    echo "[-] Changed Max Auth Tries to 2"
    echo "[-] Changing Max Sessions to 2..."
    sudo sed -i 's/#MaxSessions 10/MaxSessions 2/' "$sshd_config"
    echo "[-] Changed Max Sessions to 2"
    echo "[-] Revoking Agent Forwarding, TCP Forwarding, TCP Keep Alive, Compression, Client Alive Count Max, and Password Authentication"
    sudo sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding no/' "$sshd_config"
    sudo sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' "$sshd_config"
    sudo sed -i 's/#TCPKeepAlive yes/TCPKeepAlive no/' "$sshd_config"
    sudo sed -i 's/#Compression delayed/Compression delayed/' "$sshd_config"
    sudo sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 2/' "$sshd_config"
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$sshd_config"
    echo "[-] Revoked Agent Forwarding, TCP Forwarding, TCP Keep Alive, Compression, Client Alive Count Max, and Password Authentication"
    echo "[/] Restarting SSHD.."
    # Restart SSH service to apply changes
    sudo systemctl restart sshd

    echo "[✓] Secured SSH Server"
}

configure_sysctl() {
    echo "[/] Configuring sysctl settings.."
    sysctl_config="/etc/sysctl.conf"

    echo "[-] Adding sysctl configurations to $sysctl_config"

    # Add the sysctl configurations to sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> "$sysctl_config"
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> "$sysctl_config"
    echo "net.ipv4.tcp_syncookies = 1" >> "$sysctl_config"
    echo "net.ipv4.conf.all.log_martians = 1" >> "$sysctl_config"
    echo "net.ipv4.conf.default.log_martians = 1" >> "$sysctl_config"
    echo "net.ipv4.conf.all.accept_source_route = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.default.accept_source_route = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.all.rp_filter = 1" >> "$sysctl_config"
    echo "net.ipv4.conf.default.rp_filter = 1" >> "$sysctl_config"
    echo "net.ipv4.conf.all.accept_redirects = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.default.accept_redirects = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.all.secure_redirects = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.default.secure_redirects = 0" >> "$sysctl_config"
    echo "net.ipv4.ip_forward = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.all.send_redirects = 0" >> "$sysctl_config"
    echo "net.ipv4.conf.default.send_redirects = 0" >> "$sysctl_config"

    # ... (add other sysctl configurations as needed)

    echo "[+] Sysctl configurations added to $sysctl_config"
    echo "[/] Applying sysctl settings..."
    sysctl -p
    echo "[✓] Sysctl settings applied"
}


# Function to configure UFW rules
configure_ufw() {
    echo "[/] Configuring UFW..]"
    echo "[-] Allowing users current IP: $current_ip"
    current_ip=$(echo "$SSH_CLIENT" | cut -d' ' -f 1)
    ufw allow in from "${current_ip}" comment 'Allow current IP'
    echo "[-] Allowed users current IP: $current_ip"
    echo "[-] Allowing SSH, HTTP, and HTTPS"
    ufw allow 80 comment 'Allow HTTP'
    ufw allow 443 comment 'Allow HTTPS'
    ufw allow 22 comment 'Allow SSH'
    echo "[-] Allowed SSH, HTTP, and HTTPS"
    echo "[-] Denying all other incoming connections"
    ufw default deny incoming
    echo "[-] Denied all other incoming connections"
    echo "[/] Enabling UFW"
    ufw enable
    echo "[✓] Configured UFW and allowed your IP to access services."
}

# Function to configure Docker and UFW rules
configure_docker_ufw() {
    echo "[/] Configuring Docker..]"
    echo "[?] Do you want to configure Docker & its UFW rules?"
    read -r configure_docker_ufw

    if [ "$configure_docker_ufw" = true ]; then
        if ! command -v docker &> /dev/null; then
            sudo apt install docker.io -y
        fi
        echo "[/] Configuring Docker.."
        echo "[-] Allowing Docker through UFW"
        # Disable docker default iptables configuration
        mkdir -p /etc/docker
        echo "{ \"iptables\": false }" >> /etc/docker/daemon.json

        # Set default FORWARD policy to accept & reload
        sed -i -e 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw
        ufw reload

        iptables -t nat -A POSTROUTING ! -o docker0 -s 172.17.0.0/16 -j MASQUERADE
        echo "[-] Allowed Docker through UFW"
        echo "[/] Restarting Docker.."
        systemctl restart docker

        echo "[✓] Configured Docker"
    fi
}

# Function to configure Redis
configure_redis() {
    echo "[/] Configuring Redis..]"
    echo "[?] Should we configure Redis?"
    read -r configure_redis

    if [ "$configure_redis" = true ]; then
        echo "[-] Installing Redis.."
        sudo apt install lsb-release
        curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
        sudo apt-get update
        sudo apt-get install redis
        echo "[+] Installed Redis"
        cp -R resources/redis.conf /etc/redis/
        systemctl restart redis

        echo "[✓] Configured Redis"
    fi
}
ignore_ICMP () {
    echo "Installing ICMP Ignore"
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    echo "** Kernel: Setting parameter: icmp_echo_ignore_broadcast -> true"
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo "** Kernel: Setting parameter: accept_redirects -> false"
    iptables -t mangle -A PREROUTING -p icmp -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING -p icmp -> DROP"
}

drop_routed_packets () {
    echo "Installing Drop source routed packets"
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
    echo "** Kernel: Setting parameter: accept_source_route -> false"
}

tcp_syn_cookies () {
    echo "Installing TCP Syn cookies"
    sysctl -w net/ipv4/tcp_syncookies=1
    echo "** Kernel: Setting parameter: tcp_syncookies -> true"
}

tcp_syn_backlog () {
    echo "Increasing TCP Syn Backlog"
    echo 2048 > /proc/sys/net/ipv4/tcp_max_syn_backlog
    echo "** Kernel: Setting parameter: tcp_max_syn_backlog -> 2048"
}

tcp_syn_ack () {
    echo "Decreasing TCP Syn-Ack Retries"
    echo 3 > /proc/sys/net/ipv4/tcp_synack_retries
    echo "** Kernel: Setting parameter: tcp_synack_retries -> 3"
}

ip_spoof () {
    echo "Enabling Address Spoofing Protection"
    echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo "** Kernel: Setting parameter: rp_filter -> true"
}

disable_syn_packet_track () {
    echo "Disabling SYN Packet Track"
    sysctl -w net/netfilter/nf_conntrack_tcp_loose=0
    echo "** Kernel: Setting parameter: nf_conntrack_tcp_loose -> false"
}

drop_invalid_packets () {
    echo "Installing invalid packet drop"
    iptables -A INPUT -m state --state INVALID -j DROP
    echo "** IPTables: Setting rule: -A INPUT -m state INVALID -j DROP"
}

bogus_tcp_flags () {
    echo "Installing Bogus TCP Flags"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags FIN,SYN FIN,SYN -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags SYN,RST SYN,RST -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags SYN,FIN SYN,FIN -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags  FIN,RST FIN,RST -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags FIN,ACK FIN -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ACK,URG URG -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ACK,FIN FIN -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ACK,PSH PSH -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ALL ALL -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ALL NONE -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ALL FIN,PSH,URG -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ALL SYN,FIN,PSH,URG -> DROP"
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING --tcp-flags ALL SYN,RST,ACK,FIN,URG -> DROP"
}

drop_fragment_chains () {
    echo "Installing Chains Fragment drop"
    iptables -t mangle -A PREROUTING -f -j DROP
    echo "** IPTables: Setting rule: -t mangle -A PREROUTING -f -> DROP"
}

tcp_syn_timestamps () {
    echo "Setting TCP Syn Timestamps"
    sysctl -w net/ipv4/tcp_timestamps=1
    echo "** Kernel: Setting parameter: tcp_timestamps -> true"
}

limit_cons_per_ip () {
    echo "Setting connections limit per ip"
    iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset
    echo "** IPTables: Setting rule: TCP -m connlimit --connlimit-above 111 -> REJECT WITH TCP RESET"
}

limit_rst_packets () {
    echo "Setting RST packets limit"
    iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
    echo "** IPTables: Setting rule: -A INPUT -p tcp --tcp-flags RST RST -m limit --limit2/s -> ACCEPT"
    iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
    echo "** IPTables: Setting rule: -A INPUT -p tcp --tcp-flags RST RST -> DROP"
}

syn_proxy () {
    echo "Installing SYN Proxy"
    iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
    echo "** IPTables: Setting rule: raw -A PREROUTING -p tcp -m tcp --syn --notrack -> CT"
    iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
    echo "** IPTables: Setting rule: TCP -m conntrack --ctstate INVALID,UNTRACKET -j SYNPROXY 1460"
    iptables -A INPUT -m state --state INVALID -j DROP
    echo "** IPTables: Setting rule: -A INPUT -m state INVALID -j DROP"
}

prevent_ssh_bf () {
    echo "Installing SSH Bruteforce Detection"
    iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
    echo "** IPTables: Setting rule: SSH -m conntrack --ctstate NEW -m recent --set"
    iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
    echo "** IPTables: Setting rule: SSH --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -> DROP"
}

prevent_port_scanner () {
    echo "Installing Port Scanner Detection"
    iptables -N port-scanning
    echo "** IPTables: Setting rule: -N port-scanning"
    iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
    echo "** IPTables: Setting rule: TCP SYN,ACK,FIN,RST RST -m limit 1/s --limit-burst 2 -> RETURN"
    iptables -A port-scanning -j DROP
    echo "** IPTables: Setting rule: -A portscanning -> DROP"
}

# Function to configure MongoDB
configure_mongo() {
    echo "[/] Configuring Mongo..]"
    echo "[?] Should we configure MongoDB?"
    read -r configure_mongo

    if [ "$configure_mongo" = true ]; then
        echo "[-] Installing MongoDB.."
        sudo apt-get install gnupg
        curl -fsSL https://pgp.mongodb.com/server-6.0.asc | \
            sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg \
            --dearmor
        echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list

        sudo apt-get update
        sudo apt-get install -y mongodb-org
        echo "[+] Installed MongoDB"
        echo "[-] Configuring MongoDB.."
        cp -R resources/mongod.conf /etc/
        echo "[-] Configured MongoDB"
        systemctl restart mongod

        echo "[✓] Configured MongoDB"
    fi
}

# Function to configure Consul
configure_consul() {
    echo "[/] Configuring Consul.."
    echo "[?]Should we start up a Consul dev server (requires Docker)?"
    read -r configure_consul

    if [ "$configure_consul" = true ]; then
        # Start Consul dev server @ 0.0.0.0:8500
        docker run -d --name=dev-consul -e CONSUL_BIND_INTERFACE=eth0 -p 8500:8500 consul

        echo "[✓] Configured Consul"
    fi
}
# Main execution
update_upgrade
install_starship
configure_ssh
configure_ssh_settings
configure_ufw
configure_docker_ufw
configure_sysctl
configure_redis
configure_mongo
configure_consul
ignore_ICMP
drop_routed_packets
tcp_syn_cookies
tcp_syn_backlog
tcp_syn_ack
ip_spoof
disable_syn_packet_track
drop_invalid_packets
bogus_tcp_flags
drop_fragment_chains
limit_cons_per_ip
syn_proxy
prevent_ssh_bf
prevent_port_scanner
limit_rst_packets
tcp_syn_timestamps

echo "Installation script completed."
