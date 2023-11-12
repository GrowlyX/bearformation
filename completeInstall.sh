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
configure_redis
configure_mongo
configure_consul


echo "Installation script completed."
