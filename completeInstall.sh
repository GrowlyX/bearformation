#!/bin/bash

if [ ! "$EUID" -eq 0 ]; then
    echo "This script must be run as root."
    exit 1
fi
# Function to update and upgrade
update_upgrade() {
    sudo apt-get update -y
    sudo apt-get upgrade -y
}

# Function to install Starship
install_starship() {
    if ! command -v starship &> /dev/null; then
        sh -c "$(curl -fsSL https://starship.rs/install.sh)" -- -f
        echo 'eval "$(starship init bash)"' >> ~/.bashrc
        source ~/.bashrc
        echo "Configured Starship"
    fi
}

# Function to configure SSH
configure_ssh() {
    mkdir -p ~/.ssh
    touch ~/.ssh/authorized_keys

    echo "Enter your SSH key:"
    read -r ssh_key

    echo "$ssh_key" >> ~/.ssh/authorized_keys
    systemctl restart sshd
    echo "Configured SSH (please test in a new ssh session to verify)"
}

# Function to configure SSH settings
configure_ssh_settings() {
    sshd_config="/etc/ssh/sshd_config"

    # Backup the original sshd_config file
    sudo cp "$sshd_config" "$sshd_config.bak"

    # Update SSH settings
    sudo sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' "$sshd_config"
    sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 2/' "$sshd_config"
    sudo sed -i 's/#MaxSessions 10/MaxSessions 2/' "$sshd_config"
    sudo sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding no/' "$sshd_config"
    sudo sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' "$sshd_config"
    sudo sed -i 's/#TCPKeepAlive yes/TCPKeepAlive no/' "$sshd_config"
    sudo sed -i 's/#Compression delayed/Compression delayed/' "$sshd_config"
    sudo sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 2/' "$sshd_config"
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$sshd_config"

    # Restart SSH service to apply changes
    sudo systemctl restart sshd

    echo "Configured SSH settings"
}


# Function to configure UFW rules
configure_ufw() {
    current_ip=$(echo "$SSH_CLIENT" | cut -d' ' -f 1)

    ufw allow 22 comment 'Allow SSH'
    ufw allow in from "${current_ip}" comment 'Allow current IP'
    ufw default deny incoming
    ufw enable

    echo "Configured UFW and allowed your IP to access services."
}

# Function to configure Docker and UFW rules
configure_docker_ufw() {
    echo "Do you want to configure Docker & its UFW rules?"
    read -r configure_docker_ufw

    if [ "$configure_docker_ufw" = true ]; then
        if ! command -v docker &> /dev/null; then
            sudo apt install docker.io -y
        fi

        # Disable docker default iptables configuration
        mkdir -p /etc/docker
        echo "{ \"iptables\": false }" >> /etc/docker/daemon.json

        # Set default FORWARD policy to accept & reload
        sed -i -e 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw
        ufw reload

        iptables -t nat -A POSTROUTING ! -o docker0 -s 172.17.0.0/16 -j MASQUERADE
        systemctl restart docker

        echo "Configured Docker"
    fi
}


# Main execution
update_upgrade
install_starship
configure_ssh
configure_ssh_settings
configure_ufw
configure_docker_ufw

echo "Installation script completed."
