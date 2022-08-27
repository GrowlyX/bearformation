# author - gorlwx
# update & upgrade if required
apt-get update
apt-get upgrade

# install & configure starship
curl -sS https://starship.rs/install.sh | sh

# add starship evaluator to .bashrc
echo eval "$(starship init bash)" >>".bashrc"
source .bashrc

echo "configured starship"

# install bashtop, because it's cool
snap install bashtop

# configure SSH, enable pubkey auth, & disable pass auth
cp -R resources/sshd_config /etc/ssh
mkdir /.ssh/
touch /.ssh/authorized_keys

echo "enter your ssh key, more can be added in \"/.ssh/authorized_keys\" (We assume all users are on root)"
read -r ssh_key

echo "$ssh_key" >>/.ssh/authorized_keys

systemctl restart sshd
echo "configured ssh (please test)"

# configure default UFW rules
ufw allow 22
ufw default deny incoming
ufw enable

echo "we've configured ufw, but you should allow your ip through:"
echo "ufw allow in from <your IP>"

# install & configure docker.io & UFW rules
echo "should we configure docker & its UFW rules?"
read -r configure_docker_ufw

if [ "$configure_docker_ufw" = true ]; then
  apt install docker.io

  # disable docker default iptables configuration
  mkdir /etc/docker
  touch /etc/docker/daemon.json

  echo "{ \"iptables\": false }" >>/etc/docker/daemon.json

  # set default FORWARD policy to accept & reload
  sed -i -e 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw
  ufw reload

  iptables -t nat -A POSTROUTING ! -o docker0 -s 172.17.0.0/16 -j MASQUERADE
  systemctl restart docker

  echo "configured docker"
fi

# install & configure redis
echo "should we configure redis?"
read -r configure_redis

if [ "$configure_redis" = true ]; then
  apt install redis
  cp -R resources/redis.conf /etc/redis/
  systemctl restart redis

  echo "configured redis"
fi

# install & configure mongo
echo "should we configure mongo?"
read -r configure_mongo

if [ "$configure_mongo" = true ]; then
  apt install mongodb
  cp -R resources/mongodb.conf /etc/
  systemctl restart mongodb

  echo "configured mongo"
fi

# install & configure consul
echo "should we start up a consul dev server (requires docker)?"
read -r configure_consul

if [ "$configure_consul" = true ]; then
  # start consul dev server @ 0.0.0.0:8500
  docker run -d --name=dev-consul -e CONSUL_BIND_INTERFACE=eth0 -p 8500:8500 consul

  echo "configured consul"
fi

echo "woo hoo finished installation"
