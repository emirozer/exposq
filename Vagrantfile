# -*- mode: ruby -*-
# vi: set ft=ruby :


require 'socket'
ip_address = Socket.ip_address_list.find { |ai| ai.ipv4? && !ai.ipv4_loopback? }.ip_address

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # You can fetch the below box from here:
  # http://www.vagrantbox.es/
  # Tested : CentOS 7.0 x64 (Minimal, VirtualBox Guest Additions 4.3.28, Puppet 3.8.1 
  config.vm.box = 'centos'
  config.vm.boot_timeout = 500
  config.vm.network :forwarded_port, guest: 3000, host: 3000
  config.vm.network "private_network", type: "dhcp"
  
  $script = <<-SCRIPT
  mkdir ~/go
  sudo yum install -y golang
  export GOPATH=~/go
  echo 'export GOPATH=~/go' >> .bashrc
  export PATH=$PATH:$GOPATH/bin
  echo 'export PATH=$PATH:$GOPATH/bin' >> .bashrc
  go get github.com/emirozer/exposq
  nohup exposq -vagrant &
  SCRIPT

  config.vm.provision "shell", inline: $script, privileged: false




end
