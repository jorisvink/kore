# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = '2'

@provision_ubuntu = <<PROVISION_UBUNTU
sudo apt-get install -y build-essential git-core

sudo apt-get install ca-certificates
wget --quiet https://www.postgresql.org/media/keys/ACCC4CF8.asc
sudo apt-key add ACCC4CF8.asc
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
sudo apt-get update
sudo apt-get install -y postgresql-server-dev-9.4
PROVISION_UBUNTU

@provision_centos = <<PROVISION_CENTOS
sudo yum install -y @development openssl-devel

wget --quiet http://yum.postgresql.org/9.4/redhat/rhel-7-x86_64/pgdg-centos94-9.4-1.noarch.rpm
sudo yum localinstall -y ./pgdg-centos94-9.4-1.noarch.rpm
sudo yum clean all
sudo yum install -y postgresql94-devel
echo "PATH=\$PATH:/usr/pgsql-9.4/bin" >> /home/vagrant/.bash_profile
PROVISION_CENTOS

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.provider :virtualbox do |vb|
    vb.gui = false
    vb.memory = '2048'
    vb.cpus = '2'
  end
  config.vm.synced_folder '.', '/home/vagrant/kore'

  config.vm.define "centos66" do |cfg|
    cfg.vm.box = "chef/centos-6.6"
    cfg.vm.hostname = "centos66"
    cfg.vm.provision 'shell', inline: @provision_centos
  end
  config.vm.define "centos70" do |cfg|
    cfg.vm.box = "chef/centos-7.0"
    cfg.vm.hostname = "centos70"
    cfg.vm.provision 'shell', inline: @provision_centos
  end

  config.vm.define "ubuntu1404" do |cfg|
    cfg.vm.box = "chef/ubuntu-14.04"
    cfg.vm.hostname = "ubuntu1404"
    cfg.vm.provision 'shell', inline: @provision_ubuntu
  end
  config.vm.define "ubuntu1410" do |cfg|
    cfg.vm.box = "chef/ubuntu-14.10"
    cfg.vm.hostname = "ubuntu1410"
    cfg.vm.provision 'shell', inline: @provision_ubuntu
  end
end
