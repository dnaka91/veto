Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.define "iptables" do |iptables|
    iptables.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get dist-upgrade -y
      apt-get install -y ipset xtables-addons-dkms
      apt-get autoremove -y
    SHELL
  end

  config.vm.define "nftables" do |nftables|
    nftables.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get dist-upgrade -y
      apt-get install -y nftables
      apt-get remove -y iptables
      apt-get autoremove -y
    SHELL
  end
end
