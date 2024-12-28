Vagrant.configure("2") do |config|

  config.vm.box = "debian/bullseye64"
	
	config.vm.hostname = "ft-nmap-vm"
  
	config.vm.synced_folder "~/Desktop/ft_nmap", "/home/vagrant/ft_nmap"

  config.vm.provision "shell", inline: <<-SHELL
		apt-get update -y
		apt-get install -y apt-utils clang make binutils git gcc inetutils-traceroute vim tcpdump nmap libpcap-dev net-tools valgrind
	SHELL

end
