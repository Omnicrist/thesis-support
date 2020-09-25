#!/bin/bash

### A MANO ###
### mkdir /home/alarm/.ssh
### ssh-keygen -f ~/.ssh/alarm
### cat ~/.ssh/alarm.pub > ~/.ssh/authorized_keys
### chmod 600 ~/.ssh/authorized_keys
### exit
### scp alarm@raspberry:/home/alarm/.ssh/alarm ~/Scrivania/alarm

ssh -i ~/Scrivania/alarm alarm@raspberry << EOF
    export TERM=xterm-256color
    export SHELL=/bin/bash
    echo "root" | su root -c "pacman-key --init"
    echo "root" | su root -c "pacman-key --populate archlinuxarm"
    echo "root" | su root -c "pacman -Syu --noconfirm"

    echo "root" | su root -c "pacman -S --needed base-devel --noconfirm"
    echo "root" | su root -c "pacman -S cmake git lm_sensors wget --noconfirm"

    echo "root" | su root -c "groupadd sudo"
    echo "root" | su root -c "usermod -aG sudo alarm"
    echo "root" | su root -c "echo -e '%sudo\tALL=(ALL)\tNOPASSWD:\tALL' >> /etc/sudoers"
    echo "root" | su root -c "reboot"
EOF

sleep 45

ssh -i ~/Scrivania/alarm alarm@raspberry << EOF
    export TERM=xterm-256color
    export SHELL=/bin/bash
    curl -O https://blackarch.org/strap.sh
    chmod +x strap.sh
    sudo ./strap.sh

    # Uncomment Ecuador, Poland, Vietnam
    sudo cp /etc/pacman.d/blackarch-mirrorlist /etc/pacman.d/blackarch-mirrorlist.backup
    sudo chgrp sudo /etc/pacman.d/blackarch-mirrorlist
    sudo chmod 664 /etc/pacman.d/blackarch-mirrorlist
    sudo awk '/^# Ecuador$/{f=1; next}f==0{next}/^$/{exit}{print substr(\$0, 3); f=1}' /etc/pacman.d/blackarch-mirrorlist.backup | grep http  > /etc/pacman.d/blackarch-mirrorlist
    sudo awk '/^# Poland$/{f=1; next}f==0{next}/^$/{exit}{print substr(\$0, 3); f=1}' /etc/pacman.d/blackarch-mirrorlist.backup | grep http >> /etc/pacman.d/blackarch-mirrorlist
    sudo awk '/^# Vietnam$/{f=1; next}f==0{next}/^$/{exit}{print substr(\$0, 3); f=1}' /etc/pacman.d/blackarch-mirrorlist.backup | grep http >> /etc/pacman.d/blackarch-mirrorlist
    sudo chmod 644 /etc/pacman.d/blackarch-mirrorlist
    sudo chgrp root /etc/pacman.d/blackarch-mirrorlist

    sudo ./strap.sh
    sudo pacman -Syu --noconfirm

    sudo pacman -S openvas --noconfirm
    sudo pacman -S greenbone-security-assistant --noconfirm
    sudo pacman -S python2 --noconfirm

    wget https://github.com/redis/hiredis/archive/v0.13.3.tar.gz -O /tmp/hiredis-0.13.3.tar.gz
    #sudo su root -c "cp /usr/lib/libhiredis.so.1.0.0 /home/alarm/libhiredis.so.1.0.0_bk"
    sudo su root -c "tar -xf /tmp/hiredis-0.13.3.tar.gz -C /opt/"
    cd /opt/hiredis-0.13.3
    sudo su root -c "make"
    sudo su root -c "make install"
    sudo su root -c "echo '/usr/local/lib' > /etc/ld.so.conf.d/openvas.conf"
    sudo su root -c "echo '/usr/local/lib' >> /etc/ld.so.conf"
    sudo su root -c "ldconfig"

    # sudo rm /usr/lib/systemd/system/gsad.service
    
    sudo wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/greenbone-security-assistant.service -O /usr/lib/systemd/system/greenbone-security-assistant.service
    sudo wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/openvas-manager.service -O /usr/lib/systemd/system/openvas-manager.service
    sudo rm -f /usr/lib/systemd/system/openvas-scanner.service
    sudo wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/openvas-scanner.service -O /usr/lib/systemd/system/openvas-scanner.service
    wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/openvas-start -O ~/openvas-start
    wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/openvas-stop -O ~/openvas-stop
    sudo wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/openvassd.conf -O /etc/openvas/openvassd.conf
    chmod +x ~/openvas-start ~/openvas-stop

    sudo systemctl enable openvas-manager
    sudo systemctl enable openvas-scanner
    sudo systemctl enable greenbone-security-assistant

    sudo systemctl daemon-reload

    sudo cp /etc/redis.conf /etc/redis.conf_bk
    sudo sed -i 's/# unixsocket \/tmp\/redis.sock/unixsocket \/var\/lib\/redis\/redis.sock/g' /etc/redis.conf
    sudo sed -i 's/# unixsocketperm 700/unixsocketperm 700/g' /etc/redis.conf
    sudo sed -i 's/^port 6379$/port 0/g' /etc/redis.conf
    sudo sed -i 's/^databases 16$/databases 128/g' /etc/redis.conf
    sudo sysctl vm.overcommit_memory=1
    sudo systemctl start redis
    sudo systemctl enable redis
    # sudo systemctl status redis

    sudo pacman -S nmap --noconfirm

    sudo openvas-manage-certs -a

    # Copia dei certificati
    sudo mkdir -p /var/lib/gvm/private/CA/
    sudo mkdir /var/lib/gvm/CA/
    sudo cp /var/lib/openvas/private/CA/serverkey.pem /var/lib/gvm/private/CA/serverkey.pem
    sudo cp /var/lib/openvas/CA/servercert.pem /var/lib/gvm/CA/servercert.pem

    sudo greenbone-nvt-sync
    sudo greenbone-scapdata-sync
    sudo greenbone-certdata-sync
    sudo openvasmd --create-user=admin --role=Admin
    sudo openvasmd --user=admin --new-password=admin

    
    sudo ~/openvas-start
    sudo openvasmd --update

    # Install Metasploit

    sudo pacman -S metasploit --noconfirm
    sudo mv /usr/bin/ruby /usr/bin/ruby-2.7
    sudo mv /usr/bin/gem /usr/bin/gem-2.7

    sudo pacman -S ruby2.6 --noconfirm
    sudo ln -s /usr/bin/gem-2.6 /usr/bin/gem
    sudo ln -s /usr/bin/ruby-2.6 /usr/bin/ruby

    sudo gem install bundler:1.15.4 rdoc
    cd /opt/metasploit
    sudo bundle install
    cd ~

    sudo echo 'export HOSTNAME=alarmpi' >> /home/alarm/.bashrc
    sudo echo 'alias msfconsole=/opt/metasploit/msfconsole' >> /home/alarm/.bashrc
    source /home/alarm/.bashrc

    sudo pacman -S python-pip
    pip3 install pymetasploit3
    sudo pip3 install pymetasploit3
    sudo wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/msfrpcd.service -O /usr/lib/systemd/system/msfrpcd.service
    wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/msfrpcd-start -O ~/msfrpcd-start
    wget https://raw.githubusercontent.com/Omnicrist/thesis-support/master/msfrpcd-stop -O ~/msfrpcd-stop

    sudo systemctl enable msfrpcd

    msfconsole
EOF
