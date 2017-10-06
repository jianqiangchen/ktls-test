#!/bin/bash

# Tested in Ubuntu 1604


ktls_root=/home/jianqche/work/ktls

build_linux() {
    cd /usr/src
    sudo apt-get install libncurses5-dev gcc make git exuberant-ctags bc libssl-dev
    sudo git clone https://github.com/ktls/net_next_ktls.git
    cd /usr/src/net_next_ktls

    sudo make menuconfig
    sudo make -j 4
    sudo make modules
    sudo make modules_install
    sudo make install
    #change grub setting https://www.howtogeek.com/196655/how-to-configure-the-grub2-boot-loaders-settings/
    sudo update-grub
    sudo reboot
}


build_ktls_module() {
    mkdir -p $ktls_root
    cd $ktls_root
    git clone https://github.com/ktls/af_ktls.git
    cd af_ktls
    # may need to fix fix skb_splice_bits issue, remove last parameter for now. Need to check later 
    make
}

run_module() {
    cd $ktls_root
    cd af_ktls
    sudo rmmod af_ktls.ko
    sudo modprobe strparser
    sudo insmod af_ktls.ko
    lsmod | grep "ktls"
}


build_linux
#build_ktls_module
#run_module



