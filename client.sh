#!/bin/bash

echo "./client.sh 192.168.95.9 8843 1 ECDH-ECDSA-AES128-GCM-SHA256 10K 10000 1 1 1"

ipaddress=$1
port=$2
https=$3
cipher=$4
file=$5
filesize=$6
thread=$7
connection=$8
request=$9

start_test() {
    ./epoll_client $https $cipher $ipaddress $port $file $filesize $thread $connection $request
}

start_test

