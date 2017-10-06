#!/bin/bash

echo "./server.sh 8843 1 ECDH-ECDSA-AES128-GCM-SHA256 1M"

[ -f 1K ] || dd if=/dev/urandom of=1K bs=1000 count=1
[ -f 10K ] || dd if=/dev/urandom of=10K bs=1000 count=10
[ -f 100K ] || dd if=/dev/urandom of=100K bs=1000 count=100
[ -f 1M ] || dd if=/dev/urandom of=1M bs=1000 count=1000
[ -f 10M ] || dd if=/dev/urandom of=10M bs=1000 count=10000
[ -f 100M ] || dd if=/dev/urandom of=100M bs=1000 count=100000


start_test() {
    ./epoll_server $1 $2 $3 $4
}

start_test $1 $2 $3 $4
