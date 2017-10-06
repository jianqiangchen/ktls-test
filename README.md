# ktls-test

Use ktls_setup.sh as the base to setup KTLS
1. Ubuntu 16.04 is tested
2. Patch the kernel with ktls patch or use https://github.com/ktls/net_next_ktls.git which included the patch already
3. build the kernel
4. build the KTLS module
5. run KTLS module

./server.sh 8843 1 ECDH-ECDSA-AES128-GCM-SHA256 10M
./client.sh 192.168.95.9 8843 1 ECDH-ECDSA-AES128-GCM-SHA256 10M 10000000 1 1 1
