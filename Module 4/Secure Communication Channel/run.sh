#!/bin/bash
pkill -9 node
T2=/home/isl/t2
rm $T2/peripheral.log
rm $T2/enclave.log
echo "Starting Peripheral"
node --no-warnings $T2/peripheral &> $T2/peripheral.log &
echo "Peripheral logs"
echo "--------------------------------------------"
until [ -f $T2/peripheral.log ]
do
     sleep 1
done
while ! nc -z localhost 37200 </dev/null; do sleep 1; done

cat $T2/peripheral.log
echo "--------------------------------------------"
echo ""
echo "Starting Enclave"
node --no-warnings $T2/enclave &> $T2/enclave.log &
echo "Enclave logs"
echo "--------------------------------------------"
until [ -f $T2/enclave.log ]
do
     sleep 1.5
done
cat $T2/enclave.log
echo ""
echo "--------------------------------------------"