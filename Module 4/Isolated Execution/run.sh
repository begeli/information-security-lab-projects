#!/bin/bash
pkill -9 node
pkill -9 string_parser
rm -f /home/isl/t1/manager.log
rm -f /home/isl/t1/string_parser.log
rm -f /home/isl/t1/peripheral.log
sleep 2
echo "Starting Manager"
node --no-warnings /home/isl/t1/manager &> /home/isl/t1/manager.log &
echo "Manager Logs"
echo "--------------------------------------------"
#until [ -f /home/isl/t1/manager.log ]
#do
sleep 2
#done
cat /home/isl/t1/manager.log
echo "--------------------------------------------"
echo ""

sleep 2
echo "Starting Peripheral"
node --no-warnings /home/isl/t1/peripheral &> /home/isl/t1/peripheral.log &
echo "Peripheral Logs"
echo "--------------------------------------------"
#until [ -f /home/isl/t1/peripheral.log ]
#do
sleep 2
#done
cat /home/isl/t1/peripheral.log
echo "--------------------------------------------"
echo ""

sleep 2
echo "Starting StringParser"
#cd /home/isl/t1/
#/home/isl/t1/string_parser  &
screen -dmS string_parser -L -Logfile /home/isl/t1/string_parser.log ./string_parser
#screen -S string_parser -X echo ""
echo "StringParser Logs"
sleep 2
python3 /home/isl/t1/test_string_parser.py

echo "--------------------------------------------"
#until [ -f /home/isl/t1/string_parser.log ]
#do
sleep 2
#done
screen -S string_parser -X echo ""
#screen -S string_parser -X echo ""