#Runs StringParser independently; make sure, that this is the only instance running!
echo "Starting StringParser"
rm /home/isl/t1/string_parser.log
screen -dmS string_parser -L -Logfile /home/isl/t1/string_parser.log ./string_parser
echo "StringParser Logs"
echo "--------------------------------------------"
until [ -f /home/isl/t1/string_parser.log ]
do
     sleep 0.5
done
screen -S string_parser -X echo ""
#cat /home/isl/t1/string_parser.log
sleep 2
python3 /home/isl/t1/test_string_parser.py
echo "--------------------------------------------"