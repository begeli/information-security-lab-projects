#Runs peripheral independently; make sure, that this is the only instance running!
echo "Starting Peripheral"
rm -f /home/isl/t1/peripheral.log
node --no-warnings /home/isl/t1/peripheral &> /home/isl/t1/peripheral.log &
echo "Peripheral Logs"
echo "--------------------------------------------"
until [ -f /home/isl/t1/peripheral.log ]
do
     sleep 0.5
done
cat /home/isl/t1/peripheral.log
echo "--------------------------------------------"
echo ""