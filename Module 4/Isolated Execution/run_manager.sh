#Runs Manager independently; make sure, that this is the only instance running!
echo "Starting Manager"
rm -f /home/isl/t1/manager.log
node --no-warnings /home/isl/t1/manager &> /home/isl/t1/manager.log &
echo "Manager Logs"
echo "--------------------------------------------"
until [ -f /home/isl/t1/manager.log ]
do
     sleep 0.5
done
cat /home/isl/t1/manager.log
echo "--------------------------------------------"
echo ""