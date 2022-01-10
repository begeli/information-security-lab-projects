echo "Starting RP Request"
rm -f /home/isl/t1/remote_party.log

echo "--------------------------------------------"
node --no-warnings /home/isl/t1/remote_party 2>&1 | tee /home/isl/t1/remote_party.log
echo "--------------------------------------------"
echo "Finished Request"