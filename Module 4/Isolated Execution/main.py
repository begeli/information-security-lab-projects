import requests
import os
import subprocess
import time
import binascii

def switch_to_t1():
	os.chdir("/home/isl/t1")
	
def kill_all():
	os.system("pkill -9 node")
	os.system("pkill -9 string_parser")
	os.system("killall screen")
	
def kill_process(port_number):
	os.system(f"kill -9 $(lsof -t -i:{port_number})")
	
def start_manager():
	os.system("./run_manager.sh")

def start_peripheral():
	os.system("./run_peripheral.sh")
	
def start_string_parser():
	os.system("./run_string_parser.sh")

def start_remote_party():
	subprocess.Popen(["sh", "./start.sh"], stdin=subprocess.PIPE)

def start_all():
	os.system("./run.sh")

def exploit_1():
	start_manager()
	start_peripheral()
	
	subprocess.run("screen -dmS string_parser -L -Logfile /home/isl/t1/string_parser.log gdb string_parser", shell=True)
	
	subprocess.run("screen -S string_parser -p 0 -X stuff \"set follow-fork-mode child^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"break process_request.c:340^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"run^M\"", shell=True)
	
	time.sleep(1)
	start_remote_party()
	
	time.sleep(1)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"set variable M_response_cleartext = \\\"<mes><action type='key-update'/></mes>\\\"^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"continue^M\"", shell=True)
	
	time.sleep(1)

def exploit_2():
	start_manager()
	start_peripheral()
	
	subprocess.run("screen -dmS string_parser -L -Logfile /home/isl/t1/string_parser.log gdb string_parser", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"set follow-fork-mode child^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"break *0x0040338a^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"break *0x004033c3^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"run^M\"", shell=True)
	
	time.sleep(1)
	start_remote_party()
	
	time.sleep(1)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"set variable redirectAdmin = 0x8da8a1^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"continue^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"set variable redeemselector = 2^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"set variable verifyer_second = '\\x0'^M\"", shell=True)
	subprocess.run("screen -S string_parser -p 0 -X stuff \"continue^M\"", shell=True)
	
	time.sleep(1)

def main():
	# Switch to correct directory
	switch_to_t1()
	
	# Kill all processes running currently
	kill_all()
	
	# Start exploit 1
	exploit_1()
	
	kill_all()
	
	# Start exploit 2
	exploit_2()
	
	kill_all()
	
	start_all()

if __name__ == "__main__":
	main()