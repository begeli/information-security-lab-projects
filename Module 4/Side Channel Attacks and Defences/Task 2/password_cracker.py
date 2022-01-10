import sys
import os
import shutil

CHARS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
MAX_LEN = 31
TOOL_PATH = "/home/sgx/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace"

def create_output(out_id, cracked_password):
	out_path = f"/home/sgx/isl/t2/output/oput_{out_id}"
	os.makedirs(os.path.dirname(out_path), exist_ok=True)
	output_file = open(out_path, "w")
	output_file.write(cracked_password)
	output_file.close()

def create_trace(guess, ch):
	os.chdir(TOOL_PATH)
	out_path = f"/home/sgx/isl/t2/traces/trace_{ch}"
	os.makedirs(os.path.dirname(out_path), exist_ok=True)
	command = f"../../../pin -t ./obj-intel64/SGXTrace.so -o {out_path} -trace 1 -- ~/isl/t2/password_checker_2 {guess}"
	os.system(command)	

def delete_traces():
	trace_path = "/home/sgx/isl/t2/traces"
	shutil.rmtree(trace_path)

def find_letter_positions(correct_letters, ch):
	trace_path = f"/home/sgx/isl/t2/traces/trace_{ch}"
	
	iter_count = 0
	with open(trace_path) as f:
		for line in f:
			if "0x4011ca" in line:
				iter_count += 1
			if "0x4011b6" in line:
				correct_letters[iter_count] = ch				

def main():
	if len(sys.argv) != 2:
		print("Incorrect number of command line arguments entered...")			
		exit()

	correct_letters = {}
	for ch in CHARS:
		guess = ch * MAX_LEN
		create_trace(guess, ch)
		find_letter_positions(correct_letters, ch)	

	cracked_password = ""
	last_index = max(correct_letters.keys())
	for index in range(1, last_index + 1):
		cracked_password += correct_letters[index]
	cracked_password += ",complete"
	
	create_output(sys.argv[1], cracked_password)
	#print(cracked_password)

	delete_traces()

if __name__ == "__main__":
	main()
