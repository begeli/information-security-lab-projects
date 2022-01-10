import sys
import os

def get_file_names(path):
	return os.listdir(path)

def create_output(out_id, cracked_password):
	out_path = f"/home/sgx/isl/t1/output/oput_{out_id}"
	os.makedirs(os.path.dirname(out_path), exist_ok=True)
	output_file = open(out_path, "w")
	output_file.write(cracked_password)
	output_file.close()

def shift_char(guess, shift_amount, guess_is_larger):
	if not guess_is_larger:
		return chr(ord(guess) + shift_amount)
	else:	
		return chr(((ord(guess) - ord('a') + shift_amount) % 26) + ord('a'))
		#print(chr((ord(guess) + shift_amount) % 26))

def main():
	if len(sys.argv) != 3:
		print("Incorrect number of command line arguments entered...")
		exit()
	
	path = sys.argv[1]
	out_id = sys.argv[2]

	
	exec_traces = get_file_names(path)
	is_guess_correct = False
	correct_letters = {}
	password_len = -1
	for trace in exec_traces:
		correct_count = 0
		iter_count = 0

		guess_is_larger = False
		shift_amount = 0		
	
		with open(path + "/" + trace) as f:
			for line in f:
				if "0x401211" in line:
					correct_count += 1
					correct_letters[iter_count] = trace[iter_count - 1]
				if "0x40126f" in line:
					guess_is_larger = True
				if "0x401286" in line:
					shift_amount += 1
				if "0x401292" in line:
					if shift_amount > 0:
						#print("Shift ")
						#print(shift_amount - 1)
						#print(guess_is_larger)
						shift_char(trace[iter_count - 1], shift_amount - 1, guess_is_larger)
						correct_letters[iter_count] = shift_char(trace[iter_count - 1], shift_amount - 1, guess_is_larger)
					shift_amount = 0
					guess_is_larger = False					

					iter_count += 1
				if "0x4012a8" in line:
					is_guess_correct = True
					

		if len(trace) - 3 > iter_count:
			password_len = iter_count - 1

		#print(trace)
		#print(correct_count)
		#print(iter_count)

	is_guess_correct = password_len != -1
	last_index = max(correct_letters.keys())
	cracked_password = ""
	for index in range(1, last_index + 1):
		if index in correct_letters:
			cracked_password += correct_letters[index]
		else:
			is_guess_correct = False
			cracked_password += "_"

	status = ",complete" if is_guess_correct else ",partial"
	cracked_password += status 
	#print(cracked_password)
	create_output(out_id, cracked_password)

if __name__ == "__main__":
	main()