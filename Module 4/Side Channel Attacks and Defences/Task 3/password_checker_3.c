#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define ADD(a,b) (a + b)


int pad_and_check(char *out, char *i, int i_size) {
	int pos1 = 0;
	int pos2 = 0;
	int found_dollar = 0;

  // Just check in case someone tries to be cheeky and use $.
	for (pos1 = 0; pos1 < (15 - i_size); pos1++) {
		out[pos1] = '$';
	}
	for (pos2 = 0; (pos1 + pos2) < 15; pos2++) {
		out[pos1 + pos2] = i[pos2];
		found_dollar |= (i[pos2] == '$');
	}
	return found_dollar;
}


int check_password(char* p, int p_size,  char* i, int i_size) {

	int pos = 0;
	int miss = 0;
	char guess [16] = "\0";

	if (i_size > 14 || i_size < 0) {
		return 0;
	}

	miss = pad_and_check(guess, i, i_size);

	for (pos = 0; pos < 15; pos++) {
		miss |= (p[pos] != guess[pos]);
	}

	return !miss;
}

//assumptions: password only has small characters [a, z], maximum length is 15 characters
int main (int argc, char* argv[])	{

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <password guess> <output_file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	FILE* password_file;
	char password [16] = "\0";

	size_t len = 0;
	char* line;
	password_file = fopen ("/home/sgx/isl/t3_3/password.txt", "r");

	if (password_file == NULL) {
		perror("cannot open password file\n");
		exit(EXIT_FAILURE);
	}

	fread(password, 1, 15, password_file);

	int is_match = 0;
	is_match = check_password(password, 15, argv[1], strlen(argv[1]));

	FILE* output_file;
	output_file = fopen (argv[2], "wb");
	fputc(is_match, output_file);
	fclose(output_file);

	fclose(password_file);
	return 0;
}


