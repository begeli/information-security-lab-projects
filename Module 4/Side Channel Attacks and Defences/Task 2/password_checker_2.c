#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

int check_password(char* p, int p_size,  char* i, int i_size) {

	int max_length = MIN(p_size, i_size); //only check till the end of the smallest string
	int pos = 0;
	int j, k = 0;

	for (pos = 0; pos < max_length; pos++)	{
		if (p[pos] == i[pos]) {
			k++;
		}
		else {
			j++;
		}	
	}

	if (p_size == i_size && k == p_size)
		return 1;
	else 
		return 0;

}

//assumptions: password only has small characters [a, z], maximum length is 31 characters
int main (int argc, char* argv[])	{

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <password guess>\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	FILE* password_file;
	char password [32] = "\0";
	
	size_t len = 0;
	char* line;
	password_file = fopen ("/home/sgx/isl/t2/password.txt", "r");

	if (password_file == NULL) {
		perror("cannot open password file\n");
		exit(EXIT_FAILURE);
	}

	fscanf(password_file, "%s", password);

	int is_match = 0; 
	is_match = check_password(password, strlen(password), argv[1], strlen(argv[1]));

	if (is_match == 1)
		printf("correct.\n");
	else
		printf("wrong.\n");

	fclose(password_file);
	return 0;
}


