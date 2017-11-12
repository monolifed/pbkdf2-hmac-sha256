
#include <stdio.h>
#include <string.h>

#include "pbkdf2_hmac_sha256.h"

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "test <key> <salt>");
		return 1;
	}
		
	unsigned dklen = 30;
	unsigned rounds = 100000;
	uint8_t DK[ dklen ];
	pbkdf2_sha256((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]), rounds, DK, dklen);
	for (size_t i = 0; i < dklen; i++)
	{
		printf("%02X%s", DK[ i ], (i % 4 == 3) ? "-" : "");
	}
	printf("\n");
	return 0;
}
