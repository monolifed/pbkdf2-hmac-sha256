#include <stdio.h>
#include <string.h>
#include "pbkdf2_hmac_sha256.h"

#if defined(COMPARE_X_OSSL)
#include <openssl/evp.h>
#include <openssl/crypto.h>

//int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen,
//	int iter, const EVP_MD *digest, int keylen, unsigned char *out);
int ossl_pbkdf2_sha256(const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen,
	uint32_t rounds, uint8_t *dk, uint32_t dklen)
{
	return PKCS5_PBKDF2_HMAC((char *)key, keylen, salt, saltlen, rounds, EVP_sha256(), dklen, dk);
}
#endif

int print_as_hex(uint8_t *s,  uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) ? "-" : "");
	}
	printf("\n");
	return 0;
}

int compute_hmac(uint8_t *key, uint32_t klen, uint8_t *salt, uint32_t slen)
{
	uint8_t md[SHA256_DIGESTLEN];
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, salt, slen);
	hmac_sha256_final(&hmac, md);
	print_as_hex(md, sizeof md);
	return 0;
}

int compute_sha(uint8_t *key, uint32_t klen)
{
	uint8_t md[SHA256_DIGESTLEN];
	SHA256_CTX sha;
	sha256_init(&sha);
	sha256_update(&sha, key, klen);
	sha256_final(&sha, md);
	print_as_hex(md, sizeof md);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "test <key> <salt>\n");
		return 1;
	}
	printf("SHA256 of argv[1]:\n");
	compute_sha((uint8_t *) argv[1], strlen(argv[1]));
	
	printf("HMAC-SHA256 of argv[2] with key arg[1]:\n");
	compute_hmac((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]));
	
	unsigned dklen = 90;
	unsigned rounds = 1000;
	
	uint8_t dk_this[ dklen ];
	pbkdf2_sha256((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]),
		rounds, dk_this, dklen);
	printf("THIS_PBKDF2 of secret:arg[1], salt:arg[2], rounds:%i, dklen:%i \n", rounds, dklen);
	print_as_hex(dk_this, dklen);
	
#if defined(COMPARE_X_OSSL)
	uint8_t dk_ossl[ dklen ];
	ossl_pbkdf2_sha256((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]), rounds,
		dk_ossl, dklen);
	printf("OSSL_PBKDF2 of secret:arg[1], salt:arg[2], rounds:%i, dklen:%i \n", rounds, dklen);
	print_as_hex(dk_ossl, dklen);
	
	
	if (memcmp(dk_ossl, dk_this, dklen) == 0)
		printf("They match!\n");
	else
		printf("They do not match!\n");
#endif
		
	return 0;
}