#include <stdio.h>
#include <string.h>

#define PBKDF2_SHA256_STATIC
#define PBKDF2_SHA256_IMPLEMENTATION
#include "pbkdf2_hmac_sha256.h"

#if defined(HAS_OSSL)
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#endif

void print_as_hex(const uint8_t *s,  const uint32_t slen)
{
	for (uint32_t i = 0; i < slen; i++)
	{
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
	}
	printf("\n");
}

void check_with_ossl(const uint8_t *this_one, const uint8_t *ossl_one, uint32_t len, 
	const char *what)
{
	if (memcmp(this_one, ossl_one, len) == 0)
	{
		printf(" *ossl %s matches.\n", what);
	}
	else
	{
		printf(" *ossl %s does not match. It was:\n", what);
		print_as_hex(ossl_one, len);
	}
}

void compute_sha(const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN];
	SHA256_CTX sha;
	sha256_init(&sha);
	sha256_update(&sha, msg, mlen);
	sha256_final(&sha, md);
	print_as_hex(md, sizeof md);

#if defined(HAS_OSSL)
	uint8_t md_ossl[SHA256_DIGESTLEN];
	EVP_MD_CTX *sha_ossl = EVP_MD_CTX_new();
	EVP_DigestInit_ex(sha_ossl, EVP_sha256(), 0);
	EVP_DigestUpdate(sha_ossl, msg, mlen);
	EVP_DigestFinal_ex(sha_ossl, md_ossl, 0);
	
	EVP_MD_CTX_free(sha_ossl);

	check_with_ossl(md, md_ossl, sizeof md, "sha256");
#endif
}

void compute_hmac(const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN];
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, msg, mlen);
	hmac_sha256_final(&hmac, md);
	print_as_hex(md, sizeof md);

#if defined(HAS_OSSL)
	uint8_t md_ossl[SHA256_DIGESTLEN];
	HMAC_CTX *hmac_ossl = HMAC_CTX_new();
	HMAC_Init_ex(hmac_ossl, key, klen, EVP_sha256(), 0);
	HMAC_Update(hmac_ossl, msg, mlen);
	HMAC_Final(hmac_ossl, md_ossl, 0);
	
	HMAC_CTX_free(hmac_ossl);

	check_with_ossl(md, md_ossl, sizeof md, "hmac-sha256");

#endif
}

void compute_pbkdf2(const uint8_t *key, uint32_t klen, const uint8_t *salt, uint32_t slen,
	uint32_t rounds, uint32_t dklen)
{
	uint8_t dk[dklen];
	HMAC_SHA256_CTX pbkdf_hmac;
	pbkdf2_sha256(&pbkdf_hmac, key, klen, salt, slen, rounds, dk, dklen);
	print_as_hex(dk, dklen);
	
#if defined(HAS_OSSL)
	uint8_t dk_ossl[dklen];
	PKCS5_PBKDF2_HMAC((const char *) key, klen, salt, slen, rounds, EVP_sha256(), dklen, dk_ossl);

	check_with_ossl(dk, dk_ossl, sizeof dk, "pbkdf2-sha256");
#endif
}

#define DKLEN 50
#define ROUNDS 1000

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		fprintf(stderr, "test <arg1> <arg2>\n");
		return 1;
	}
	printf("SHA256 of argv[1]:\n");
	compute_sha((uint8_t *) argv[1], strlen(argv[1]));
	printf("\n");
	
	printf("HMAC-SHA256 of argv[2] with key arg[1]:\n");
	compute_hmac((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]));
	printf("\n");
	
	printf("PBKDF2 of key:arg[1], salt:arg[2], rounds:%i, dklen:%i \n", ROUNDS, DKLEN);
	compute_pbkdf2((uint8_t *) argv[1], strlen(argv[1]), (uint8_t *) argv[2], strlen(argv[2]),
		ROUNDS, DKLEN);
	printf("\n");
	
	return 0;
}