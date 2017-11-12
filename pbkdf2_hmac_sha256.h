
#define SHA256_BLOCKLEN  64ul //size of message block buffer
#define SHA256_DIGESTLEN 32ul //size of digest
#define SHA256_DIGESTINT 8ul  //size in uint32_t = 32/4

#include <stdint.h>

typedef struct sha256_ctx_t
{
	uint64_t len;                 // processed message length
	uint32_t h[SHA256_DIGESTINT]; // hash state
	uint8_t buf[SHA256_BLOCKLEN]; // message block buffer
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *m, uint32_t mlen);
// resets state
void sha256_final(SHA256_CTX *ctx, uint8_t *md);

typedef struct hmac_sha256_ctx_t
{
	uint8_t inner_key[SHA256_BLOCKLEN];
	uint8_t outer_key[SHA256_BLOCKLEN];
	SHA256_CTX sha_init; // initial hash state
	SHA256_CTX sha;
} HMAC_SHA256_CTX;

void hmac_sha256_init(HMAC_SHA256_CTX *hmac, uint8_t *key, uint32_t keylen);
void hmac_sha256_update(HMAC_SHA256_CTX *hmac, uint8_t *m, uint32_t mlen);
// resets state to the one after init
void hmac_sha256_final(HMAC_SHA256_CTX *hmac, uint8_t *md);

void pbkdf2_sha256(uint8_t *key, uint32_t keylen, uint8_t *salt, uint32_t saltlen,
	uint32_t rounds, uint8_t *dk, uint32_t dklen);
