all: test_pbkdf2

test_pbkdf2: test_pbkdf2.c pbkdf2_hmac_sha256.h
	gcc -O2 -Wall -Wextra -pedantic -std=c99 -o test_pbkdf2 test_pbkdf2.c

test_pbkdf2_ossl: test_pbkdf2.c pbkdf2_hmac_sha256.h
	gcc -O2 -Wall -Wextra -pedantic -std=c99 -DHAS_OSSL -o test_pbkdf2_ossl test_pbkdf2.c -lcrypto

clean:
	rm -f test_pbkdf2 test_pbkdf2_ossl
