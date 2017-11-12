all: test_pbkdf2

test_pbkdf2: test_pbkdf2.c pbkdf2_hmac_sha256.c pbkdf2_hmac_sha256.h
	gcc -O2 -Wall -Wextra -pedantic -std=c99 -o test_pbkdf2 test_pbkdf2.c pbkdf2_hmac_sha256.c

clean:
	rm -f test_pbkdf2
