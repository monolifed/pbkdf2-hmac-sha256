CFLAGS := -O2 -Wall -Wextra -Wsign-conversion -pedantic -std=c99
APPNAME := test_pbkdf2

ifeq ($(OS),Windows_NT)
	RM := del /Q
	CC := gcc
	EXT := .exe
endif

APP := $(APPNAME)$(EXT)
APP_OSSL := $(APPNAME)_ossl$(EXT)

all: $(APP)

$(APP): test_pbkdf2.c pbkdf2_sha256.h
	$(CC) $(CFLAGS) -o $@ $<

$(APP_OSSL): test_pbkdf2.c pbkdf2_sha256.h
	$(CC) $(CFLAGS) -DHAS_OSSL -o $@ $< -lcrypto

clean:
	$(RM) $(APP) $(APP_OSSL)
