#    Názov súboru: Makefile
#    Autor: Dávid Mudrák
#    Popis: Kompilácia a linkovanie projektových súborov ML-DSA-44
#           (genkey, sign_file, verify, openssl_from_app, app_from_openssl)
#           vrátane PQClean implementácie a OpenSSL kompatibility.
#    Diplomová práca: Post-kvantové digitálne podpisy
#    Študijný program: Počítačové siete (Ing.)
#    Školiace pracovisko: KEMT FEI TUKE
#    Dátum: 25.11.2025
#    Vygenerované pomocou ChatGPT



CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -Isource -Icommon -IC:/OPENSSL/include

# Na Windows/MinGW nelinkujeme priamo libcrypto/libssl,
# lebo pouzivame len externy program openssl.exe, nie C API.
LDFLAGS =

SRC_DIR = source
COMMON_DIR = common
KEYS_DIR = keys

# Spolocne zdrojaky – LEN common/*.c, NIE keccak2x/ a keccak4x/
COMMON_SRC = $(wildcard $(COMMON_DIR)/*.c)

# Tvoje hlavne programy v source/
APP_GENKEY          = $(SRC_DIR)/genkey.c
APP_SIGN            = $(SRC_DIR)/sign_file.c
APP_VERIFY          = $(SRC_DIR)/verify.c
APP_OPENSSL_FROMAPP = $(SRC_DIR)/openssl_from_app.c
APP_APP_FROMOPENSSL = $(SRC_DIR)/app_from_openssl.c

# Binarky ML-DSA
BINARIES = genkey sign_file verify openssl_from_app app_from_openssl

# ===== All =====
all: $(BINARIES)

# ----- ML-DSA executables -----
genkey: $(APP_GENKEY) $(COMMON_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sign_file: $(APP_SIGN) $(COMMON_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

verify: $(APP_VERIFY) $(COMMON_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ----- OpenSSL direction: APP -> OpenSSL -----
openssl_from_app: $(APP_OPENSSL_FROMAPP)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ----- OpenSSL direction: OpenSSL -> APP -----
app_from_openssl: $(APP_APP_FROMOPENSSL)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ----- Utility targets -----
clean:
	rm -f $(SRC_DIR)/*.o $(COMMON_DIR)/*.o
	rm -f $(BINARIES) *.exe
	rm -f $(KEYS_DIR)/*.pem $(KEYS_DIR)/*.bin $(KEYS_DIR)/*.txt \
	      $(KEYS_DIR)/*.hex $(KEYS_DIR)/*.sig

clean_keys:
	rm -f $(KEYS_DIR)/*.pem $(KEYS_DIR)/*.bin $(KEYS_DIR)/*.txt \
	      $(KEYS_DIR)/*.hex $(KEYS_DIR)/*.sig

.PHONY: all clean clean_keys
