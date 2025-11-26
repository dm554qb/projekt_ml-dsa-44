/*
    Názov súboru: sign_file.c
    Autor: Dávid Mudrák
    Popis: Podpisovanie súborov pomocou post-kvantovej schémy ML-DSA-44.
           Načíta súbor a súkromný kľúč, vytvorí podpis a uloží ho do keys/.
    Diplomová práca: Post-kvantové digitálne podpisy
    Študijný program: Počítačové siete (Ing.)
    Školiace pracovisko: KEMT FEI TUKE
    Dátum: 25.11.2025
*/
/* Vygenerované pomocou ChatGPT */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Pouzitie: %s <subor_na_podpisanie> <subor_so_sukromnym_klucom>\n", argv[0]);
        fprintf(stderr, "Priklad: %s files/test_bin.bin keys/app_secretkey.bin\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *input_file = argv[1];
    const char *secretkey_file = argv[2];

    FILE *fin = fopen(input_file, "rb");
    if (!fin) {
        perror("Chyba pri otvarani vstupneho suboru");
        return EXIT_FAILURE;
    }

    FILE *fsk = fopen(secretkey_file, "rb");
    if (!fsk) {
        perror("Chyba pri otvarani sukromneho kluca");
        fclose(fin);
        return EXIT_FAILURE;
    }

    // Nacitanie obsahu suboru
    fseek(fin, 0, SEEK_END);
    size_t mlen = ftell(fin);
    rewind(fin);

    uint8_t *message = malloc(mlen);
    if (!message) {
        fprintf(stderr, "Chyba: nedostatok pamate.\n");
        fclose(fin);
        fclose(fsk);
        return EXIT_FAILURE;
    }

    size_t read_bytes_msg = fread(message, 1, mlen, fin);
    fclose(fin);

    if (read_bytes_msg != mlen) {
        fprintf(stderr, "Chyba: nepodarilo sa nacitat cely subor '%s' (precitane %zu z %zu bajtov)\n",
                input_file, read_bytes_msg, mlen);
        free(message);
        fclose(fsk);
        return EXIT_FAILURE;
    }


    // Nacitanie sukromneho kluca
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    size_t read_bytes = fread(sk, 1, sizeof(sk), fsk);
    fclose(fsk);

    if (read_bytes != sizeof(sk)) {
        fprintf(stderr, "Chyba: nespravna velkost sukromneho kluca (%zu / %zu bajtov)\n",
                read_bytes, sizeof(sk));
        free(message);
        return EXIT_FAILURE;
    }

    // Vytvorenie podpisu
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t siglen = 0;

    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, message, mlen, sk) != 0) {
        fprintf(stderr, "Chyba: podpis sa nepodarilo vytvorit.\n");
        free(message);
        return EXIT_FAILURE;
    }

    // Ulozenie podpisu do suboru
    FILE *fsig = fopen("keys/app_sign.bin", "wb");
    if (!fsig) {
        perror("Chyba pri ukladani podpisu");
        free(message);
        return EXIT_FAILURE;
    }

    fwrite(sig, 1, siglen, fsig);
    fclose(fsig);

    printf("Subor '%s' bol uspesne podpisany.\n", input_file);
    printf("Pouzity sukromny kluc: %s\n", secretkey_file);
    printf("Podpis ulozeny ako 'keys/app_sign.bin' (%zu bajtov)\n", siglen);

    free(message);
    return EXIT_SUCCESS;
}
