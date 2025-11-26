/*
    Pôvodný autor kódu:
        Komunita PQClean (BSD-2-Clause licencia)

    Tento súbor je súčasťou projektu:
        Post-kvantové digitálne podpisy – ML-DSA-44

    Zdrojový kód je prevzatý bez úprav z projektu PQClean:
        https://github.com/PQClean/PQClean/tree/master/crypto_sign/ml-dsa-44

    Licencia pôvodného kódu:
        SPDX-License-Identifier: BSD-2-Clause

    Poznámka:
        Súbor je zahrnutý v projekte len ako súčasť implementácie ML-DSA-44.
        Neobsahuje žiadne úpravy ani zásahy oproti originálnemu PQClean kódu.
*/
#ifndef PQCLEAN_MLDSA44_CLEAN_NTT_H
#define PQCLEAN_MLDSA44_CLEAN_NTT_H
#include "params.h"
#include <stdint.h>

void PQCLEAN_MLDSA44_CLEAN_ntt(int32_t a[N]);

void PQCLEAN_MLDSA44_CLEAN_invntt_tomont(int32_t a[N]);

#endif
