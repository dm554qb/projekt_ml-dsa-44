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
#ifndef PQCLEAN_MLDSA44_CLEAN_REDUCE_H
#define PQCLEAN_MLDSA44_CLEAN_REDUCE_H
#include "params.h"
#include <stdint.h>

#define MONT (-4186625) // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

int32_t PQCLEAN_MLDSA44_CLEAN_montgomery_reduce(int64_t a);

int32_t PQCLEAN_MLDSA44_CLEAN_reduce32(int32_t a);

int32_t PQCLEAN_MLDSA44_CLEAN_caddq(int32_t a);

int32_t PQCLEAN_MLDSA44_CLEAN_freeze(int32_t a);

#endif
