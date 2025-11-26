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
#include "params.h"
#include "reduce.h"
#include <stdint.h>

/*************************************************
* Name:        PQCLEAN_MLDSA44_CLEAN_montgomery_reduce
*
* Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
*              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA44_CLEAN_montgomery_reduce(int64_t a) {
    int32_t t;

    t = (int32_t)((uint64_t)a * (uint64_t)QINV);
    t = (a - (int64_t)t * Q) >> 32;
    return t;
}

/*************************************************
* Name:        PQCLEAN_MLDSA44_CLEAN_reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA44_CLEAN_reduce32(int32_t a) {
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

/*************************************************
* Name:        PQCLEAN_MLDSA44_CLEAN_caddq
*
* Description: Add Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA44_CLEAN_caddq(int32_t a) {
    a += (a >> 31) & Q;
    return a;
}

/*************************************************
* Name:        PQCLEAN_MLDSA44_CLEAN_freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ Q.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA44_CLEAN_freeze(int32_t a) {
    a = PQCLEAN_MLDSA44_CLEAN_reduce32(a);
    a = PQCLEAN_MLDSA44_CLEAN_caddq(a);
    return a;
}
