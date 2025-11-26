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
#ifndef PQCLEAN_MLDSA44_CLEAN_PACKING_H
#define PQCLEAN_MLDSA44_CLEAN_PACKING_H
#include "params.h"
#include "polyvec.h"
#include <stdint.h>

void PQCLEAN_MLDSA44_CLEAN_pack_pk(uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1);

void PQCLEAN_MLDSA44_CLEAN_pack_sk(uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const uint8_t tr[TRBYTES],
                                   const uint8_t key[SEEDBYTES],
                                   const polyveck *t0,
                                   const polyvecl *s1,
                                   const polyveck *s2);

void PQCLEAN_MLDSA44_CLEAN_pack_sig(uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES], const uint8_t c[CTILDEBYTES], const polyvecl *z, const polyveck *h);

void PQCLEAN_MLDSA44_CLEAN_unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES]);

void PQCLEAN_MLDSA44_CLEAN_unpack_sk(uint8_t rho[SEEDBYTES],
                                     uint8_t tr[TRBYTES],
                                     uint8_t key[SEEDBYTES],
                                     polyveck *t0,
                                     polyvecl *s1,
                                     polyveck *s2,
                                     const uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES]);

int PQCLEAN_MLDSA44_CLEAN_unpack_sig(uint8_t c[CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES]);

#endif
