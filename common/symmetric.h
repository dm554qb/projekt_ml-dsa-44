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
#ifndef PQCLEAN_MLDSA44_CLEAN_SYMMETRIC_H
#define PQCLEAN_MLDSA44_CLEAN_SYMMETRIC_H
#include "fips202.h"
#include "params.h"
#include <stdint.h>


typedef shake128incctx stream128_state;
typedef shake256incctx stream256_state;

void PQCLEAN_MLDSA44_CLEAN_dilithium_shake128_stream_init(shake128incctx *state,
        const uint8_t seed[SEEDBYTES],
        uint16_t nonce);

void PQCLEAN_MLDSA44_CLEAN_dilithium_shake256_stream_init(shake256incctx *state,
        const uint8_t seed[CRHBYTES],
        uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
    PQCLEAN_MLDSA44_CLEAN_dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
    shake128_inc_squeeze(OUT, (OUTBLOCKS)*(SHAKE128_RATE), STATE)
#define stream128_release(STATE) shake128_inc_ctx_release(STATE)

#define stream256_init(STATE, SEED, NONCE) \
    PQCLEAN_MLDSA44_CLEAN_dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
    shake256_inc_squeeze(OUT, (OUTBLOCKS)*(SHAKE256_RATE), STATE)
#define stream256_release(STATE) shake256_inc_ctx_release(STATE)

#endif
