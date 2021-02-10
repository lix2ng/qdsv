/*
 *  Bob Jr. is the smaller sponge using Keccak permutation K-f[800]. Reference:
 *    https://github.com/XKCP
 *    https://keccak.team/files/Keccak-reference-3.0.pdf
 *
 *  WAM is for word-aligned, whole-word, forward memory operations.
 */

#ifndef SUPP_H_
#define SUPP_H_

/* -----------------------------------------------------------------------------
 * Handy stuff. (handy.h)
 */
#include <stdint.h>
typedef unsigned uint;
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
/* For end of line in inline assemblers. */
#define br "\n\t"

#define _naked __attribute__((naked))
#define _align4 __attribute__((aligned(4)))

#ifdef __thumb2__
#define _alfn __attribute__((aligned(4)))
#else
#define _alfn
#endif

/* -----------------------------------------------------------------------------
 * All lengths are in bytes, and are truncated to whole words.
 */
void wam_copy(void *d, const void *s, uint len);
void wam_zero(void *w, uint len);
void wam_fill(void *w, uint len, uint v);
void wam_swap(void *a, void *b, uint len);

/* -----------------------------------------------------------------------------
 * Bob Jr. is Keccak f[800] instantiated as follows:
 *  - Mode = overwrite
 *  - Rate = 68B
 *  - Capacity = 256b
 *  - Rounds: 10 for general use
 */

#define BOBJR_RATE 68

typedef struct bobjr_ctx {
   uint32_t ptr;                   // read/write pointer into state.
   uint8_t _align4 state[25 * 4];  // the 25 words Keccak state.
} bobjr_ctx;

void bobjr_init(bobjr_ctx *ctx);
/* "wa" suffix denotes word aligned operations. */
void bobjr_absorb_wa(bobjr_ctx *ctx, const uint8_t *data, uint len);
void bobjr_finish_wa(bobjr_ctx *ctx);
/* Removed squeeze since we're not using it. */

/* The K-f[800] permute function; might be useful. */
void kf800_permute(uint32_t *A, uint nr);

#endif /* SUPP_H_ */

/* vim: set syn=c cin et sw=3 ts=3 tw=80 fo=1cjMmnoqr: */
