/*
 *  Bob Jr. is the smaller sponge using Keccak permutation K-f[800]. Reference:
 *    https://github.com/XKCP
 *    https://keccak.team/files/Keccak-reference-3.0.pdf
 *
 *  WAM is for word-aligned, whole-word, forward memory operations.
 */

#include "supp.h"

#ifndef CONF_KF800_UNROLL
#define CONF_KF800_UNROLL 1
#endif

/*
 * K-f[800] defines 22 rounds. Turn on if need more than the default 10.
 */
#ifndef CONF_KF800_FULLR
#define CONF_KF800_FULLR 0
#endif

#define BOBJR_RATE 68
#define BOBJR_NROUNDS 10

#if CONF_KF800_FULLR
#define KF800_MAXR 22
#else
#define KF800_MAXR 10
#endif

#define STR(s) STR_(s)
#define STR_(s) #s

/* -----------------------------------------------------------------------------
 * K-f[800] in Thumb-2 assembler.
 * 712B, 27+338/r. 10r = 3407c or 50 c/b.
 */
#if defined(__thumb2__)
void _align4 _naked kf800_permute(uint32_t *A, uint nr)
{
   // clang-format off
   asm(
      "push       {r4-r11, lr}" br
      "rsb        lr, r1, #" STR(KF800_MAXR) br // 11c.

   ".L_round:" br
      "cmp        lr, #" STR(KF800_MAXR) br
      "bhs        .L_done" br                   // 2c (4c for exit).

// Theta, part 1. C[5] in r1-r5. 6+43+1=50c.
      "ldm        r0!, {r1-r5}" br
      "ldm        r0!, {r6-r12}" br
      "eors       r1, r6" br
      "eors       r2, r7" br
      "eor        r3, r8" br
      "eor        r4, r9" br
      "eor        r5, r10" br
      "eor        r1, r11" br
      "eor        r2, r12" br

      "ldm        r0!, {r6-r12}" br
      "eors       r3, r6" br
      "eors       r4, r7" br
      "eor        r5, r8" br
      "eor        r1, r9" br
      "eor        r2, r10" br
      "eor        r3, r11" br
      "eor        r4, r12" br

      "ldm        r0!, {r6-r11}" br
      "eors       r5, r6" br
      "eors       r1, r7" br
      "eor        r2, r8" br
      "eor        r3, r9" br
      "eor        r4, r10" br
      "eor        r5, r11" br

      "subs       r0, #100" br         // restore A

// Theta, part 2. D[5] in r8-r12. 5c
      "eor        r8, r5, r2, ror #31" br    // D0 = C4 ^ (C1 <<< 1)
      "eor        r9, r1, r3, ror #31" br    // D1 = C0 ^ (C2 <<< 1)
      "eor        r10, r2, r4, ror #31" br   // D2 = C1 ^ (C3 <<< 1)
      "eor        r11, r3, r5, ror #31" br   // D3 = C2 ^ (C4 <<< 1)
      "eor        r12, r4, r1, ror #31" br   // D4 = C3 ^ (C0 <<< 1)

// Theta, part 3. A[] in r1-r7 (7,7,7,4 batches). 23x3+14+1=84c.
      "ldm        r0, {r1-r7}" br
      "eor        r1, r8" br
      "eor        r2, r9" br
      "eor        r3, r10" br
      "eor        r4, r11" br
      "eor        r5, r12" br
      "eor        r6, r8" br
      "eor        r7, r9" br
      "stm        r0!, {r1-r7}" br

      "ldm        r0, {r1-r7}" br
      "eor        r1, r10" br
      "eor        r2, r11" br
      "eor        r3, r12" br
      "eor        r4, r8" br
      "eor        r5, r9" br
      "eor        r6, r10" br
      "eor        r7, r11" br
      "stm        r0!, {r1-r7}" br

      "ldm        r0, {r1-r7}" br
      "eor        r1, r12" br
      "eor        r2, r8" br
      "eor        r3, r9" br
      "eor        r4, r10" br
      "eor        r5, r11" br
      "eor        r6, r12" br
      "eor        r7, r8" br
      "stm        r0!, {r1-r7}" br

      "ldm        r0, {r1-r4}" br
      "eor        r1, r9" br
      "eor        r2, r10" br
      "eor        r3, r11" br
      "eor        r4, r12" br
      "stm        r0!, {r1-r4}" br

      "subs       r0, #100" br

// Rho & Pi. 6 elements per batch, using r1-r6, r7-r12. 18+19+19+20=76c.
      "ldr        r1, [r0, #1*4]" br
      "ldr        r2, [r0, #10*4]" br
      "ldr        r3, [r0, #7*4]" br
      "ldr        r4, [r0, #11*4]" br
      "ldr        r5, [r0, #17*4]" br
      "ldr        r6, [r0, #18*4]" br
      "ror        r7, r1, #31" br
      "ror        r8, r2, #29" br
      "ror        r9, r3, #26" br
      "ror        r10, r4, #22" br
      "ror        r11, r5, #17" br
      "ror        r12, r6, #11" br
      "str        r7, [r0, #10*4]" br
      "str        r8, [r0, #7*4]" br
      "str        r9, [r0, #11*4]" br
      "str        r10, [r0, #17*4]" br
      "str        r11, [r0, #18*4]" br

      "ldr        r1, [r0, #3*4]" br
      "ldr        r2, [r0, #5*4]" br
      "ldr        r3, [r0, #16*4]" br
      "ldr        r4, [r0, #8*4]" br
      "ldr        r5, [r0, #21*4]" br
      "ldr        r6, [r0, #24*4]" br
      "str        r12, [r0, #3*4]" br
      "ror        r7, r1, #4" br
      "ror        r8, r2, #28" br
      "ror        r9, r3, #19" br
      "ror        r10, r4, #9" br
      "ror        r11, r5, #30" br
      "ror        r12, r6, #18" br
      "str        r7, [r0, #5*4]" br
      "str        r8, [r0, #16*4]" br
      "str        r9, [r0, #8*4]" br
      "str        r10, [r0, #21*4]" br
      "str        r11, [r0, #24*4]" br

      "ldr        r1, [r0, #4*4]" br
      "ldr        r2, [r0, #15*4]" br
      "ldr        r3, [r0, #23*4]" br
      "ldr        r4, [r0, #19*4]" br
      "ldr        r5, [r0, #13*4]" br
      "ldr        r6, [r0, #12*4]" br
      "str        r12, [r0, #4*4]" br
      "ror        r7, r1, #5" br
      "ror        r8, r2, #23" br
      "ror        r9, r3, #8" br
      "ror        r10, r4, #24" br
      "ror        r11, r5, #7" br
      "ror        r12, r6, #21" br
      "str        r7, [r0, #15*4]" br
      "str        r8, [r0, #23*4]" br
      "str        r9, [r0, #19*4]" br
      "str        r10, [r0, #13*4]" br
      "str        r11, [r0, #12*4]" br

      "ldr        r1, [r0, #2*4]" br
      "ldr        r2, [r0, #20*4]" br
      "ldr        r3, [r0, #14*4]" br
      "ldr        r4, [r0, #22*4]" br
      "ldr        r5, [r0, #9*4]" br
      "ldr        r6, [r0, #6*4]" br
      "str        r12, [r0, #2*4]" br
      "ror        r7, r1, #2" br
      "ror        r8, r2, #14" br
      "ror        r9, r3, #25" br
      "ror        r10, r4, #3" br
      "ror        r11, r5, #12" br
      "ror        r12, r6, #20" br
      "str        r7, [r0, #20*4]" br
      "str        r8, [r0, #14*4]" br
      "str        r9, [r0, #22*4]" br
      "str        r10, [r0, #9*4]" br
      "str        r11, [r0, #6*4]" br
      "str        r12, [r0, #1*4]" br

// Chi. Load A[] in r6-r10; result in r1-r5. 22x5+1=111c.
      "ldm        r0, {r6-r10}" br
      "bic        r1, r8, r7" br
      "eors       r1, r6" br
      "bic        r2, r9, r8" br
      "eors       r2, r7" br
      "bic        r3, r10, r9" br
      "eor        r3, r8" br
      "bic        r4, r6, r10" br
      "eor        r4, r9" br
      "bic        r5, r7, r6" br
      "eor        r5, r10" br
      "stm        r0!, {r1-r5}" br

      "ldm        r0, {r6-r10}" br
      "bic        r1, r8, r7" br
      "eors       r1, r6" br
      "bic        r2, r9, r8" br
      "eors       r2, r7" br
      "bic        r3, r10, r9" br
      "eor        r3, r8" br
      "bic        r4, r6, r10" br
      "eor        r4, r9" br
      "bic        r5, r7, r6" br
      "eor        r5, r10" br
      "stm        r0!, {r1-r5}" br

      "ldm        r0, {r6-r10}" br
      "bic        r1, r8, r7" br
      "eors       r1, r6" br
      "bic        r2, r9, r8" br
      "eors       r2, r7" br
      "bic        r3, r10, r9" br
      "eor        r3, r8" br
      "bic        r4, r6, r10" br
      "eor        r4, r9" br
      "bic        r5, r7, r6" br
      "eor        r5, r10" br
      "stm        r0!, {r1-r5}" br

      "ldm        r0, {r6-r10}" br
      "bic        r1, r8, r7" br
      "eors       r1, r6" br
      "bic        r2, r9, r8" br
      "eors       r2, r7" br
      "bic        r3, r10, r9" br
      "eor        r3, r8" br
      "bic        r4, r6, r10" br
      "eor        r4, r9" br
      "bic        r5, r7, r6" br
      "eor        r5, r10" br
      "stm        r0!, {r1-r5}" br

      "ldm        r0, {r6-r10}" br
      "bic        r1, r8, r7" br
      "eors       r1, r6" br
      "bic        r2, r9, r8" br
      "eors       r2, r7" br
      "bic        r3, r10, r9" br
      "eor        r3, r8" br
      "bic        r4, r6, r10" br
      "eor        r4, r9" br
      "bic        r5, r7, r6" br
      "eor        r5, r10" br
      "stm        r0!, {r1-r5}" br
      "subs       r0, #100" br

// Iota. 10c
      "adr        r2, .L_rcs" br
      "ldr        r1, [r0, #0]" br
      "ldr        r2, [r2, lr, lsl #2]" br
      "eors       r1, r2" br
      "str        r1, [r0, #0]" br
      "add        lr, #1" br
      "b          .L_round" br

// Total 338c per round.
   ".L_done:" br
      "pop        {r4-r11, pc}" br

      ".align     2" br
   ".L_rcs:" br
#if CONF_KF800_FULLR
      ".word 0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b" br
      ".word 0x80000001, 0x80008081, 0x00008009, 0x0000008a, 0x00000088" br
      ".word 0x80008009, 0x8000000a" br
#endif
      ".word 0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002" br
      ".word 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080" br
      : : :"r1","r2","r3","r12","lr","cc","memory"
   );
   // clang-format on
}

#else

/* -----------------------------------------------------------------------------
 * C version.
 * M0 unrolled: 700B, 24+509/r, ~75.2 c/b.
 * M0 iterative: 440B, 25+708/r, ~104.5 c/b.
 */

static inline uint32_t ROL(uint32_t x, uint32_t n)
{
   return (x << n) | (x >> (32u - n));
}

void kf800_permute(uint32_t *A, uint nr)
{
   // clang-format off
   static const uint32_t kf800_rcs[KF800_MAXR] = {
#if CONF_KF800_FULLR
      0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b,
      0x80000001, 0x80008081, 0x00008009, 0x0000008a, 0x00000088,
      0x80008009, 0x8000000a,
#endif
      0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002,
      0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080
   };
   // clang-format on

   uint32_t X, Y;
   uint32_t C[5], D[5];

   /* NB: unsigned iterator will reject nr>KF800_MAXR case. */
   for (uint r = KF800_MAXR - nr; r < KF800_MAXR; r++) {
      /* Theta */
#if CONF_KF800_UNROLL
      C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
      C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
      C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
      C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
      C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];
#else
      for (int x = 0; x < 5; x++)
         C[x] = A[x] ^ A[5 + x] ^ A[10 + x] ^ A[15 + x] ^ A[20 + x];
#endif

      D[0] = C[4] ^ ROL(C[1], 1);
      D[1] = C[0] ^ ROL(C[2], 1);
      D[2] = C[1] ^ ROL(C[3], 1);
      D[3] = C[2] ^ ROL(C[4], 1);
      D[4] = C[3] ^ ROL(C[0], 1);

#if CONF_KF800_UNROLL
      A[0] ^= D[0], A[5] ^= D[0], A[10] ^= D[0], A[15] ^= D[0], A[20] ^= D[0];
      A[1] ^= D[1], A[6] ^= D[1], A[11] ^= D[1], A[16] ^= D[1], A[21] ^= D[1];
      A[2] ^= D[2], A[7] ^= D[2], A[12] ^= D[2], A[17] ^= D[2], A[22] ^= D[2];
      A[3] ^= D[3], A[8] ^= D[3], A[13] ^= D[3], A[18] ^= D[3], A[23] ^= D[3];
      A[4] ^= D[4], A[9] ^= D[4], A[14] ^= D[4], A[19] ^= D[4], A[24] ^= D[4];
#else
      for (int x = 0; x < 5; x++) {
         A[x] ^= D[x];
         A[x + 5] ^= D[x];
         A[x + 10] ^= D[x];
         A[x + 15] ^= D[x];
         A[x + 20] ^= D[x];
      }
#endif
      /* Rho and Pi combined. */
      Y = A[1], X = A[10], A[10] = ROL(Y, 1);
      Y = X, X = A[7], A[7] = ROL(Y, 3);
      Y = X, X = A[11], A[11] = ROL(Y, 6);
      Y = X, X = A[17], A[17] = ROL(Y, 10);
      Y = X, X = A[18], A[18] = ROL(Y, 15);
      Y = X, X = A[3], A[3] = ROL(Y, 21);

      Y = X, X = A[5], A[5] = ROL(Y, 28);
      Y = X, X = A[16], A[16] = ROL(Y, 4);
      Y = X, X = A[8], A[8] = ROL(Y, 13);
      Y = X, X = A[21], A[21] = ROL(Y, 23);
      Y = X, X = A[24], A[24] = ROL(Y, 2);
      Y = X, X = A[4], A[4] = ROL(Y, 14);

      Y = X, X = A[15], A[15] = ROL(Y, 27);
      Y = X, X = A[23], A[23] = ROL(Y, 9);
      Y = X, X = A[19], A[19] = ROL(Y, 24);
      Y = X, X = A[13], A[13] = ROL(Y, 8);
      Y = X, X = A[12], A[12] = ROL(Y, 25);
      Y = X, X = A[2], A[2] = ROL(Y, 11);

      Y = X, X = A[20], A[20] = ROL(Y, 30);
      Y = X, X = A[14], A[14] = ROL(Y, 18);
      Y = X, X = A[22], A[22] = ROL(Y, 7);
      Y = X, X = A[9], A[9] = ROL(Y, 29);
      Y = X, X = A[6], A[6] = ROL(Y, 20);
      A[1] = ROL(X, 12);

      /* Chi */
#if CONF_KF800_UNROLL
      X = A[0], Y = A[1];
      A[0] ^= ~Y & A[2];
      A[1] ^= ~A[2] & A[3];
      A[2] ^= ~A[3] & A[4];
      A[3] ^= ~A[4] & X;
      A[4] ^= ~X & Y;

      X = A[5], Y = A[6];
      A[5] ^= ~Y & A[7];
      A[6] ^= ~A[7] & A[8];
      A[7] ^= ~A[8] & A[9];
      A[8] ^= ~A[9] & X;
      A[9] ^= ~X & Y;

      X = A[10], Y = A[11];
      A[10] ^= ~Y & A[12];
      A[11] ^= ~A[12] & A[13];
      A[12] ^= ~A[13] & A[14];
      A[13] ^= ~A[14] & X;
      A[14] ^= ~X & Y;

      X = A[15], Y = A[16];
      A[15] ^= ~Y & A[17];
      A[16] ^= ~A[17] & A[18];
      A[17] ^= ~A[18] & A[19];
      A[18] ^= ~A[19] & X;
      A[19] ^= ~X & Y;

      X = A[20], Y = A[21];
      A[20] ^= ~Y & A[22];
      A[21] ^= ~A[22] & A[23];
      A[22] ^= ~A[23] & A[24];
      A[23] ^= ~A[24] & X;
      A[24] ^= ~X & Y;

#else
      for (int y = 0; y < 25; y += 5) {
         X = A[y + 0], Y = A[y + 1];
         A[y + 0] ^= ~Y & A[y + 2];
         A[y + 1] ^= ~A[y + 2] & A[y + 3];
         A[y + 2] ^= ~A[y + 3] & A[y + 4];
         A[y + 3] ^= ~A[y + 4] & X;
         A[y + 4] ^= ~X & Y;
      }
#endif

      /* Iota */
      A[0] ^= kf800_rcs[r];
   }
}
#endif  // C version.

/* -------------------------------------------------------------------------- */
void bobjr_absorb_wa(bobjr_ctx *ctx, const uint8_t *data, uint len)
{
   uint ptr = ctx->ptr;
   while (len) {
      uint cpy = BOBJR_RATE - ptr;
      cpy = len < cpy ? len : cpy;
      wam_copy(ctx->state + ptr, data, cpy);
      len -= cpy;
      data += cpy;
      ptr += cpy;
      if (ptr == BOBJR_RATE) {
         kf800_permute((uint32_t *)ctx->state, BOBJR_NROUNDS);
         ptr = 0;
      }
   }
   ctx->ptr = ptr;
}

/* -------------------------------------------------------------------------- */
void bobjr_finish_wa(bobjr_ctx *ctx)
{
   uint ptr = ctx->ptr;
   wam_zero(ctx->state + ptr, BOBJR_RATE - ptr);
   ctx->state[ptr] = 0x01;
   ctx->state[BOBJR_RATE - 1] |= 0x80;
   kf800_permute((uint32_t *)ctx->state, BOBJR_NROUNDS);
   ctx->ptr = 0;
}

/* -----------------------------------------------------------------------------
 * Memory copy. 4-words batch.
 */
#ifdef __thumb__
void _alfn _naked wam_copy(void *d, const void *s, uint len)
{
   // clang-format off
   asm(
      ".syntax unified" br
      "push       {r4-r6, lr}" br
      "lsrs       r2, #2" br
#ifdef __thumb2__
      "b.w        2f" br
#else
      "b          2f" br
#endif
      "1:" br
      "ldm        r1!, {r3-r6}" br
      "stm        r0!, {r3-r6}" br
   "2:" br
      "subs       r2, #4" br
      "bpl        1b" br
      "adds       r2, #4" br
      // 0-3 words left to copy.
      "beq        10f" br
      "cmp        r2, #2" br
      "beq        12f" br
      "bhi        13f" br
      "ldr        r3, [r1]" br
      "str        r3, [r0]" br
      "pop        {r4-r6, pc}" br
   "12:" br
      "ldm        r1!, {r3-r4}" br
      "stm        r0!, {r3-r4}" br
      "pop        {r4-r6, pc}" br
   "13:" br
      "ldm        r1!, {r3-r5}" br
      "stm        r0!, {r3-r5}" br
   "10:" br
      "pop        {r4-r6, pc}" br
      : : :"r0","r1","r2","r3","cc","memory"
   );
   // clang-format on
}
#else
void wam_copy(void *d, const void *s, uint len)
{
   uint32_t *D = (uint32_t *)d;
   uint32_t *S = (uint32_t *)s;
   len /= 4;
   while (len >= 2) {
      *D++ = *S++;
      *D++ = *S++;
      len -= 2;
   }
   if (len) *D++ = *S++;
}
#endif

/* -----------------------------------------------------------------------------
 * Memory fillers. 4-words batch.
 */
#ifdef __thumb__
void _alfn _naked wam_zero(void *w, uint len)
{
   // clang-format off
   asm(
      ".syntax    unified" br
#ifdef __thumb2__
      "mov.w      r2, #0" br
#else
      "movs       r2, #0" br
#endif
      ".thumb_func" br
      ".global wam_fill" br
   "wam_fill:" br
      "push       {r4, r5, lr}" br
      "mov        r3, r2" br
      "lsrs       r1, #2" br
      "mov        r4, r2" br
      "mov        r5, r3" br
      "b          2f" br
   "1:" br
      "stm        r0!, {r2-r5}" br
   "2:" br
      "subs       r1, #4" br
      "bpl        1b" br
      "adds       r1, #4" br
      // 0-3 words left.
      "beq        10f" br
      "cmp        r1, #2" br
      "beq        12f" br
      "bhi        13f" br
      "str        r2, [r0]" br
      "pop        {r4, r5, pc}" br
   "12:" br
      "stm        r0!, {r2, r3}" br
      "pop        {r4, r5, pc}" br
   "13:" br
      "stm        r0!, {r2-r4}" br
   "10:" br
      "pop        {r4, r5, pc}" br
      : : :"r0","r1","r2","r3","cc","memory"
   );
   // clang-format on
}
#else
void wam_fill(void *w, uint len, uint v)
{
   uint32_t *W = (uint32_t *)w;

   len /= 4;
   while (len >= 2) {
      *W++ = v;
      *W++ = v;
      len -= 2;
   }
   if (len) *W = v;
}

void wam_zero(void *w, uint len)
{
   wam_fill(w, len, 0);
}
#endif

/* -----------------------------------------------------------------------------
 * Block swap. Thumb-1 does 2w and Thumb-2 does 4w. Number of usable registers
 * seriously limits batch size.
 */
#ifdef __thumb__
void _alfn _naked wam_swap(void *a, void *b, uint len)
{
   // clang-format off
   asm(
      ".syntax    unified" br
#ifdef __thumb2__
      "push       {r4-r8, lr}" br
      "lsrs       r2, #2" br
      "b          2f" br
   "1:" br
      "ldm        r0, {r3-r6}" br
      "ldm        r1, {r7, r8, r12, lr}" br
      "stm        r0!, {r7, r8, r12, lr}" br
      "stm        r1!, {r3-r6}" br
   "2:" br
      "subs       r2, #4" br
      "bpl.w      1b" br
      "adds       r2, #4" br
      "beq        10f" br
      // 1-3 words, loop.
   "3:" br
      "ldr        r3, [r0]" br
      "ldr        r4, [r1]" br
      "str        r4, [r0], #4" br
      "str        r3, [r1], #4" br
      "subs       r2, #1" br
      "bne        3b" br
   "10:" br
      "pop        {r4-r8, pc}" br
      : : :"r0","r1","r2","r3","r12","lr","cc","memory"
#else
      "push       {r4-r6}" br
      "lsrs       r2, #2" br
      "b          2f" br
   "1:" br
      "ldm        r0!, {r3, r4}" br
      "ldm        r1!, {r5, r6}" br
      "subs       r0, #8" br
      "subs       r1, #8" br
      "stm        r0!, {r5, r6}" br
      "stm        r1!, {r3, r4}" br
   "2:" br
      "subs       r2, #2" br
      "bpl        1b" br
      "adds       r2, #2" br
      "beq        10f" br
      "ldr        r3, [r0]" br
      "ldr        r5, [r1]" br
      "str        r5, [r0]" br
      "str        r3, [r1]" br
   "10:" br
      "pop        {r4-r6}" br
      "bx         lr" br
      : : :"r0","r1","r2","r3","cc","memory"
#endif
   );
   // clang-format on
}

#else
void wam_swap(void *a, void *b, uint len)
{
   uint32_t *A = (uint32_t *)a;
   uint32_t *B = (uint32_t *)b;
   uint32_t T;

   len /= 4;
   while (len >= 2) {
      T = *A;
      *A++ = *B;
      *B++ = T;
      T = *A;
      *A++ = *B;
      *B++ = T;
      len -= 2;
   }
   if (len) {
      T = *A;
      *A++ = *B;
      *B++ = T;
   }
}
#endif

/* vim: set syn=c cin et sw=3 ts=3 tw=80 fo=1cjMmnoqr: */
