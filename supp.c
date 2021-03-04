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
 * 648B, 30+278/r. 10r = 2810c or 41.3 c/b.
 */
#ifdef __thumb2__
void _align4 _naked kf800_permute(uint32_t *A, uint nr)
{
   // clang-format off
   asm(
      "push       {r4-r11, lr}" __
      "rsb        r1, #" STR(KF800_MAXR) __
      "adr        r2, .L_rcs" __
      "add        lr, r2, r1, lsl #2" __
   ".L_round:" __
      "adr        r1, .L_rc_end" __
      "cmp        lr, r1" __
      "bhs        .L_done" __

// Theta, part 1. C[5] in r1-r5.
      "ldm        r0!, {r1-r12}" __
      "eors       r1, r6" __
      "eors       r2, r7" __
      "eor        r3, r8" __
      "eor        r4, r9" __
      "eor        r5, r10" __
      "eor        r1, r11" __
      "eor        r2, r12" __

      "ldm        r0!, {r6-r12}" __
      "eors       r3, r6" __
      "eors       r4, r7" __
      "eor        r5, r8" __
      "eor        r1, r9" __
      "eor        r2, r10" __
      "eor        r3, r11" __
      "eor        r4, r12" __

      "ldm        r0!, {r6-r11}" __
      "eors       r5, r6" __
      "eors       r1, r7" __
      "eor        r2, r8" __
      "eor        r3, r9" __
      "eor        r4, r10" __
      "eor        r5, r11" __
      "subs       r0, #100" __

// Theta, part 2. D[5] in r8-r12.
      "eor        r8, r5, r2, ror #31" __    // D0 = C4 ^ (C1 <<< 1)
      "eor        r9, r1, r3, ror #31" __    // D1 = C0 ^ (C2 <<< 1)
      "eor        r10, r2, r4, ror #31" __   // D2 = C1 ^ (C3 <<< 1)
      "eor        r11, r3, r5, ror #31" __   // D3 = C2 ^ (C4 <<< 1)
      "eor        r12, r4, r1, ror #31" __   // D4 = C3 ^ (C0 <<< 1)

#define rD0 "r8"
#define rD1 "r9"
#define rD2 "r10"
#define rD3 "r11"
#define rD4 "r12"

// Theta part 3 and Rho and Pi all together.
      "ldr        r7, [r0]" __
      "eor        r7, " rD0 __
      "str        r7, [r0]" __
      /*
       * M3 & M4 TRM: neighboring LDR & STR single can pipeline their address
       * and data phase for 1c execution; but unaligned wide ops may disrupt it.
       * Also: STR Rx,[Ry,#imm] is always one cycle.
       */
      "ldr        r1, [r0, #4* 1]" __
      "ldr        r2, [r0, #4* 10]" __
      "ldr        r3, [r0, #4* 7]" __
      "ldr        r4, [r0, #4* 11]" __
      "ldr        r5, [r0, #4* 17]" __
      "ldr        r6, [r0, #4* 18]" __
      "eor        r1, " rD1 __
      "eor        r2, " rD0 __
      "eor        r3, " rD2 __
      "eor        r4, " rD1 __
      "eor        r5, " rD2 __
      "eor        r6, " rD3 __
      "ror        r1, #31" __
      "ror        r2, #29" __
      "ror        r3, #26" __
      "ror        r4, #22" __
      "ror        r5, #17" __
      "ror        r7, r6, #11" __
      "str        r1, [r0, #4* 10]" __
      "str        r2, [r0, #4* 7]" __
      "str        r3, [r0, #4* 11]" __
      "str        r4, [r0, #4* 17]" __
      "str        r5, [r0, #4* 18]" __

      "ldr        r1, [r0, #4* 3]" __
      "ldr        r2, [r0, #4* 5]" __
      "ldr        r3, [r0, #4* 16]" __
      "ldr        r4, [r0, #4* 8]" __
      "ldr        r5, [r0, #4* 21]" __
      "ldr        r6, [r0, #4* 24]" __
      "str        r7, [r0, #4* 3]" __
      "eor        r1, " rD3 __
      "eor        r2, " rD0 __
      "eor        r3, " rD1 __
      "eor        r4, " rD3 __
      "eor        r5, " rD1 __
      "eor        r6, " rD4 __
      "ror        r1, #4" __
      "ror        r2, #28" __
      "ror        r3, #19" __
      "ror        r4, #9" __
      "ror        r5, #30" __
      "ror        r7, r6, #18" __
      "str        r1, [r0, #4* 5]" __
      "str        r2, [r0, #4* 16]" __
      "str        r3, [r0, #4* 8]" __
      "str        r4, [r0, #4* 21]" __
      "str        r5, [r0, #4* 24]" __

      "ldr        r1, [r0, #4* 4]" __
      "ldr        r2, [r0, #4* 15]" __
      "ldr        r3, [r0, #4* 23]" __
      "ldr        r4, [r0, #4* 19]" __
      "ldr        r5, [r0, #4* 13]" __
      "ldr        r6, [r0, #4* 12]" __
      "str        r7, [r0, #4* 4]" __
      "eor        r1, " rD4 __
      "eor        r2, " rD0 __
      "eor        r3, " rD3 __
      "eor        r4, " rD4 __
      "eor        r5, " rD3 __
      "eor        r6, " rD2 __
      "ror        r1, #5" __
      "ror        r2, #23" __
      "ror        r3, #8" __
      "ror        r4, #24" __
      "ror        r5, #7" __
      "ror        r7, r6, #21" __
      "str        r1, [r0, #4* 15]" __
      "str        r2, [r0, #4* 23]" __
      "str        r3, [r0, #4* 19]" __
      "str        r4, [r0, #4* 13]" __
      "str        r5, [r0, #4* 12]" __

      "ldr        r1, [r0, #4* 2]" __
      "ldr        r2, [r0, #4* 20]" __
      "ldr        r3, [r0, #4* 14]" __
      "ldr        r4, [r0, #4* 22]" __
      "ldr        r5, [r0, #4* 9]" __
      "ldr        r6, [r0, #4* 6]" __
      "str        r7, [r0, #4* 2]" __
      "eor        r1, " rD2 __
      "eor        r2, " rD0 __
      "eor        r3, " rD4 __
      "eor        r4, " rD2 __
      "eor        r5, " rD4 __
      "eor        r6, " rD1 __
      "ror        r1, #2" __
      "ror        r2, #14" __
      "ror        r3, #25" __
      "ror        r4, #3" __
      "ror        r5, #12" __
      "ror        r6, #20" __
      "str        r1, [r0, #4* 20]" __
      "str        r2, [r0, #4* 14]" __
      "str        r3, [r0, #4* 22]" __
      "str        r4, [r0, #4* 9]" __
      "str        r5, [r0, #4* 6]" __
      "str        r6, [r0, #4* 1]" __

#undef rD0
#undef rD1
#undef rD2
#undef rD3
#undef rD4

// Chi. Load A[] in r6-r10; result in r1-r5.
      "ldm        r0, {r6-r10}" __
      "bic        r1, r8, r7" __
      "bic        r2, r9, r8" __
      "bic        r3, r10, r9" __
      "bic        r4, r6, r10" __
      "bic        r5, r7, r6" __
      "eors       r1, r6" __
      "eors       r2, r7" __
      "eor        r3, r8" __
      "eor        r4, r9" __
      "eor        r5, r10" __
      "stm        r0!, {r1-r5}" __

      "ldm        r0, {r6-r10}" __
      "bic        r1, r8, r7" __
      "bic        r2, r9, r8" __
      "bic        r3, r10, r9" __
      "bic        r4, r6, r10" __
      "bic        r5, r7, r6" __
      "eors       r1, r6" __
      "eors       r2, r7" __
      "eor        r3, r8" __
      "eor        r4, r9" __
      "eor        r5, r10" __
      "stm        r0!, {r1-r5}" __

      "ldm        r0, {r6-r10}" __
      "bic        r1, r8, r7" __
      "bic        r2, r9, r8" __
      "bic        r3, r10, r9" __
      "bic        r4, r6, r10" __
      "bic        r5, r7, r6" __
      "eors       r1, r6" __
      "eors       r2, r7" __
      "eor        r3, r8" __
      "eor        r4, r9" __
      "eor        r5, r10" __
      "stm        r0!, {r1-r5}" __

      "ldm        r0, {r6-r10}" __
      "bic        r1, r8, r7" __
      "bic        r2, r9, r8" __
      "bic        r3, r10, r9" __
      "bic        r4, r6, r10" __
      "bic        r5, r7, r6" __
      "eors       r1, r6" __
      "eors       r2, r7" __
      "eor        r3, r8" __
      "eor        r4, r9" __
      "eor        r5, r10" __
      "stm        r0!, {r1-r5}" __

      "ldm        r0, {r6-r10}" __
      "bic        r1, r8, r7" __
      "bic        r2, r9, r8" __
      "bic        r3, r10, r9" __
      "bic        r4, r6, r10" __
      "bic        r5, r7, r6" __
      "eors       r1, r6" __
      "eors       r2, r7" __
      "eor        r3, r8" __
      "eor        r4, r9" __
      "eor        r5, r10" __
      "stm        r0!, {r1-r5}" __
      "subs       r0, #100" __

// Iota.
      "ldr        r1, [r0, #0]" __
      "ldr        r2, [lr], #4" __
      "eors       r1, r2" __
      "str        r1, [r0, #0]" __
      "b          .L_round" __

// Total 282c per round.
   ".L_done:" __
      "pop        {r4-r11, pc}" __

      ".align     2" __
   ".L_rcs:" __
#if CONF_KF800_FULLR
      ".word 0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b" __
      ".word 0x80000001, 0x80008081, 0x00008009, 0x0000008a, 0x00000088" __
      ".word 0x80008009, 0x8000000a" __
#endif
      ".word 0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002" __
      ".word 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080" __
   ".L_rc_end:" __
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
 * Memory copy. 4-word batch.
 */
#ifdef __thumb__
void _alfn _naked wam_copy(void *d, const void *s, uint len)
{
   // clang-format off
   asm(
      ".syntax unified" __
      "push       {r4-r6, lr}" __
      "lsrs       r2, #2" __
#ifdef __thumb2__
      "b.w        2f" __
#else
      "b          2f" __
#endif
      "1:" __
      "ldm        r1!, {r3-r6}" __
      "stm        r0!, {r3-r6}" __
   "2:" __
      "subs       r2, #4" __
      "bpl        1b" __
      "adds       r2, #4" __
      // 0-3 words left to copy.
      "beq        10f" __
      "cmp        r2, #2" __
      "beq        12f" __
      "bhi        13f" __
      "ldr        r3, [r1]" __
      "str        r3, [r0]" __
      "pop        {r4-r6, pc}" __
   "12:" __
      "ldm        r1!, {r3-r4}" __
      "stm        r0!, {r3-r4}" __
      "pop        {r4-r6, pc}" __
   "13:" __
      "ldm        r1!, {r3-r5}" __
      "stm        r0!, {r3-r5}" __
   "10:" __
      "pop        {r4-r6, pc}" __
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
 * Memory fillers. 4-word batch.
 */
#ifdef __thumb__
void _alfn _naked wam_zero(void *w, uint len)
{
   // clang-format off
   asm(
      ".syntax    unified" __
#ifdef __thumb2__
      "mov.w      r2, #0" __
#else
      "movs       r2, #0" __
#endif
      ".thumb_func" __
      ".global wam_fill" __
   "wam_fill:" __
      "push       {r4, r5, lr}" __
      "mov        r3, r2" __
      "lsrs       r1, #2" __
      "mov        r4, r2" __
      "mov        r5, r3" __
      "b          2f" __
   "1:" __
      "stm        r0!, {r2-r5}" __
   "2:" __
      "subs       r1, #4" __
      "bpl        1b" __
      "adds       r1, #4" __
      // 0-3 words left.
      "beq        10f" __
      "cmp        r1, #2" __
      "beq        12f" __
      "bhi        13f" __
      "str        r2, [r0]" __
      "pop        {r4, r5, pc}" __
   "12:" __
      "stm        r0!, {r2, r3}" __
      "pop        {r4, r5, pc}" __
   "13:" __
      "stm        r0!, {r2-r4}" __
   "10:" __
      "pop        {r4, r5, pc}" __
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
 * Block swap. 4-word batch.
 */
#ifdef __thumb__
void _alfn _naked wam_swap(void *a, void *b, uint len)
{
   // clang-format off
   asm(
      ".syntax    unified" __
#ifdef __thumb2__
      "push       {r4-r8, lr}" __
#else
      "push       {r4-r6}" __
#endif
      "lsrs       r2, #2" __
      "b          2f" __
   "1:" __
#ifdef __thumb2__
      "ldm        r0, {r3-r6}" __
      "ldm        r1, {r7, r8, r12, lr}" __
      "stm        r0!, {r7, r8, r12, lr}" __
      "stm        r1!, {r3-r6}" __
#else
      "ldm        r0!, {r3, r4}" __
      "ldm        r1!, {r5, r6}" __
      "subs       r0, #8" __
      "subs       r1, #8" __
      "stm        r0!, {r5, r6}" __
      "stm        r1!, {r3, r4}" __
      "ldm        r0!, {r3, r4}" __
      "ldm        r1!, {r5, r6}" __
      "subs       r0, #8" __
      "subs       r1, #8" __
      "stm        r0!, {r5, r6}" __
      "stm        r1!, {r3, r4}" __
#endif
   "2:" __
      "subs       r2, #4" __
#ifdef __thumb2__
      "bpl.w      1b" __
#else
      "bpl        1b" __
#endif
      "adds       r2, #4" __
      "beq        10f" __
      // 1-3 words, loop.
   "3:" __
      "ldr        r3, [r0]" __
      "ldr        r4, [r1]" __
      "stm        r0!, {r4}" __
      "stm        r1!, {r3}" __
      "subs       r2, #1" __
      "bne        3b" __
   "10:" __
#ifdef __thumb2__
      "pop        {r4-r8, pc}" __
      : : :"r0","r1","r2","r3","r12","lr","cc","memory"
#else
      "pop        {r4-r6}" __
      "bx         lr" __
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
