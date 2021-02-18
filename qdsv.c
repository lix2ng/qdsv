/*
 * Digital Signature Verifier
 *
 * Based on qDSA signature scheme and Cortex-M0 code, by Joost Renes (1),
 * using the hyperelliptic Gaudry-Schost curve (2).
 *
 * Modifications:
 *  - C files are merged and cleaned up.
 *  - assembly files are put together and made EABI compliant.
 *  - add optimized assemblers for Cortex-M4 and Cortex-M3.
 *  - use Bob Jr. as the hash function (reduced round Keccak-f[800]).
 *  - use WAM for fast copy/zeroize/swap on small aligned memory blocks.
 *  - use variable-time Ladder swap in verifier-only compile (saves ~140Kc).
 *  - interfaces are changed for convenience.
 *
 * Limitations:
 *  - message size is fixed to 32 bytes.
 *  - signature, public key and message are required to be word-aligned.
 *
 * Current verifier performance [1f2i]:
 *    M0: 5080Kc (106ms on 48MHz M0), 6012B Flash, 752B stack.
 *    M3: 3633Kc (57ms on 64MHz M3),  5126B Flash, 732B stack.
 *    M4: 2912Kc (46ms on 64MHz M4),  5014B Flash, 724B stack.
 *
 * Ref: arm-none-eabi-gcc 7.3.1 20180622 (release). Numbers are obtained on
 * uVision simulator -- which doesn't consider slow Flash wait cycles nor
 * savings from code cache and code/data pipelining.
 *
 * 1. J. Renes, B. Smith: qDSA: Small and Secure Digital Signatures with Curve-
 *    based Diffie-Hellman Key Pairs.
 *    https://arxiv.org/abs/1709.03358
 *    https://joostrenes.nl/software/arm-g2.tar.gz
 * 2. P. Gaudry, E. Schost: Genus 2 point counting over prime fields.
 *    https://www.sciencedirect.com/science/article/pii/S0747717111001386
 */

#include "supp.h"
#include "qdsv.h"

/* Compile for verifier only or the full package. */
#ifndef CONF_QDSA_FULL
#define CONF_QDSA_FULL 0
#endif

/* Field element, 16B/4W. */
typedef union {
   uint8_t b[16];
   uint32_t v[4];
} _align4 fe1271;

/* Assembly routines for Cortex-M series. */
static void bigint_sqr(uint32_t *r, const uint32_t *x);
#ifdef __thumb2__
// Thumb-2 MUL is a label inside SQR assembler.
void bigint_mul(uint32_t *r, const uint32_t *x, const uint32_t *y);
#else
static void bigint_mul(uint32_t *r, const uint32_t *x, const uint32_t *y);
#endif
static void bigint_red(uint32_t *r, const uint32_t *a);
static void fe1271_mulconst(fe1271 *r, const fe1271 *x, uint16_t y);
static void fe1271_add(fe1271 *r, const fe1271 *x, const fe1271 *y);
static void fe1271_sub(fe1271 *r, const fe1271 *x, const fe1271 *y);
// Hdmrd can be made unary as well but it may not be beneficial.
static void fe1271_hdmrd(fe1271 *r, const fe1271 *x);
static void fe1271_neg(fe1271 *x);
static void fe1271_freeze(fe1271 *x);

#include "fe1271.inc"

/* -----------------------------------------------------------------------------
 * IMPORTANT: do not change the layout. The point structures may be reused and
 * their layouts are assumed.
 * -----------------------------------------------------------------------------
 */
/*
 * Point on Kummer surface, 64B/16W.
 */
typedef struct {
   fe1271 X;
   fe1271 Y;
   fe1271 Z;
   fe1271 T;
} _align4 kpoint;

/*
 * Compressed Kummer Point, 32B/8W.
 */
typedef union {
   uint8_t b[32];
   struct {
      fe1271 fe1;
      fe1271 fe2;
   };
} _align4 ckpoint;

static void fe1271_setzero(fe1271 *r)
{
   wam_zero(r, sizeof(fe1271));
}

static void fe1271_copy(fe1271 *r, const fe1271 *x)
{
   wam_copy(r, x, sizeof(fe1271));
}

/* Return "zeroness" of Fe: 0 if it's zero; 1 if it's not. */
static int fe1271_zeroness(fe1271 *r)
{
   fe1271 one;

   fe1271_setzero(&one);
   one.b[0] = 1;
   fe1271_add(&one, &one, r);
   fe1271_freeze(&one);
   one.b[0] ^= 1;
   uint t = one.v[0] | one.v[1] | one.v[2] | one.v[3];
   return !(t == 0);
}

static void fe1271_mul(fe1271 *r, const fe1271 *x, const fe1271 *y)
{
   uint32_t t[8];

   bigint_mul(t, x->v, y->v);
   bigint_red(r->v, t);
}

static void fe1271_square(fe1271 *r, const fe1271 *x)
{
   uint32_t t[8];

   bigint_sqr(t, x->v);
   bigint_red(r->v, t);
}

static void fe1271_powminhalf(fe1271 *r, const fe1271 *x)
{
   int i;
   fe1271 x2, x3, x6;

   // Total: 11 MUL, 125 SQR.
   fe1271_square(&x2, x);      // 2
   fe1271_mul(&x3, &x2, x);    // 3
   fe1271_square(&x6, &x3);    // 6
   fe1271_square(&x6, &x6);    // 12
   fe1271_mul(&x3, &x6, &x3);  // 2^4-1
   fe1271_square(&x6, &x3);    // 30
   fe1271_mul(&x6, &x6, x);    // 2^5-1
   fe1271_square(r, &x6);      // 2^6-2
   for (i = 0; i < 4; i++)
      fe1271_square(r, r);   // 2^10-2^5
   fe1271_mul(&x6, r, &x6);  // 2^10-1
   fe1271_square(r, &x6);    // 2^11-2
   for (i = 0; i < 9; i++)
      fe1271_square(r, r);   // 2^20-2^10
   fe1271_mul(&x6, r, &x6);  // 2^20-1
   fe1271_square(r, &x6);    // 2^21-2
   for (i = 0; i < 19; i++)
      fe1271_square(r, r);   // 2^40-2^20
   fe1271_mul(&x6, r, &x6);  // 2^40-1
   fe1271_square(r, &x6);    // 2^41-2
   for (i = 0; i < 39; i++)
      fe1271_square(r, r);  // 2^80-2^40
   fe1271_mul(r, r, &x6);   // 2^80-1
   for (i = 0; i < 40; i++)
      fe1271_square(r, r);  // 2^120-2^40
   fe1271_mul(r, r, &x6);   // 2^120-1
   for (i = 0; i < 4; i++)
      fe1271_square(r, r);   // 2^124-2^4
   fe1271_mul(r, r, &x3);    // 2^124-1
   fe1271_square(r, r);      // 2^125-2
   fe1271_mul(&x6, r, &x2);  // 2^125
   fe1271_square(&x6, &x6);  // 2^126
   fe1271_mul(r, r, &x6);
}

static void fe1271_invert(fe1271 *r, const fe1271 *x)
{
   fe1271 t;

   fe1271_square(r, x);
   fe1271_powminhalf(r, r);
   fe1271_mul(&t, r, x);
   fe1271_mul(r, r, &t);
}

static void set_const(fe1271 *r, uint16_t c)
{
   fe1271_setzero(r);
   r->v[0] = c;
}

static void fe1271_sum(
   fe1271 *r, fe1271 *t, uint16_t c1, uint16_t c2, uint16_t c3, uint16_t c4)
{
   set_const(t, c1);
   fe1271_mulconst(t, t, c2);
   set_const(r, c3);
   fe1271_mulconst(r, r, c4);
   fe1271_add(r, r, t);
}

/*
 * Return the square-root of delta, with sign of sigma, if it exists.
 *
 * Input:
 *      delta: Element of fe1271
 *      sigma: Either 0 or 1
 * Output:
 *      0 if delta has a sqrt, 1 otherwise
 *      R: sqrt(delta), if it exists
 */
static int fe1271_has_sqrt(
   fe1271 *R, fe1271 *t, const fe1271 *delta, uint8_t sigma)
{
   fe1271_powminhalf(R, delta);
   fe1271_mul(R, R, delta);
   fe1271_square(t, R);
   fe1271_sub(t, t, delta);
   if (fe1271_zeroness(t) != 0) {
      return 1;
   }
   fe1271_freeze(R);
   if ((R->b[0] & 1) ^ sigma) {
      fe1271_neg(R);
   }
   return 0;
}

/*
 * 512+=256 large integer addition, possibly starting at an offset of x.
 * Changed from r=x+y to in-place addition x+=y. 48 invocations.
 */
static void large_add(uint32_t *x, const uint32_t *y, uint os)
{
   uint64_t t0, t1;
   uint32_t carry = 0;

   for (int i = 0; i < 8; i++) {
      t0 = (uint64_t)x[i + os];
      t1 = (uint64_t)y[i];
      t0 += carry;
      t0 += t1;
      carry = (t0 >> 32) & 1;
      x[i + os] = (uint32_t)t0;
   }

   for (int i = 8 + os; i < 16; i++) {
      t0 = (uint64_t)x[i];
      t0 += carry;
      carry = (t0 >> 32) & 1;
      x[i] = (uint32_t)t0;
   }
}

/* 256x256 bit integer multiplication. 12 invocations. */
static void large_mul(uint32_t *r, const uint32_t *x, const uint32_t *y)
{
   uint32_t temp[8];
   // Clear the upper 256 bit of r.
   wam_zero(&r[8], 8 * 4);
   bigint_mul(r, x, y);
   bigint_mul(temp, x, y + 4);
   large_add(r, temp, 4);
   bigint_mul(temp, x + 4, y);
   large_add(r, temp, 4);
   bigint_mul(temp, x + 4, y + 4);
   large_add(r, temp, 8);
}

/* 512 -> 250-bit reduction modulo N. 2 invocations. */
static void large_red(uint32_t *res, const uint32_t *x)
{
   static const uint32_t L[8] = { 0x840C05BD, 0x47730B4B, 0xF9A154FF,
      0xD2C27FC9, 0x20C75294, 0x334D698, 0x0, 0x0 };
   static const uint32_t L6[8] = { 0x3016F40, 0xDCC2D2E1, 0x68553FD1,
      0xB09FF27E, 0x31D4A534, 0xCD35A608, 0x0, 0x0 };

   uint32_t r[16], temp[16];

   wam_copy(r, x, 16 * 4);
   for (int i = 0; i < 4; i++) {
      large_mul(temp, r + 8, L6);
      wam_copy(&r[8], &temp[8], 8 * 4);
      large_add(r, temp, 0);
   }

   r[8] = (r[8] << 6) | ((r[7] & 0xfc000000) >> 26);
   r[7] &= 0x03ffffff;
   large_mul(temp, r + 8, L);
   wam_copy(&r[8], &temp[8], 8 * 4);
   large_add(r, temp, 0);
   r[8] = (r[7] & 0x04000000) >> 26;
   r[7] &= 0x03ffffff;
   large_mul(temp, r + 8, L);
   r[8] = 0;
   large_add(r, temp, 0);
   wam_copy(res, r, 8 * 4);
}

/*
 * Pairwise multiply two tuples, where the second tuple has small values.
 *
 * Input:
 *      xq: Four fe1271 elements (X,Y,Z,T)
 *      cons: Four small (16 bits) fe1271 elements
 * Output:
 *      xq: (a*X, b*Y, c*Z, d*T)
 */
static void mul4_const(kpoint *xq, const uint16_t cons[])
{
   fe1271_mulconst(&xq->X, &xq->X, cons[0]);
   fe1271_mulconst(&xq->Y, &xq->Y, cons[1]);
   fe1271_mulconst(&xq->Z, &xq->Z, cons[2]);
   fe1271_mulconst(&xq->T, &xq->T, cons[3]);
}

/*
 * Pairwise multiply two tuples.
 *
 * Input:
 *      xq: Four fe1271 elements (X1,Y1,Z1,T1)
 *      xp: Four fe1271 elements (X2,Y2,Z2,T2)
 * Output:
 *      xq: (X1*X2, Y1*Y2, Z1*Z2, T1*T2)
 */
static void mul4(kpoint *xq, const kpoint *xp)
{
   fe1271_mul(&xq->X, &xq->X, &xp->X);
   fe1271_mul(&xq->Y, &xq->Y, &xp->Y);
   fe1271_mul(&xq->Z, &xq->Z, &xp->Z);
   fe1271_mul(&xq->T, &xq->T, &xp->T);
}

/*
 * Pairwise square a tuple.
 *
 * Input:
 *      xp: Four fe1271 elements (X,Y,Z,T)
 * Output:
 *      xq: (X^2,Y^2,Z^2,T^2)
 */
static void sqr4(kpoint *xq, const kpoint *xp)
{
   fe1271_square(&xq->X, &xp->X);
   fe1271_square(&xq->Y, &xp->Y);
   fe1271_square(&xq->Z, &xp->Z);
   fe1271_square(&xq->T, &xp->T);
}

static const uint16_t ehat[4] = {  //
   0x341, 0x9C3, 0x651, 0x231
};

/*
 * Simultaneous xDBL and xADD operation on the Kummer. To deal with negated
 * constants, it assume the first coordinates of xp, xq are negated. The first
 * output coordinate of xp will be negated.
 *
 * Input:
 *      xp: Uncompressed Kummer point
 *      xq: Uncompressed Kummer point
 *      xd: Wrapped difference Kummer point (xp-xq)
 * Output:
 *      xp: Uncompressed Kummer point 2*xp
 *      xq: Uncompressed Kummer point xp+xq
 */
static void xDBLADD(kpoint *xp, kpoint *xq, const kpoint *xd)
{
   static const uint16_t e_cons[4] = { //
      0x72, 0x39, 0x42, 0x1a2
   };

   fe1271_hdmrd(&xq->X, &xq->X);
   fe1271_hdmrd(&xp->X, &xp->X);
   mul4(xq, xp);
   sqr4(xp, xp);
   mul4_const(xq, ehat);
   mul4_const(xp, ehat);
   fe1271_hdmrd(&xq->X, &xq->X);
   fe1271_hdmrd(&xp->X, &xp->X);
   sqr4(xq, xq);
   sqr4(xp, xp);
   fe1271_mul(&xq->Y, &xq->Y, &xd->Y);
   fe1271_mul(&xq->Z, &xq->Z, &xd->Z);
   fe1271_mul(&xq->T, &xq->T, &xd->T);
   mul4_const(xp, e_cons);
}

/*
 * Unwrap a wrapped Kummer point.
 *
 * Input:
 *      xpw: Wrapped Kummer point (X/Y,X/Z,X/T)
 * Output:
 *      xp: Uncompressed Kummer point (X:Y:Z:T)
 */
static void xUNWRAP(kpoint *xp, const kpoint *xpw)
{
   fe1271_mul(&xp->T, &xpw->Y, &xpw->Z);
   fe1271_mul(&xp->Z, &xpw->Y, &xpw->T);
   fe1271_mul(&xp->Y, &xpw->Z, &xpw->T);
   fe1271_mul(&xp->X, &xp->T, &xpw->T);
}

/*
 * Wrap an uncompressed Kummer point.
 *
 * Input:
 *      xp: Uncompressed Kummer point (X:Y:Z:T)
 * Output:
 *      xpw: Wrapped Kummer point (X/Y,X/Z,X/T)
 */
static void xWRAP(kpoint *xpw, const kpoint *xp)
{
   fe1271 w0, w1, w2, w3;

   fe1271_mul(&w0, &xp->Y, &xp->Z);
   fe1271_mul(&w1, &w0, &xp->T);
   fe1271_invert(&w2, &w1);
   fe1271_mul(&w2, &w2, &xp->X);
   fe1271_mul(&w3, &w2, &xp->T);
   fe1271_mul(&xpw->Y, &w3, &xp->Z);
   fe1271_mul(&xpw->Z, &w3, &xp->Y);
   fe1271_mul(&xpw->T, &w0, &w2);
}

static const uint8_t mu_1 = 0x0b;
static const uint8_t mu_2 = 0x16;
static const uint8_t mu_3 = 0x13;
static const uint8_t mu_4 = 0x03;

#if CONF_QDSA_FULL
/* Conditional kpoint swap for constant-time Ladder. */
static void ct_swap(kpoint *x, kpoint *y, int b)
{
   uint32_t *X = (uint32_t *)x;
   uint32_t *Y = (uint32_t *)y;

   b = -b;
   for (int i = 0; i < sizeof(kpoint) / 4; i++) {
      uint32_t t = X[i] ^ Y[i];
      t &= b;
      X[i] ^= t;
      Y[i] ^= t;
   }
}
#endif

/*
 * Montgomery ladder computing n*xq via repeated differential additions and
 * constant-time conditional swaps.
 *
 * NB: verifier-only compile will swap only when necessary, i.e. not constant-
 * time anymore.
 *
 * Input:
 *      xq: Uncompressed Kummer point
 *      xd: Wrapped Kummer point xq
 *      n: Scalar
 *      l: Maximum scalar bit-length (fixed, =250)
 * Output:
 *      xp: n*xq
 *      xq: (n+1)*xq
 */
static void ladder_250(
   kpoint *xp, kpoint *xq, const kpoint *xd, const uint8_t *n)
{
   int swap, bit, prevbit = 0;

   wam_zero(xp, sizeof(kpoint));
   xp->X.v[0] = mu_1;
   xp->Y.v[0] = mu_2;
   xp->Z.v[0] = mu_3;
   xp->T.v[0] = mu_4;

   for (int i = 250; i >= 0; i--) {
      bit = (n[i >> 3] >> (i & 0x07)) & 1;
      swap = bit ^ prevbit;
      prevbit = bit;
      fe1271_neg(&xq->X);

#if CONF_QDSA_FULL
      ct_swap(xp, xq, swap);
#else
      if (swap) wam_swap(xp, xq, sizeof(kpoint));
#endif
      xDBLADD(xp, xq, xd);
   }

   fe1271_neg(&xp->X);

#if CONF_QDSA_FULL
   ct_swap(xp, xq, bit);
#else
   if (bit) wam_swap(xp, xq, sizeof(kpoint));
#endif
}

static void ladder_base_250(kpoint *xp, const uint8_t *n)
{
   // Wrapped base point.
   static const kpoint bpw = {
      .Y = { .v = { 0x4e931a48, 0xaeb351a6, 0x2049c2e7, 0x1be0c3dc } },
      .Z = { .v = { 0xe07e36df, 0x64659818, 0x8eaba630, 0x23b416cd } },
      .T = { .v = { 0x7215441e, 0xc7ae3d05, 0x4447a24d, 0x5db35c38 } }
   };

   kpoint xq;

   xUNWRAP(&xq, &bpw);
   ladder_250(xp, &xq, &bpw, n);
}

static const uint16_t q0 = 0xDF7;
static const uint16_t q1 = 0x2599;
static const uint16_t q2 = 0x1211;
static const uint16_t q3 = 0x2FE3;
static const uint16_t q4 = 0x2C0B;
static const uint16_t q5 = 0x1D33;
static const uint16_t q6 = 0x1779;
static const uint16_t q7 = 0xABD7;

/*
 * Compute K_2(l1,l2,tau).
 *
 * Input:
 *      l1: Element of fe1271
 *      l2: Element of fe1271
 *      tau: Either 0 or 1
 * Output:
 *      r: K_2(l1,l2,tau)
 */
static void get_k2(
   fe1271 *r, fe1271 *t, const fe1271 *l1, const fe1271 *l2, uint tau)
{
   fe1271_mulconst(r, l1, q2);
   fe1271_mul(r, l2, r);
   if (tau) {
      fe1271_mulconst(t, l1, q0);
      fe1271_add(r, r, t);
      fe1271_mulconst(t, l2, q1);
      fe1271_sub(r, r, t);
   }
   fe1271_mulconst(r, r, q3);
   fe1271_add(r, r, r);
   fe1271_mulconst(t, l1, q5);
   fe1271_square(t, t);
   fe1271_sub(r, t, r);
   fe1271_mulconst(t, l2, q3);
   fe1271_square(t, t);
   fe1271_add(r, t, r);
   if (tau) {
      set_const(t, q4);
      fe1271_square(t, t);
      fe1271_add(r, t, r);
   }
}

/*
 * Compute K_3(l1,l2,tau).
 *
 * Input:
 *      l1: Element of fe1271
 *      l2: Element of fe1271
 *      tau: Either 0 or 1
 * Output:
 *      r: K_3(l1,l2,tau)
 */
static void get_k3(fe1271 *r, fe1271 *t0, fe1271 *t1, const fe1271 *l1,
   const fe1271 *l2, uint tau)
{
   fe1271_square(r, l1);
   fe1271_square(t0, l2);

   if (tau) {
      set_const(t1, 1);
      fe1271_add(r, r, t1);
      fe1271_add(t0, t0, t1);
      fe1271_add(t1, r, t0);
   }
   fe1271_mul(r, r, l2);
   fe1271_mulconst(r, r, q0);
   fe1271_mul(t0, t0, l1);
   fe1271_mulconst(t0, t0, q1);
   fe1271_sub(r, r, t0);
   if (tau) {
      set_const(t0, 1);
      fe1271_sub(t1, t1, t0);
      fe1271_sub(t1, t1, t0);
      fe1271_mulconst(t1, t1, q2);
      fe1271_add(r, r, t1);
   }
   fe1271_mulconst(r, r, q3);
   if (tau) {
      fe1271_mul(t0, l1, l2);
      fe1271_mulconst(t0, t0, q6);
      fe1271_mulconst(t0, t0, q7);
      fe1271_sub(r, r, t0);
   }
}

/*
 * Compute K_4(l1,l2,tau).
 *
 * Input:
 *      l1: Element of fe1271
 *      l2: Element of fe1271
 *      tau: Either 0 or 1
 * Output:
 *      r: K_4(l1,l2,tau)
 */
static void get_k4(
   fe1271 *r, fe1271 *t, const fe1271 *l1, const fe1271 *l2, uint tau)
{
   if (tau) {
      fe1271_mulconst(t, l2, q0);
      fe1271_mulconst(r, l1, q1);
      fe1271_sub(t, t, r);
      set_const(r, q2);
      fe1271_add(t, t, r);
      fe1271_mul(t, t, l1);
      fe1271_mul(t, t, l2);
      fe1271_mulconst(t, t, q3);
      fe1271_add(t, t, t);
      fe1271_mulconst(r, l1, q3);
      fe1271_square(r, r);
      fe1271_sub(t, r, t);
      fe1271_mulconst(r, l2, q5);
      fe1271_square(r, r);
      fe1271_add(t, r, t);
   }
   fe1271_mulconst(r, l1, q4);
   fe1271_mul(r, r, l2);
   fe1271_square(r, r);
   if (tau) {
      fe1271_add(r, r, t);
   }
}

static void T_inv_row(fe1271 *r, const fe1271 *X1, const fe1271 *X2,
   const fe1271 *X3, const fe1271 *X4)
{
   fe1271 t;

   fe1271_add(r, X2, X2);
   fe1271_sub(r, r, X1);
   fe1271_mulconst(r, r, mu_1);
   fe1271_mulconst(&t, X3, mu_3);
   fe1271_add(r, r, &t);
   fe1271_mulconst(&t, X4, mu_4);
   fe1271_add(r, r, &t);
}

/*
 * Matrix multiplication by T_inv = ( mu_{} ).
 *
 * Input:
 *      (X1,X2,X3,X4): Four fe1271 elements
 * Output:
 *      r  : X1*mu_1+X2*mu_2+X3*mu_3+X4*mu_4
 *      r+1: X1*mu_2+X2*mu_1+X3*mu_4+X4*mu_3
 *      r+2: X1*mu_3+X2*mu_4+X3*mu_1+X4*mu_2
 *      r+3: X1*mu_4+X2*mu_3+X3*mu_2+X4*mu_1
 */
static void T_inv(kpoint *r, const kpoint *x)
{
   T_inv_row(&r->X, &x->T, &x->Z, &x->Y, &x->X);
   T_inv_row(&r->Y, &x->Z, &x->T, &x->X, &x->Y);
   T_inv_row(&r->Z, &x->Y, &x->X, &x->T, &x->Z);
   T_inv_row(&r->T, &x->X, &x->Y, &x->Z, &x->T);
}

/*
 * Decompress two field elements and two sign bits to a Kummer point.
 * If valid decompression is possible, return 0. Otherwise, return 1.
 *
 * Input:
 *      x: Compressed Kummer point (l1,l2,tau,sigma)
 * Output:
 *      r: Uncompressed Kummer point
 */
static int decompress(kpoint *r, kpoint *t, const ckpoint *x)
{
   uint tau, sigma;

   fe1271_copy(&r->X, &x->fe1);
   fe1271_copy(&r->Y, &x->fe2);

   tau = (r->X.b[15] & 0x80) >> 7;
   sigma = (r->Y.b[15] & 0x80) >> 7;
   r->X.b[15] &= 0x7f;
   r->Y.b[15] &= 0x7f;

   get_k2(&t->Y, &r->Z, &r->X, &r->Y, tau);
   get_k3(&t->Z, &r->Z, &r->T, &r->X, &r->Y, tau);
   get_k4(&t->T, &r->Z, &r->X, &r->Y, tau);

   if (fe1271_zeroness(&t->Y) == 0)  // k2 = 0
   {
      fe1271_freeze(&t->Z);
      if (fe1271_zeroness(&t->Z) == 0)  // k3 = 0
      {
         if (fe1271_zeroness(&r->X) | fe1271_zeroness(&r->Y) | tau | sigma) {
            return 1;
         } else {
            wam_zero(t, sizeof(kpoint));
            t->T.b[0] = 1;
         }
      } else if (sigma ^ t->Z.b[0]) {
         fe1271_mul(&t->X, &t->Z, &r->X);
         fe1271_add(&t->X, &t->X, &t->X);
         fe1271_mul(&t->Y, &t->Z, &r->Y);
         fe1271_add(&t->Y, &t->Y, &t->Y);
         if (tau) {
            fe1271_add(&t->Z, &t->Z, &t->Z);
         } else {
            fe1271_setzero(&t->Z);
         }
      } else {
         return 1;
      }
   } else {
      fe1271_square(&r->Z, &t->Z);
      fe1271_mul(&r->T, &t->Y, &t->T);
      fe1271_sub(&r->Z, &r->Z, &r->T);
      if (fe1271_has_sqrt(&r->T, &t->X, &r->Z, sigma)) {
         return 1;
      }
      fe1271_add(&t->T, &t->Z, &r->T);
      if (tau) {
         fe1271_copy(&t->Z, &t->Y);
      } else {
         fe1271_setzero(&t->Z);
      }
      fe1271_mul(&t->X, &t->Y, &r->X);
      fe1271_mul(&t->Y, &t->Y, &r->Y);
   }
   T_inv(r, t);
   return 0;
}

static const uint16_t muhat[4] = {  //
   0x0021, 0x000B, 0x0011, 0x0031
};

/*
 * Compute the Hadamard transform on four fe1271 elements.
 *
 * Input:
 *      (x,x+1,x+2,x+3): Four fe1271 elements
 * Output:
 *      r  : x + (x+1) + (x+2) + (x+3)
 *      r+1: x + (x+1) - (x+2) - (x+3)
 *      r+2: x - (x+1) + (x+2) - (x+3)
 *      r+3: x - (x+1) - (x+2) + (x+3)
 */
static void fe1271_H(fe1271 *x)
{
   fe1271_neg(x);
   fe1271_hdmrd(x, x);
   fe1271_neg(x + 3);
}

/*
 * Compute the dot product of two tuples.
 *
 * Input:
 *      (x0,x1,x2,x3): Four fe1271 elements
 *      (y0,y1,y2,y3): Four fe1271 elements
 * Output:
 *      r: x0*y0 + x1*y1 + x2*y2 + x3*y3
 */
static void dot(fe1271 *r, const fe1271 *x0, const fe1271 *x1, const fe1271 *x2,
   const fe1271 *x3, const fe1271 *y0, const fe1271 *y1, const fe1271 *y2,
   const fe1271 *y3)
{
   fe1271 t;

   fe1271_mul(r, x0, y0);
   fe1271_mul(&t, x1, y1);
   fe1271_add(r, r, &t);
   fe1271_mul(&t, x2, y2);
   fe1271_add(r, r, &t);
   fe1271_mul(&t, x3, y3);
   fe1271_add(r, r, &t);
}

/*
 * Compute the dot product of two tuples, where the second tuple has small
 * values and some are negated.
 *
 * Input:
 *      (x0,x1,x2,x3): Four fe1271 elements
 *      (k1,k2,k3,k4): Four small (< 16 bits) fe1271 elements
 * Output:
 *      r: x0*k1 - x1*k2 - x2*k3 + x3*k4
 */
static void dot_const(fe1271 *r, const fe1271 *x0, const fe1271 *x1,
   const fe1271 *x2, const fe1271 *x3)
{
   static const uint16_t k1 = 0x1259;
   static const uint16_t k2 = 0x173F;
   static const uint16_t k3 = 0x1679;
   static const uint16_t k4 = 0x07C7;

   fe1271 t;

   fe1271_mulconst(r, x0, k1);
   fe1271_mulconst(&t, x1, k2);
   fe1271_sub(r, r, &t);
   fe1271_mulconst(&t, x2, k3);
   fe1271_sub(r, r, &t);
   fe1271_mulconst(&t, x3, k4);
   fe1271_add(r, r, &t);
}

/*
 * Four quadratic forms B_{ii} on the Kummer, where 1 <= i <= 4.
 *
 * Input:
 *      sP: Uncompressed point on the Kummer
 *      hQ: Uncompressed point on the Kummer
 * Output:
 *      r: ( B_{11}, B_{22}, B_{33}, B_{44} )
 */
static void bii_values(
   kpoint *r, kpoint *t0, kpoint *t1, const kpoint *sP, const kpoint *hQ)
{
   sqr4(t0, sP);
   sqr4(r, hQ);
   mul4_const(t0, ehat);
   mul4_const(r, ehat);
   fe1271_neg(&t0->X);
   fe1271_neg(&r->X);
   dot(&t1->X, &t0->X, &t0->Y, &t0->Z, &t0->T, &r->X, &r->Y, &r->Z, &r->T);
   dot(&t1->Y, &t0->X, &t0->Y, &t0->Z, &t0->T, &r->Y, &r->X, &r->T, &r->Z);
   dot(&t1->Z, &t0->X, &t0->Z, &t0->Y, &t0->T, &r->Z, &r->X, &r->T, &r->Y);
   dot(&t1->T, &t0->X, &t0->T, &t0->Y, &t0->Z, &r->T, &r->X, &r->Z, &r->Y);
   dot_const(&r->X, &t1->X, &t1->Y, &t1->Z, &t1->T);
   dot_const(&r->Y, &t1->Y, &t1->X, &t1->T, &t1->Z);
   dot_const(&r->Z, &t1->Z, &t1->T, &t1->X, &t1->Y);
   dot_const(&r->T, &t1->T, &t1->Z, &t1->Y, &t1->X);
   mul4_const(r, muhat);
   fe1271_neg(&r->X);
}

/*
 * Quadratic form B_{ij} on the Kummer, where (P1,P2,P3,P4), (Q1,Q2,Q3,Q4) are
 * some permutation of the coordinates of two Kummer points P and Q, and
 * (c1,c2,c3,c4) is a permutation of curve constants depending of the choice of
 * {i,j}.
 *
 * Input:
 *      (P1,P2,P3,P4): Permutation of coordinates of P
 *      (Q1,Q2,Q3,Q4): Permutation of coordinates of Q
 *      (c1,c2,c3,c4): Permutation of curve constants
 * Output:
 *      r: B_{ij}
 */
static void bij_value(fe1271 *r, kpoint *t, const fe1271 *P1, const fe1271 *P2,
   const fe1271 *P3, const fe1271 *P4, const fe1271 *Q1, const fe1271 *Q2,
   const fe1271 *Q3, const fe1271 *Q4, uint16_t c1, uint16_t c2, uint16_t c3,
   uint16_t c4)
{
   fe1271_mul(r, P1, P2);
   fe1271_mul(&t->X, Q1, Q2);
   fe1271_mul(&t->Y, P3, P4);
   fe1271_sub(r, r, &t->Y);
   fe1271_mul(&t->Z, Q3, Q4);
   fe1271_sub(&t->X, &t->X, &t->Z);
   fe1271_mul(r, r, &t->X);
   fe1271_mul(&t->X, &t->Y, &t->Z);
   fe1271_mulconst(r, r, c3);
   fe1271_mulconst(r, r, c4);
   fe1271_sum(&t->Y, &t->Z, c3, c4, c1, c2);
   fe1271_mul(&t->X, &t->X, &t->Y);
   fe1271_sub(r, &t->X, r);
   fe1271_mulconst(r, r, c1);
   fe1271_mulconst(r, r, c2);
   fe1271_sum(&t->Y, &t->Z, c2, c4, c1, c3);
   fe1271_mul(r, r, &t->Y);
   fe1271_sum(&t->Y, &t->Z, c2, c3, c1, c4);
   fe1271_mul(r, r, &t->Y);
}

/*
 * Verify whether  BjjR1^2 - 2*C*BijR1R2 + BiiR2^2 = 0.
 *
 * Input:
 *      Bij: Biquadratic form Bij
 *      Bjj: Biquadratic form Bjj
 *      Bii: Biquadratic form Bii
 *      R1: Coordinate of Kummer point R
 *      R2: Coordinate of Kummer point R
 * Output:
 *      0 if BjjR1^2 - 2*C*BijR1R2 + BiiR2^2 = 0,
 *      1 otherwise
 */
static int quad(fe1271 *Bij, kpoint *t, const fe1271 *Bjj, const fe1271 *Bii,
   const fe1271 *R1, const fe1271 *R2)
{
   static const fe1271 C = { //
      .b = { 0x43, 0xA8, 0xDD, 0xCD, 0xD8, 0xE3, 0xF7, 0x46, 0xDD, 0xA2, 0x20,
         0xA3, 0xEF, 0x0E, 0xF5, 0x40 }
   };

   fe1271_square(&t->X, R1);
   fe1271_mul(&t->X, Bjj, &t->X);
   fe1271_mul(&t->Y, R1, R2);
   fe1271_mul(&t->Y, Bij, &t->Y);
   fe1271_mul(&t->Y, &C, &t->Y);
   fe1271_add(&t->Y, &t->Y, &t->Y);
   fe1271_sub(&t->X, &t->X, &t->Y);
   fe1271_square(&t->Y, R2);
   fe1271_mul(&t->Y, Bii, &t->Y);
   fe1271_add(&t->X, &t->X, &t->Y);
   return fe1271_zeroness(&t->X);
}

/*
 * Verify whether R = ± (sP ± hQ) on the Kummer.
 *
 * Input:
 *      sP: Uncompressed point on the Kummer
 *      hQ: Uncompressed point on the Kummer
 *      xr: Compression of Kummer point R
 * Output:
 *      0 if R = ± (sP ± hQ), 1 otherwise
 */
static int check(kpoint *sP, kpoint *hQ, kpoint *R, kpoint *t, ckpoint *xr)
{
   kpoint Bii;
   fe1271 Bij;
   int v = 0;

   fe1271_H(&sP->X);
   fe1271_H(&hQ->X);
   bii_values(&Bii, t, R, sP, hQ);
   if (decompress(R, t, xr)) {
      return 1;
   }
   fe1271_H(&R->X);
   // B12
   bij_value(&Bij, t, &sP->X, &sP->Y, &sP->Z, &sP->T, &hQ->X, &hQ->Y, &hQ->Z,
      &hQ->T, muhat[0], muhat[1], muhat[2], muhat[3]);
   v |= quad(&Bij, t, &Bii.Y, &Bii.X, &R->X, &R->Y);
   // B13
   bij_value(&Bij, t, &sP->X, &sP->Z, &sP->Y, &sP->T, &hQ->X, &hQ->Z, &hQ->Y,
      &hQ->T, muhat[0], muhat[2], muhat[1], muhat[3]);
   v |= quad(&Bij, t, &Bii.Z, &Bii.X, &R->X, &R->Z);
   // B14
   bij_value(&Bij, t, &sP->X, &sP->T, &sP->Y, &sP->Z, &hQ->X, &hQ->T, &hQ->Y,
      &hQ->Z, muhat[0], muhat[3], muhat[1], muhat[2]);
   v |= quad(&Bij, t, &Bii.T, &Bii.X, &R->X, &R->T);
   // B23
   bij_value(&Bij, t, &sP->Y, &sP->Z, &sP->X, &sP->T, &hQ->Y, &hQ->Z, &hQ->X,
      &hQ->T, muhat[1], muhat[2], muhat[0], muhat[3]);
   fe1271_neg(&Bij);
   v |= quad(&Bij, t, &Bii.Z, &Bii.Y, &R->Y, &R->Z);
   // B24
   bij_value(&Bij, t, &sP->Y, &sP->T, &sP->X, &sP->Z, &hQ->Y, &hQ->T, &hQ->X,
      &hQ->Z, muhat[1], muhat[3], muhat[0], muhat[2]);
   fe1271_neg(&Bij);
   v |= quad(&Bij, t, &Bii.T, &Bii.Y, &R->Y, &R->T);
   // B34
   bij_value(&Bij, t, &sP->Z, &sP->T, &sP->X, &sP->Y, &hQ->Z, &hQ->T, &hQ->X,
      &hQ->Y, muhat[2], muhat[3], muhat[0], muhat[1]);
   fe1271_neg(&Bij);
   v |= quad(&Bij, t, &Bii.T, &Bii.Z, &R->Z, &R->T);
   return v;
}

static void scalar_get_hrqm(
   fe1271 *z, const uint8_t *r, const uint8_t *q, const uint8_t *m)
{
   bobjr_ctx ctx;
   bobjr_init(&ctx);
   bobjr_absorb_wa(&ctx, r, 32);  // R, 1st half of sig.
   bobjr_absorb_wa(&ctx, q, 32);  // Q, the public key.
   bobjr_absorb_wa(&ctx, m, 32);  // M, the message.
   bobjr_finish_wa(&ctx);         // 64B H(R||Q||M) ready in state.
   large_red(z->v, (uint32_t *)ctx.state);
}

static void scalar_get32(uint32_t *r, const uint8_t *x)
{
   uint32_t t[16];
   wam_copy(t, x, 32);
   wam_zero(&t[8], 32);
   large_red(r, t);
}

/* -----------------------------------------------------------------------------
 * Verify correctness of a signature with respect to a public key.
 * Return 0 if correct, 1 if incorrect.
 *
 * Input:
 *      sig (64 bytes): Signature
 *      pkey (32 bytes): Public key
 *      msg (32 bytes): Message, 32B fixed size
 * Output:
 *      0 if correct, 1 if incorrect
 */
int qdsa_verify(
   const uint8_t sig[64], const uint8_t pk[32], const uint8_t msg[32])
{
   kpoint sP, hQ, R, pxw;

   if (decompress(&sP, &hQ, (const ckpoint *)pk)) {
      return 1;
   }

   scalar_get32(R.X.v, sig + 32);        // 2nd half sig: s in R.X, R.Y.
   scalar_get_hrqm(&R.Z, sig, pk, msg);  // h = H(R||Q||M) in R.Z, R.T.

   xWRAP(&pxw, &sP);
   ladder_250(&hQ, &sP, &pxw, R.Z.b);  // [h]Q
   ladder_base_250(&sP, R.X.b);        // [s]P
   return check(&sP, &hQ, &R, &pxw, (ckpoint *)sig);
}

#if CONF_QDSA_FULL

static void large_neg(uint32_t *r, const uint32_t *x)
{
   static const uint32_t N[8] = { 0x7BF3FA43, 0xB88CF4B4, 0x65EAB00, 0x2D3D8036,
      0xDF38AD6B, 0xFCCB2967, 0xFFFFFFFF, 0x3FFFFFF };
   uint64_t t0, t1;
   uint32_t carry = 0;
   for (int i = 0; i < 8; i++) {
      t0 = (uint64_t)N[i];
      t1 = (uint64_t)x[i];
      t1 += carry;
      t0 -= t1;
      carry = (t0 >> 32) & 1;
      r[i] = (uint32_t)t0;
   }
}

static void scalar_ops(
   uint32_t *s, const ckpoint *r, const uint32_t *h, const uint32_t *d)
{
   uint32_t t[16];

   large_mul(t, h, d);
   large_red(s, t);
   wam_zero(&t[8], 8 * 4);
   large_neg(t, s);
   large_add(t, r->fe1.v, 0);
   large_red(s, t);
}

static void T_row(fe1271 *r, const fe1271 *X1, const fe1271 *X2,
   const fe1271 *X3, const fe1271 *X4)
{
   static const uint16_t khat_1 = 0x3C1;
   static const uint16_t khat_2 = 0x80;
   static const uint16_t khat_3 = 0x239;
   static const uint16_t khat_4 = 0x449;

   fe1271 t;

   fe1271_mulconst(r, X2, khat_2);
   fe1271_mulconst(&t, X3, khat_3);
   fe1271_add(r, r, &t);
   fe1271_mulconst(&t, X4, khat_4);
   fe1271_add(r, r, &t);
   fe1271_mulconst(&t, X1, khat_1);
   fe1271_sub(r, r, &t);
}

/*
 * Matrix multiplication by T = ( khat_{} )
 *
 * Input:
 *      (X1,X2,X3,X4): Four fe1271 elements
 * Output:
 *      r  : X1*khat_4+X2*khat_3+X3*khat_2+X4*khat_1
 *      r+1: X1*khat_3+X2*khat_4+X3*khat_1+X4*khat_2
 *      r+2: X1*khat_2+X2*khat_1+X3*khat_4+X4*khat_3
 *      r+3: X1*khat_1+X2*khat_2+X3*khat_3+X4*khat_4
 */
static void T(kpoint *r, const kpoint *x)
{
   T_row(&r->X, &x->T, &x->Z, &x->Y, &x->X);
   T_row(&r->Y, &x->Z, &x->T, &x->X, &x->Y);
   T_row(&r->Z, &x->Y, &x->X, &x->T, &x->Z);
   T_row(&r->T, &x->X, &x->Y, &x->Z, &x->T);
}

/*
 * Compress a Kummer point to two field elements, and two sign bits.
 *
 * Input:
 *      x: Uncompressed Kummer point
 * Output:
 *      l1: Element of fe1271
 *      l2: Element of fe1271
 *      tau: Either 0 or 1 (top bit of l1)
 *      sigma: Either 0 or 1 (top bit of l2)
 */
static void compress(fe1271 *l1, fe1271 *l2, const kpoint *x)
{
   kpoint t;
   uint tau;

   T(&t, x);

   tau = fe1271_zeroness(&t.Z);  // 0 if L_3 = 0, 1 if L_3 != 0
   if (tau) {
      fe1271_invert(l2, &t.Z);
   } else if (fe1271_zeroness(&t.Y)) {
      fe1271_invert(l2, &t.Y);
   } else if (fe1271_zeroness(&t.X)) {
      fe1271_invert(l2, &t.X);
   } else {
      fe1271_invert(l2, &t.T);
   }

   // Normalize
   fe1271_mul(&t.T, &t.T, l2);
   fe1271_mul(l1, &t.X, l2);
   fe1271_mul(l2, &t.Y, l2);

   // k2*l4 - k3
   get_k2(&t.Z, &t.X, l1, l2, tau);
   fe1271_mul(&t.Z, &t.Z, &t.T);
   get_k3(&t.T, &t.X, &t.Y, l1, l2, tau);
   fe1271_sub(&t.Z, &t.Z, &t.T);

   fe1271_freeze(l1);
   fe1271_freeze(l2);
   fe1271_freeze(&t.Z);
   l1->b[15] |= ((tau & 1) << 7);
   l2->b[15] |= ((t.Z.b[0] & 1) << 7);
}

/* -----------------------------------------------------------------------------
 * Generate a public key point on the Kummer.
 *
 * Input:
 *      sk (32 bytes): 32 bytes of randomness
 * Output:
 *      pk (32 bytes): Public key
 */
int qdsa_dh_keygen(uint8_t pk[32], const uint8_t sk[32])
{
   kpoint R;
   ckpoint rx;  // group scalar

   scalar_get32(rx.fe1.v, sk);
   ladder_base_250(&R, rx.fe1.b);
   compress(&rx.fe1, &rx.fe2, &R);
   wam_copy(pk, &rx, 32);
   return 0;
}

/* -----------------------------------------------------------------------------
 * Generate a shared secret.
 *
 * Input:
 *      sk (32 bytes): 32 bytes of randomness
 *      pk (32 bytes): Public key (remote)
 * Output:
 *      ss (32 bytes): Shared secret
 */
int qdsa_dh_exchange(uint8_t ss[32], const uint8_t pk[32], const uint8_t sk[32])
{
   kpoint SS, PK, pkw;
   ckpoint pkc;

   wam_copy(&pkc, pk, 32);
   decompress(&PK, &SS, &pkc);
   xWRAP(&pkw, &PK);

   scalar_get32(pkc.fe1.v, sk);
   ladder_250(&SS, &PK, &pkw, pkc.fe1.b);
   compress(&pkc.fe1, &pkc.fe2, &SS);
   wam_copy(ss, &pkc, 32);
   return 0;
}

/* -----------------------------------------------------------------------------
 * Generate a 64-byte pseudo-random string (sk), and a compressed public key
 * point (pk) on the Kummer.
 *
 * Input:
 *      seed (32 bytes): Randomness, or master secret.
 * Output:
 *      pk (32 bytes): Public key
 *      sk (64 bytes): Pseudo-random secret
 */
int qdsa_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32])
{
   kpoint R;
   ckpoint rx;
   bobjr_ctx ctx;

   bobjr_init(&ctx);
   bobjr_absorb_wa(&ctx, seed, 32);  // d
   bobjr_finish_wa(&ctx);            // H(d)
   wam_copy(sk, ctx.state, 64);      // d", d' is sk.

   scalar_get32(rx.fe1.v, sk + 32);
   ladder_base_250(&R, rx.fe1.b);
   compress(&rx.fe1, &rx.fe2, &R);
   wam_copy(pk, &rx, 32);  // Q = compressed [d']P is pk.
   return 0;
}

/* -----------------------------------------------------------------------------
 * Generate a signature consisting of a 32-byte compressed point on the Kummer
 * and an integer modulo the curve order. Total 64 bytes.
 *
 * Input:
 *      msg (32 bytes): Message
 *      pk (32 bytes): Public key
 *      sk (64 bytes): Pseudo-random secret
 * Output:
 *      sig (64 bytes): signature
 */
int qdsa_sign(uint8_t sig[64], const uint8_t msg[32], const uint8_t pk[32],
   const uint8_t sk[64])
{
   kpoint R;
   ckpoint rx, r;
   bobjr_ctx ctx;

   bobjr_init(&ctx);
   bobjr_absorb_wa(&ctx, sk, 32);   // d" in 1st half of secret key.
   bobjr_absorb_wa(&ctx, msg, 32);  // M
   bobjr_finish_wa(&ctx);           // r = H(d"||M) ready in state.
   large_red(r.fe1.v, (uint32_t *)ctx.state);

   ladder_base_250(&R, r.fe1.b);
   compress(&rx.fe1, &rx.fe2, &R);
   wam_copy(sig, &rx, 32);  // 1st half of sig: R = compressed [r]P

   scalar_get_hrqm(&R.X, rx.b, pk, msg);  // h = H(R||Q||M) in R.X, R.Y.
   scalar_get32(R.Z.v, sk + 32);          // d' in 2nd half of secret key.
   scalar_ops(R.Z.v, &r, R.X.v, R.Z.v);   // s = (r-hd') mod N.
   wam_copy(sig + 32, &R.Z, 32);          // 2nd half of sig: s in R.Z, R.T.
   return 0;
}

#endif  // CONF_QDSA_FULL

/* vim: set syn=c cin et sw=3 ts=3 tw=80 fo=cjMmnoqr: */
