/*
 * Assembler routines for Fp=2^127-1.
 */

/* -----------------------------------------------------------------------------
 * Add: 106 invocations.
 */
#ifdef __thumb__
void _naked fe1271_add(fe1271 *r, const fe1271 *x, const fe1271 *y)
{
   // clang-format off
   asm(
      ".syntax unified" br
      "push       {r4-r7, lr}" br
      "ldm        r1!, {r3-r6}" br
      "ldm        r2!, {r1, r7}" br
      "adds       r3, r1" br
      "adcs       r4, r7" br
      "ldm        r2!, {r1, r7}" br
      "adcs       r5, r1" br
      "adcs       r6, r7" br
      "movs       r2, #0" br
      "adcs       r2, r2" br
      "lsls       r6, #1" br
      "adcs       r2, r2" br
      "lsrs       r6, #1" br
      "movs       r7, #0" br
      "adds       r3, r2" br
      "adcs       r4, r7" br
      "adcs       r5, r7" br
      "adcs       r6, r7" br
      "stm        r0!, {r3-r6}" br
      "pop        {r4-r7, pc}" br
      : : : "r0","r1","r2","r3","cc","memory"
   );
   // clang-format on
}

#else
void fe1271_add(fe1271 *r, const fe1271 *x, const fe1271 *y)
{
   uint32_t c = 0;
   uint64_t t0, t1, t2;

   for (int i = 0; i < 4; i++) {
      t0 = (uint64_t)(x->v[i]);
      t1 = (uint64_t)(y->v[i]);
      t2 = t0 + t1;
      t2 += c;
      c = (t2 >> 32) & 1;
      r->v[i] = (uint32_t)t2;
   }
   c *= 2;
   for (int i = 0; i < 4; i++) {
      t0 = (uint64_t)r->v[i];
      t0 += c;
      c = (t0 >> 32) & 1;
      r->v[i] = (uint32_t)t0;
   }
}
#endif

/* -----------------------------------------------------------------------------
 * Sub: 60 invocations.
 */
#ifdef __thumb__
void _naked fe1271_sub(fe1271 *r, const fe1271 *x, const fe1271 *y)
{
   // clang-format off
   asm(
      ".syntax unified" br
      "push       {r4-r7, lr}" br
      "ldm        r1!, {r3-r6}" br
      "ldm        r2!, {r1, r7}" br
      "subs       r3, r1" br
      "sbcs       r4, r7" br
      "ldm        r2!, {r1, r7}" br
      "sbcs       r5, r1" br
      "sbcs       r6, r7" br
      "sbcs       r2, r2" br
      "rsbs       r2, #0" br
      "lsls       r2, #1" br
      "movs       r7, #0" br
      "subs       r3, r2" br
      "sbcs       r4, r7" br
      "sbcs       r5, r7" br
      "sbcs       r6, r7" br
      "sbcs       r7, r7" br
      "lsls       r7, #1" br
      "adds       r3, r7" br
      "stm        r0!, {r3-r6}" br
      "pop        {r4-r7, pc}" br
      : : : "r0","r1","r2","r3","cc","memory"
   );
   // clang-format on
}
#else
void fe1271_sub(fe1271 *r, const fe1271 *x, const fe1271 *y)
{
   uint32_t c = 0;
   uint64_t t0, t1;

   for (int i = 0; i < 4; i++) {
      t0 = (uint64_t)(x->v[i]);
      t1 = (uint64_t)(y->v[i]);
      t1 += c;
      t0 -= t1;
      c = (t0 >> 32) & 1;
      r->v[i] = (uint32_t)t0;
   }
   // reduce
   c *= 2;
   for (int i = 0; i < 4; i++) {
      t0 = (uint64_t)(r->v[i]);
      t0 -= c;
      c = (t0 >> 32) & 1;
      r->v[i] = (uint32_t)t0;
   }
}
#endif

/* -----------------------------------------------------------------------------
 * Neg: 518 invocations.
 */
#ifdef __thumb__
void _naked fe1271_neg(fe1271 *x)
{
   // clang-format off
   asm(
      ".syntax unified" br
#ifdef __thumb2__
      "push       {r4-r7}" br
      "movs       r7, #0" br
      "ldm        r0, {r3-r6}" br
      "rsbs       r1, r3, #0" br
      "sbcs       r2, r7, r4" br
      "sbcs       r3, r7, r5" br
      "sbcs       r7, r7, r6" br
      "sbcs       r4, r4" br
      "rsbs       r4, #0" br
      "subs       r1, r1, r4, lsl #1" br
      "sbcs       r2, #0" br
      "sbcs       r3, #0" br
      "sbc        r7, #0" br
      "stm        r0!, {r1-r3, r7}" br
      "pop        {r4-r7}" br
      "bx         lr" br
      : : : "r0","r1","r2","r3","cc","memory"
#else
      "push       {r4-r7}" br
      "ldm        r0!, {r3-r6}" br
      "rsbs       r1, r3, #0" br
      "movs       r2, #0" br
      "sbcs       r2, r4" br
      "movs       r3, #0" br
      "sbcs       r3, r5" br
      "movs       r7, #0" br
      "sbcs       r7, r6" br
      "sbcs       r4, r4" br
      "rsbs       r4, #0" br
      "lsls       r4, #1" br
      "subs       r1, r4" br
      "movs       r4, #0" br
      "sbcs       r2, r4" br
      "sbcs       r3, r4" br
      "sbcs       r7, r4" br
      "subs       r0, #16" br
      "stm        r0!, {r1, r2, r3, r7}" br
      "pop        {r4-r7}" br
      "bx         lr" br
      : : : "r0","r1","r2","r3","cc","memory"
#endif
   );
   // clang-format on
}
#else
void fe1271_neg(fe1271 *x)
{
   fe1271 zero;

   for (int i = 0; i < 4; i++)
      zero.v[i] = 0;
   fe1271_sub(x, &zero, x);
}
#endif

/* -----------------------------------------------------------------------------
 * Freeze: 12 invocations.
 */
#ifdef __thumb__
void _naked fe1271_freeze(fe1271 *x)
{
   // clang-format off
   asm(
      ".syntax unified" br
      "push       {r4, r5, lr}" br
#ifdef __thumb2__
      "ldm        r0, {r2-r5}" br
#else
      "ldm        r0!, {r2-r5}" br
#endif
      "lsrs       r1, r5, #31" br
      "lsls       r5, #1" br
      "lsrs       r5, #1" br
      "adds       r2, r1" br
      "movs       r1, #0" br
      "adcs       r3, r1" br
      "adcs       r4, r1" br
      "adcs       r5, r1" br
      "lsls       r5, #1" br
      "adcs       r2, r1" br
      "lsrs       r5, #1" br
#ifndef __thumb2__
      "subs       r0, #16" br
#endif
      "stm        r0!, {r2-r5}" br
      "pop        {r4, r5, pc}" br
      : : : "r0","r1","r2","r3","cc","memory"
   );
   // clang-format on
}
#else
void fe1271_freeze(fe1271 *x)
{
   uint64_t c, t;

   c = (x->v[3] >> 31);    // take top bit of x
   x->v[3] &= 0x7fffffff;  // set top bit to 0 (stored in c)
   for (int i = 0; i < 4; i++) {
      t = (uint64_t)(x->v[i]) + c;
      c = (t >> 32) & 1;
      x->v[i] = (uint32_t)t;
   }
   x->v[3] += (uint32_t)c;
   x->v[0] += (x->v[3] >> 31);
   x->v[3] &= 0x7fffffff;
}
#endif

/* -----------------------------------------------------------------------------
 * Mulconst: 6172 invocations.
 * Maximum 16b constant is 0xabd7.
 */
#ifdef __thumb__
void _alfn _naked fe1271_mulconst(fe1271 *r, const fe1271 *x, uint16_t y)
{
   // clang-format off
   asm(
      ".syntax unified" br
#ifdef __thumb2__
      // M4 pipline -3c uV miscount -6c
      "push       {r4-r8, lr}" br
      "ldm        r1, {r7, r8, r12, lr}" br
      "umull      r1, r3, r2, r7" br
      "movs       r4, #0" br
      "umlal      r3, r4, r2, r8" br
      "movs       r5, #0" br
      "umlal      r4, r5, r2, r12" br
      "movs       r6, #0" br
      "umlal      r5, r6, r2, lr" br
      "lsls       r5, #1" br
      "adcs       r6, r6" br
      "lsrs       r5, #1" br
      "adds       r1, r6" br
      "adcs       r3, #0" br
      "adcs       r4, #0" br
      "adcs       r5, #0" br
      "stm        r0!, {r1, r3-r5}" br
      "pop        {r4-r8, pc}" br
      : : : "r0","r1","r3","r12","lr","cc","memory" // r2 remains

#else
      "push       {r4-r7}" br
      "ldrh       r3, [r1]" br
      "muls       r3, r2" br
      "ldrh       r4, [r1, #2]" br
      "muls       r4, r2" br
      "lsls       r6, r4, #16" br
      "lsrs       r7, r4, #16" br
      "adds       r3, r6" br
      "ldrh       r4, [r1, #4]" br
      "muls       r4, r2" br
      "adcs       r4, r7" br
      "ldrh       r5, [r1, #6]" br
      "muls       r5, r2" br
      "lsls       r6, r5, #16" br
      "lsrs       r7, r5, #16" br
      "adds       r4, r6" br
      "ldrh       r5, [r1, #8]" br
      "muls       r5, r2" br
      "adcs       r5, r7" br
      "ldrh       r6, [r1, #10]" br
      "muls       r6, r2" br
      "lsrs       r7, r6, #16" br
      "lsls       r6, #16" br
      "adds       r5, r6" br
      "ldrh       r6, [r1, #12]" br
      "muls       r6, r2" br
      "adcs       r6, r7" br
      "ldrh       r7, [r1, #14]" br
      "muls       r7, r2" br
      "lsls       r1, r7, #16" br
      "lsrs       r7, #16" br
      "adds       r6, r1" br
      "movs       r2, #0" br
      "adcs       r7, r2" br
      "lsls       r7, #1" br
      "lsls       r6, #1" br
      "adcs       r7, r2" br
      "lsrs       r6, #1" br
      "adds       r3, r7" br
      "adcs       r4, r2" br
      "adcs       r5, r2" br
      "adcs       r6, r2" br
      "stm        r0!, {r3-r6}" br
      "pop        {r4-r7}" br
      "bx         lr" br
      : : : "r0","r1","r2","r3","cc","memory"
#endif
   );
   // clang-format on
}
#else

void fe1271_mulconst(fe1271 *r, const fe1271 *x, uint16_t y)
{
   fe1271 temp;

   temp.v[0] = y;
   temp.v[1] = temp.v[2] = temp.v[3] = 0;
   uint32_t t[8];
   bigint_mul(t, x->v, temp.v);
   bigint_red(r->v, t);
}
#endif

/* -----------------------------------------------------------------------------
 * Hadamard transform: 2011 invocations.
 */
#ifdef __thumb__
void _alfn _naked fe1271_hdmrd(fe1271 *r, const fe1271 *x)
{
   // clang-format off
   asm(
      ".syntax unified" br
#ifdef __thumb2__
      "push       {r4-r9, lr}" br
      "ldm        r1!, {r8, r9, r12, lr}" br
      "ldm        r1, {r2-r5}" br
      "adds       r2, r8" br
      "adcs       r3, r9" br
      "adcs       r4, r12" br
      "adcs       r5, lr" br
      "movs       r6, #0" br
      "adc        r6, r6, r5, lsr #31" br
      "adc        r6, #0" br
      "bic        r5, #0x80000000" br
      "adds       r2, r6" br
      "adcs       r3, #0" br
      "adcs       r4, #0" br
      "adcs       r5, #0" br
      "stm        r0!, {r2-r5}" br // a[0]+a[1]

      "ldm        r1!, {r2-r5}" br
      "subs       r2, r8" br
      "sbcs       r3, r9" br
      "sbcs       r4, r12" br
      "sbcs       r5, lr" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "subs       r2, r2, r6, lsl #1" br
      "sbcs       r3, #0" br
      "sbcs       r4, #0" br
      "sbcs       r5, #0" br
      "sbcs       r7, r7" br
      "add        r3, r3, r7, lsl #1" br
      "stm        r0!, {r2-r5}" br // a[1]-a[0]

      "ldm        r1!, {r2-r9}" br // a[2] & a[3] lower 2 in r6, r7
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "adcs       r4, r8" br
      "adcs       r5, r9" br
      "movs       r6, #0" br
      "adc        r6, r6, r5, lsr #31" br
      "adc        r6, #0" br
      "bic        r5, #0x80000000" br
      "adds       r2, r6" br
      "adcs       r3, #0" br
      "adcs       r4, #0" br
      "adcs       r5, #0" br
      "mov        r8, r2" br // store for later
      "mov        r9, r3" br
      "mov        r12, r4" br
      "mov        lr, r5" br

      "subs       r1, #32" br // restore pointer
      "ldm        r1!, {r2-r7}" br // a[2] & a[3] lower 2 in r6, r7
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "ldm        r1!, {r6, r7}" br // a[3] upper two words
      "sbcs       r4, r6" br
      "sbcs       r5, r7" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "subs       r2, r2, r6, lsl #1" br
      "sbcs       r3, #0" br
      "sbcs       r4, #0" br
      "sbcs       r5, #0" br
      "sbcs       r7, r7" br
      "add        r3, r3, r7, lsl #1" br
      "adds       r0, #16" br
      "stm        r0!, {r2-r5}" br

      "subs       r0, #64" br // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "ldm        r0!, {r6, r7}" br
      "sbcs       r4, r6" br
      "sbcs       r5, r7" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "subs       r2, r2, r6, lsl #1" br
      "sbcs       r3, #0" br
      "sbcs       r4, #0" br
      "sbcs       r5, #0" br
      "sbcs       r7, r7" br
      "add        r3, r3, r7, lsl #1" br
      "adds       r0, #16" br // pointer to r[2]
      "stm        r0!, {r2-r5}" br

      "ldm        r0!, {r2-r5}" br // load d
      "subs       r0, #64" br // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "ldm        r0!, {r6, r7}" br
      "adcs       r4, r6" br
      "adcs       r5, r7" br
      "movs       r6, #0" br
      "adc        r6, r6, r5, lsr #31" br
      "adc        r6, #0" br
      "bic        r5, #0x80000000" br
      "adds       r2, r6" br
      "adcs       r3, #0" br
      "adcs       r4, #0" br
      "adcs       r5, #0" br
      "adds       r0, #32" br // pointer to r[3]
      "stm        r0!, {r2-r5}" br

      "subs       r0, #48" br // pointer to r[1]
      "ldm        r0!, {r2-r5}" br
      "adds       r2, r8" br
      "adcs       r3, r9" br
      "adcs       r4, r12" br
      "adcs       r5, lr" br
      "movs       r6, #0" br
      "adc        r6, r6, r5, lsr #31" br
      "adc        r6, #0" br
      "bic        r5, #0x80000000" br
      "adds       r2, r6" br
      "adcs       r3, #0" br
      "adcs       r4, #0" br
      "adcs       r5, #0" br
      "subs       r0, #32" br // pointer to r[0]
      "stm        r0!, {r2-r5}" br

      "ldm        r0, {r2-r5}" br
      "subs       r2, r8" br
      "sbcs       r3, r9" br
      "sbcs       r4, r12" br
      "sbcs       r5, lr" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "subs       r2, r2, r6, lsl #1" br
      "sbcs       r3, #0" br
      "sbcs       r4, #0" br
      "sbcs       r5, #0" br
      "sbcs       r7, r7" br
      "add        r3, r3, r7, lsl #1" br
      "stm        r0!, {r2-r5}" br
      "pop        {r4-r9, pc}" br
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"

#else
      "push       {r4-r7}" br
      "ldm        r1!, {r2-r5}" br
      "push       {r2-r5}" br
      "ldm        r1!, {r2-r5}" br
      "pop        {r6, r7}" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "pop        {r6, r7}" br
      "adcs       r4, r6" br
      "adcs       r5, r7" br
      "sub        sp, #16" br
      "movs       r6, #0" br
      "adcs       r6, r6" br
      "lsls       r5, #1" br
      "adcs       r6, r6" br
      "lsrs       r5, #1" br
      "movs       r7, #0" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "adcs       r4, r7" br
      "adcs       r5, r7" br
      "stm        r0!, {r2-r5}" br // a[0]+a[1]

      "subs       r1, #16" br // restore pointer
      "ldm        r1!, {r2-r5}" br
      "pop        {r6, r7}" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "pop        {r6, r7}" br
      "sbcs       r4, r6" br
      "sbcs       r5, r7" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "lsls       r6, #1" br
      "movs       r7, #0" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "sbcs       r4, r7" br
      "sbcs       r5, r7" br
      "sbcs       r7, r7" br
      "lsls       r7, #1" br
      "adds       r3, r7" br
      "stm        r0!, {r2-r5}" br // a[1]-a[0]

      "ldm        r1!, {r2-r7}" br // a[2] & a[3] lower 2 in r6, r7
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "ldm        r1!, {r6, r7}" br // a[3] upper two words
      "adcs       r4, r6" br
      "adcs       r5, r7" br
      "movs       r6, #0" br
      "adcs       r6, r6" br
      "lsls       r5, #1" br
      "adcs       r6, r6" br
      "lsrs       r5, #1" br
      "movs       r7, #0" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "adcs       r4, r7" br
      "adcs       r5, r7" br
      "push       {r2-r5}" br // store for later

      "subs       r1, #32" br // restore pointer
      "ldm        r1!, {r2-r7}" br // a[2] & a[3] lower 2 in r6, r7
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "ldm        r1!, {r6, r7}" br // a[3] upper two words
      "sbcs       r4, r6" br
      "sbcs       r5, r7" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "lsls       r6, #1" br
      "movs       r7, #0" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "sbcs       r4, r7" br
      "sbcs       r5, r7" br
      "sbcs       r7, r7" br
      "lsls       r7, #1" br
      "adds       r3, r7" br
      "adds       r0, #16" br
      "stm        r0!, {r2-r5}" br

      // c = a[1]+a[0] in r[0]
      // a = a[1]-a[0] in r[1]
      // b = a[2]+a[3] in [r8, r9, r12, lr]
      // d = a[2]-a[3] in [r2, r3, r4, r5] and r[3]

      "subs       r0, #64" br // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "ldm        r0!, {r6, r7}" br
      "sbcs       r4, r6" br
      "sbcs       r5, r7" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "lsls       r6, #1" br
      "movs       r7, #0" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "sbcs       r4, r7" br
      "sbcs       r5, r7" br
      "sbcs       r7, r7" br
      "lsls       r7, #1" br
      "adds       r3, r7" br
      "adds       r0, #16" br // pointer to r[2]
      "stm        r0!, {r2-r5}" br

      "ldm        r0!, {r2-r5}" br // load d
      "subs       r0, #64" br // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "ldm        r0!, {r6, r7}" br
      "adcs       r4, r6" br
      "adcs       r5, r7" br
      "movs       r6, #0" br
      "adcs       r6, r6" br
      "lsls       r5, #1" br
      "adcs       r6, r6" br
      "lsrs       r5, #1" br
      "movs       r7, #0" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "adcs       r4, r7" br
      "adcs       r5, r7" br
      "adds       r0, #32" br // pointer to r[3]
      "stm        r0!, {r2-r5}" br

      "subs       r0, #48" br // pointer to r[1]
      "ldm        r0!, {r2-r5}" br
      "pop        {r6, r7}" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "pop        {r6, r7}" br
      "adcs       r4, r6" br
      "adcs       r5, r7" br
      "sub        sp, #16" br
      "movs       r6, #0" br
      "adcs       r6, r6" br
      "lsls       r5, #1" br
      "adcs       r6, r6" br
      "lsrs       r5, #1" br
      "movs       r7, #0" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "adcs       r4, r7" br
      "adcs       r5, r7" br
      "subs       r0, #32" br // pointer to r[0]
      "stm        r0!, {r2-r5}" br

      "ldm        r0!, {r2-r5}" br
      "pop        {r6, r7}" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "pop        {r6, r7}" br
      "sbcs       r4, r6" br
      "sbcs       r5, r7" br
      "sbcs       r6, r6" br
      "rsbs       r6, #0" br
      "lsls       r6, #1" br
      "movs       r7, #0" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "sbcs       r4, r7" br
      "sbcs       r5, r7" br
      "sbcs       r7, r7" br
      "lsls       r7, #1" br
      "adds       r3, r7" br
      "subs       r0, #16" br
      "stm        r0!, {r2-r5}" br
      "pop        {r4-r7}" br
      "bx         lr" br
      : : : "r0","r1","r2","r3","cc","memory"
#endif
   );
   // clang-format on
}
#else
void fe1271_hdmrd(fe1271 *r, const fe1271 *x)
{
   fe1271 a, b, c, d;

   fe1271_add(&c, x, x + 1);
   fe1271_sub(&a, x + 1, x);
   fe1271_add(&b, x + 2, x + 3);
   fe1271_sub(&d, x + 2, x + 3);
   fe1271_add(r, &a, &b);
   fe1271_sub(r + 1, &a, &b);
   fe1271_add(r + 3, &c, &d);
   fe1271_sub(r + 2, &d, &c);
}
#endif

/* -----------------------------------------------------------------------------
 * Reduce a 256 bit number to a 128 bit one.
 * 10122 invocations.
 */
#ifdef __thumb__
void _alfn _naked bigint_red(uint32_t *r, const uint32_t *a)
{
   // clang-format off
   asm(
      ".syntax unified" br
#ifdef __thumb2__
      "push       {r4-r7, lr}" br
      "ldm        r1, {r2-r7, r12, lr}" br
      "movs       r1, #0" br
      "adds       r6, r6" br
      "adcs       r7, r7" br
      "adcs       r12, r12" br
      "adcs       lr, lr" br
      "adcs       r1, r1" br
      "adds       r5, lr" br
      "adcs       r1, #0" br
      "lsls       r5, #1" br
      "adcs       r1, r1" br
      "lsrs       r5, #1" br
      "adds       r2, r6" br
      "adcs       r3, r7" br
      "adcs       r4, r12" br
      "adcs       r5, #0" br
      "adds       r2, r1" br
      "adcs       r3, #0" br
      "adcs       r4, #0" br
      "adcs       r5, #0" br
      "stm        r0!, {r2-r5}" br
      "pop        {r4-r7, pc}" br
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"

#else
      "push       {r4-r7, lr}" br
      "ldm        r1!, {r4-r7}" br  // lower half
      "mov        r12, r4" br
      "mov        lr, r5" br
      "ldm        r1!, {r2-r5}" br  // upper half
// First double upper half, save carry into R1
      "movs       r1, #0" br        // for carries
      "adds       r2, r2" br
      "adcs       r3, r3" br
      "adcs       r4, r4" br
      "adcs       r5, r5" br
      "adcs       r1, r1" br        // high-half carry in r1
// Do top word first, to avoid carry later
      "adds       r7, r5" br
      "movs       r5, #0" br
      "adcs       r1, r5" br        // store carry in R1
      "lsls       r7, #1" br
      "adcs       r1, r1" br        // carry*2 + top bit
      "lsrs       r7, #1" br        // and clear top-bit of low-half
// Now start from bottom again
      "mov        r5, r12" br
      "adds       r5, r2" br
      "mov        r2, lr" br
      "adcs       r2, r3" br
      "adcs       r6, r4" br
      "movs       r3, #0" br
      "adcs       r7, r3" br
// Finally do carry bits
      "adds       r1, r5" br
      "adcs       r2, r3" br
      "adcs       r6, r3" br
      "adcs       r7, r3" br        // cannot overflow
      "stm        r0!, {r1, r2, r6, r7}" br
      "pop        {r4-r7, pc}" br
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"
#endif
   );
   // clang-format on
}
#else
void bigint_red(uint32_t *r, const uint32_t *a)
{
   uint64_t res[4];

   for (int i = 0; i < 4; i++) {
      res[i] = (uint64_t)a[i];
      res[i] += 2 * (uint64_t)a[i + 4];
   }
   // reduce the whole thing to radix 2^32
   // might need two iterations
   for (int i = 0; i < 3; i++) {
      res[i + 1] += (res[i] >> 32);
      res[i] &= 0xffffffff;
   }
   res[0] += 2 * (res[3] >> 32);  // take top bits
   res[3] &= 0xffffffff;          // set top bits to 0
   for (int i = 0; i < 3; i++) {
      res[i + 1] += (res[i] >> 32);
      r[i] = (uint32_t)res[i];
   }
   r[3] = (uint32_t)res[3];
}
#endif

/* -----------------------------------------------------------------------------
 * Multiply two 128b numbers into 256b number.
 * Mul: 3730 invocations.
 * Sqr: 6440 invocations.
 */
#ifdef __thumb2__
void _alfn _naked bigint_sqr(uint32_t *r, const uint32_t *x)
{
   // clang-format off
   asm(
      ".syntax unified" br
      "mov.w      r2, r1" br
      // Thumb-2 MUL is fast enough, use it for SQR too.
      ".thumb_func" br
      // ".global    bigint_mul" br
   "bigint_mul:" br
#ifdef __ARM_FEATURE_DSP
      /*
       * Thumb-2 with DSP Extension (UMAAL). uV:109c; real ~100c.
       *
       * The following is based on FourQ's code with further improvements:
       *  - save & restore 7 instead of 9 registers (-4c)
       *  - hide MOV and STR in delay slots (-3c or more)
       *  - STM broken down and scattered into delay slots (-4c)
       *  - change register allocation to produce more T-1 encodings; saved
       *    bytes despite STM breakdown (-10B)
       */
      "push       {r4-r9, lr}" br
      "ldm        r1, {r8-r9, r12, lr}" br
      "ldr        r1, [r2]" br
      "umull      r4, r3, r1, r8" br
      "movs       r5, #0" br
      "umlal      r3, r5, r1, r9" br
      "movs       r6, #0" br
      "umlal      r5, r6, r1, r12" br
      "str        r4, [r0]" br
      "movs       r7, #0" br
      "umlal      r6, r7, r1, lr" br

      "ldr        r1, [r2, #4]" br
      "movs       r4, #0" br
      "umlal      r3, r4, r1, r8" br
      "umaal      r4, r5, r1, r9" br
      "str        r3, [r0, #4]" br
      "umaal      r5, r6, r1, r12" br
      "umaal      r6, r7, r1, lr" br

      "ldr        r1, [r2, #8]" br
      "movs       r3, #0" br
      "umlal      r4, r3, r1, r8" br
      "umaal      r3, r5, r1, r9" br
      "str        r4, [r0, #8]" br
      "umaal      r5, r6, r1, r12" br
      "umaal      r6, r7, r1, lr" br

      "ldr        r1, [r2, #12]" br
      "movs       r4, #0" br
      "umlal      r3, r4, r1, r8" br
      "str        r3, [r0, #12]" br
      "umaal      r4, r5, r1, r9" br
      "str        r4, [r0, #16]" br
      "umaal      r5, r6, r1, r12" br
      "str        r5, [r0, #20]" br
      "umaal      r6, r7, r1, lr" br
      "str        r6, [r0, #24]" br
      "str        r7, [r0, #28]" br
      "pop        {r4-r9, pc}" br
      : : : "r1","r2","r3","r12","lr","cc","memory" // r0 remains

#else
      /*
       * Thumb-2 without UMAAL. uV:181c
       *
       * Translate UMAAL to UMULL and 2 ADD/ADC pairs. slightly better than
       * MOV #0, UMLAL and 1 ADD/ADC pair.
       */
      "push       {r4-r11, lr}" br
      "ldm        r1, {r8-r11}" br
      "ldr        r1, [r2]" br
      "umull      r4, r3, r1, r8" br
      "movs       r5, #0" br
      "umlal      r3, r5, r1, r9" br
      "movs       r6, #0" br
      "umlal      r5, r6, r1, r10" br
      "mov        r12, #0" br
      "umlal      r6, r12, r1, r11" br
      "str        r4, [r0], #4" br

      "ldr        r1, [r2, #4]" br
      "movs       r4, #0" br
      "umlal      r3, r4, r1, r8" br
      "umull      r7, lr, r1, r9" br
      "adds       r7, r5" br
      "adc        lr, #0" br
      "adds       r4, r7" br
      "adc        r5, lr, #0" br
      "umull      r7, lr, r1, r10" br
      "adds       r7, r6" br
      "adc        lr, #0" br
      "adds       r5, r7" br
      "adc        r6, lr, #0" br
      "umull      r7, lr, r1, r11" br
      "adds       r7, r12" br
      "adc        lr, #0" br
      "adds       r6, r7" br
      "adc        r12, lr, #0" br
      "str        r3, [r0], #4" br

      "ldr        r1, [r2, #8]" br
      "movs       r3, #0" br
      "umlal      r4, r3, r1, r8" br
      "umull      r7, lr, r1, r9" br
      "adds       r7, r5" br
      "adc        lr, #0" br
      "adds       r3, r7" br
      "adc        r5, lr, #0" br
      "umull      r7, lr, r1, r10" br
      "adds       r7, r6" br
      "adc        lr, #0" br
      "adds       r5, r7" br
      "adc        r6, lr, #0" br
      "umull      r7, lr, r1, r11" br
      "adds       r7, r12" br
      "adc        lr, #0" br
      "adds       r6, r7" br
      "adc        r12, lr, #0" br
      "str        r4, [r0], #4" br

      "ldr        r1, [r2, #12]" br
      "movs       r4, #0" br
      "umlal      r3, r4, r1, r8" br
      "umull      r7, lr, r1, r9" br
      "adds       r7, r5" br
      "adc        lr, #0" br
      "adds       r4, r7" br
      "adc        r5, lr, #0" br
      "umull      r7, lr, r1, r10" br
      "adds       r7, r6" br
      "adc        lr, #0" br
      "adds       r5, r7" br
      "adc        r6, lr, #0" br
      "umull      r7, lr, r1, r11" br
      "adds       r7, r12" br
      "adc        lr, #0" br
      "adds       r6, r7" br
      "adc        r12, lr, #0" br
      "stm        r0, {r3-r6, r12}" br
      "pop        {r4-r11, pc}" br
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"
#endif
   );
   // clang-format on
}

#elif defined(__thumb__)
/*
 * 385c.
 */
void _naked bigint_mul(uint32_t *r, const uint32_t *x, const uint32_t *y)
{
   // clang-format off
   asm(
      ".syntax unified" br
      "push       {r4-r7, lr}" br
      "mov        r3, r8" br
      "mov        r4, r9" br
      "mov        r5, r10" br
      "push       {r3-r5}" br
      "mov        lr, r0" br
      "mov        r12, r1" br
      "mov        r10, r2" br
      "ldm        r2!, {r4, r5}" br
      "ldm        r1!, {r2, r3, r6, r7}" br
      // MUL128
      // MUL64
      "mov        r6, r5" br
      "mov        r1, r2" br
      "subs       r5, r4" br
      "sbcs       r0, r0" br
      "eors       r5, r0" br
      "subs       r5, r0" br
      "subs       r1, r3" br
      "sbcs       r7, r7" br
      "eors       r1, r7" br
      "subs       r1, r7" br
      "eors       r7, r0" br
      "mov        r9, r1" br
      "mov        r8, r5" br
// r4xr2->r1:r0 t:r5
      "lsrs       r1, r4, #16" br
      "uxth       r4, r4" br
      "mov        r0, r4" br
      "uxth       r5, r2" br
      "lsrs       r2, #16" br
      "muls       r0, r5" br   //00
      "muls       r5, r1" br   //10
      "muls       r4, r2" br   //01
      "muls       r1, r2" br   //11
      "lsls       r2, r4, #16" br
      "lsrs       r4, #16" br
      "adds       r0, r2" br
      "adcs       r1, r4" br
      "lsls       r2, r5, #16" br
      "lsrs       r4, r5, #16" br
      "adds       r0, r2" br
      "adcs       r1, r4" br
// r6xr3->r3:r2 t:r4,r5
      "lsrs       r4, r6, #16" br
      "uxth       r6, r6" br
      "uxth       r5, r3" br
      "lsrs       r3, r3, #16" br
      "mov        r2, r6" br
      "muls       r2, r5" br
      "muls       r5, r4" br
      "muls       r6, r3" br
      "muls       r3, r4" br
      "lsls       r4, r5, #16" br
      "lsrs       r5, #16" br
      "adds       r2, r4" br
      "adcs       r3, r5" br
      "lsls       r4, r6, #16" br
      "lsrs       r5, r6, #16" br
      "adds       r2, r4" br
      "adcs       r3, r5" br

      "eors       r6, r6" br
      "adds       r2, r1" br
      "adcs       r3, r6" br
      "mov        r1, r9" br
      "mov        r5, r8" br
      "mov        r8, r0" br
// r1xr5->r0:r1 t:r4,r6
      "lsrs       r0, r1, #16" br
      "uxth       r1, r1" br
      "mov        r4, r1" br
      "lsrs       r6, r5, #16" br
      "uxth       r5, r5" br
      "muls       r1, r5" br
      "muls       r4, r6" br
      "muls       r5, r0" br
      "muls       r0, r6" br
      "lsls       r6, r4, #16" br
      "lsrs       r4, #16" br
      "adds       r1, r6" br
      "adcs       r0, r4" br
      "lsls       r6, r5, #16" br
      "lsrs       r5, #16" br
      "adds       r1, r6" br
      "adcs       r0, r5" br

      "eors       r1, r7" br
      "eors       r0, r7" br
      "eors       r4, r4" br
      "asrs       r7, #1" br
      "adcs       r1, r2" br
      "adcs       r2, r0" br
      "adcs       r7, r4" br
      "mov        r0, r8" br
      "adds       r1, r0" br
      "adcs       r2, r3" br
      "adcs       r3, r7" br
// -------------------------
      "mov        r4, lr" br
      "stm        r4!, {r0, r1}" br
      "push       {r4}" br
      "push       {r0, r1}" br
      "mov        r1, r10" br
      "mov        r10, r2" br
      "ldm        r1, {r0, r1, r4, r5}" br
      "mov        r2, r4" br
      "mov        r7, r5" br
      "subs       r2, r0" br
      "sbcs       r7, r1" br
      "sbcs       r6, r6" br
      "eors       r2, r6" br
      "eors       r7, r6" br
      "subs       r2, r6" br
      "sbcs       r7, r6" br
      "push       {r2, r7}" br
      "mov        r2, r12" br
      "mov        r12, r3" br
      "ldm        r2, {r0, r1, r2, r3}" br
      "subs       r0, r2" br
      "sbcs       r1, r3" br
      "sbcs       r7, r7" br
      "eors       r0, r7" br
      "eors       r1, r7" br
      "subs       r0, r7" br
      "sbcs       r1, r7" br
      "eors       r7, r6" br
      "mov        lr, r7" br
      "push       {r0, r1}" br
      // MUL64
      "mov        r6, r5" br
      "mov        r1, r2" br
      "subs       r5, r4" br
      "sbcs       r0, r0" br
      "eors       r5, r0" br
      "subs       r5, r0" br
      "subs       r1, r3" br
      "sbcs       r7, r7" br
      "eors       r1, r7" br
      "subs       r1, r7" br
      "eors       r7, r0" br
      "mov        r9, r1" br
      "mov        r8, r5" br
// r4xr2->r1:r0 t:r5
      "lsrs       r1, r4, #16" br
      "uxth       r4, r4" br
      "mov        r0, r4" br
      "uxth       r5, r2" br
      "lsrs       r2, #16" br
      "muls       r0, r5" br   //00
      "muls       r5, r1" br   //10
      "muls       r4, r2" br   //01
      "muls       r1, r2" br   //11
      "lsls       r2, r4, #16" br
      "lsrs       r4, #16" br
      "adds       r0, r2" br
      "adcs       r1, r4" br
      "lsls       r2, r5, #16" br
      "lsrs       r4, r5, #16" br
      "adds       r0, r2" br
      "adcs       r1, r4" br
// r6xr3->r3:r2 t:r4,r5
      "lsrs       r4, r6, #16" br
      "uxth       r6, r6" br
      "uxth       r5, r3" br
      "lsrs       r3, #16" br
      "mov        r2, r6" br
      "muls       r2, r5" br
      "muls       r5, r4" br
      "muls       r6, r3" br
      "muls       r3, r4" br
      "lsls       r4, r5, #16" br
      "lsrs       r5, #16" br
      "adds       r2, r4" br
      "adcs       r3, r5" br
      "lsls       r4, r6, #16" br
      "lsrs       r5, r6, #16" br
      "adds       r2, r4" br
      "adcs       r3, r5" br

      "eors       r6, r6" br
      "adds       r2, r1" br
      "adcs       r3, r6" br
      "mov        r1, r9" br
      "mov        r5, r8" br
      "mov        r8, r0" br
// r1xr5->r0:r1 t:r0,r6
      "lsrs       r0, r1, #16" br
      "uxth       r1, r1" br
      "mov        r4, r1" br
      "lsrs       r6, r5, #16" br
      "uxth       r5, r5" br
      "muls       r1, r5" br
      "muls       r4, r6" br
      "muls       r5, r0" br
      "muls       r0, r6" br
      "lsls       r6, r4, #16" br
      "lsrs       r4, #16" br
      "adds       r1, r6" br
      "adcs       r0, r4" br
      "lsls       r6, r5, #16" br
      "lsrs       r5, #16" br
      "adds       r1, r6" br
      "adcs       r0, r5" br

      "eors       r1, r7" br
      "eors       r0, r7" br
      "eors       r4, r4" br
      "asrs       r7, #1" br
      "adcs       r1, r2" br
      "adcs       r2, r0" br
      "adcs       r7, r4" br
      "mov        r0, r8" br
      "adds       r1, r0" br
      "adcs       r2, r3" br
      "adcs       r3, r7" br
      "mov        r4, r10" br
      "mov        r5, r12" br
      "eors       r6, r6" br
      "adds       r0, r4" br
      "adcs       r1, r5" br
      "adcs       r2, r6" br
      "adcs       r3, r6" br
      "mov        r10, r2" br
      "mov        r12, r3" br
      "pop        {r2-r5}" br
      "push       {r0, r1}" br
      "mov        r6, r5" br
      "mov        r1, r2" br
      "subs       r5, r4" br
      "sbcs       r0, r0" br
      "eors       r5, r0" br
      "subs       r5, r0" br
      "subs       r1, r3" br
      "sbcs       r7, r7" br
      "eors       r1, r7" br
      "subs       r1, r7" br
      "eors       r7, r0" br
      "mov        r9, r1" br
      "mov        r8, r5" br
// r4xr2->r1:r0 t:r1,r5
      "lsrs       r1, r4, #16" br
      "uxth       r4, r4" br
      "mov        r0, r4" br
      "uxth       r5, r2" br
      "lsrs       r2, #16" br
      "muls       r0, r5" br   //00
      "muls       r5, r1" br   //10
      "muls       r4, r2" br   //01
      "muls       r1, r2" br   //11
      "lsls       r2, r4, #16" br
      "lsrs       r4, #16" br
      "adds       r0, r2" br
      "adcs       r1, r4" br
      "lsls       r2, r5, #16" br
      "lsrs       r4, r5, #16" br
      "adds       r0, r2" br
      "adcs       r1, r4" br
// r6xr3->r3:r2 t:r4,r5
      "lsrs       r4, r6, #16" br
      "uxth       r6, r6" br
      "uxth       r5, r3" br
      "lsrs       r3, #16" br
      "mov        r2, r6" br
      "muls       r2, r5" br
      "muls       r5, r4" br
      "muls       r6, r3" br
      "muls       r3, r4" br
      "lsls       r4, r5, #16" br
      "lsrs       r5, #16" br
      "adds       r2, r4" br
      "adcs       r3, r5" br
      "lsls       r4, r6, #16" br
      "lsrs       r5, r6, #16" br
      "adds       r2, r4" br
      "adcs       r3, r5" br

      "eors       r6, r6" br
      "adds       r2, r1" br
      "adcs       r3, r6" br
      "mov        r1, r9" br
      "mov        r5, r8" br
      "mov        r8, r0" br
// r1xr5->r0:r1 t:r4,r6
      "lsrs       r0, r1, #16" br
      "uxth       r1, r1" br
      "mov        r4, r1" br
      "lsrs       r6, r5, #16" br
      "uxth       r5, r5" br
      "muls       r1, r5" br
      "muls       r4, r6" br
      "muls       r5, r0" br
      "muls       r0, r6" br
      "lsls       r6, r4, #16" br
      "lsrs       r4, #16" br
      "adds       r1, r6" br
      "adcs       r0, r4" br
      "lsls       r6, r5, #16" br
      "lsrs       r5, #16" br
      "adds       r1, r6" br
      "adcs       r0, r5" br

      "eors       r1, r7" br
      "eors       r0, r7" br
      "eors       r4, r4" br
      "asrs       r7, #1" br
      "adcs       r1, r2" br
      "adcs       r2, r0" br
      "adcs       r7, r4" br
      "mov        r0, r8" br
      "adds       r1, r0" br
      "adcs       r2, r3" br
      "adcs       r3, r7" br
      "pop        {r4, r5}" br
      "mov        r6, lr" br
      "mov        r7, lr" br
      "eors       r0, r6" br
      "eors       r1, r6" br
      "eors       r2, r6" br
      "eors       r3, r6" br
      "asrs       r6, #1" br
      "adcs       r0, r4" br
      "adcs       r1, r5" br
      "adcs       r4, r2" br
      "adcs       r5, r3" br
      "eors       r2, r2" br
      "adcs       r6, r2" br
      "adcs       r7, r2" br
      "pop        {r2, r3}" br
      "mov        r8, r2" br
      "mov        r9, r3" br
      "adds       r2, r0" br
      "adcs       r3, r1" br
      "mov        r0, r10" br
      "mov        r1, r12" br
      "adcs       r4, r0" br
      "adcs       r5, r1" br
      "adcs       r6, r0" br
      "adcs       r7, r1" br
      // MUL128 END
      "pop        {r0}" br
      "stm        r0!, {r2-r7}" br
      "pop        {r3-r5}" br
      "mov        r8, r3" br
      "mov        r9, r4" br
      "mov        r10, r5" br
      "pop        {r4-r7, pc}" br
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"
   );
   // clang-format on
}
#else
void bigint_mul(uint32_t *r, const uint32_t *x, const uint32_t *y)
{
   int i, j;
   uint64_t t0, t1, mul;
   uint64_t res[8];

   for (i = 0; i < 8; i++)
      res[i] = 0;
   for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
         t0 = (uint64_t)(x[i]);
         t1 = (uint64_t)(y[j]);
         mul = t0 * t1;
         res[i + j] += mul & 0xffffffff;  // add low part of mult to result
         res[i + j + 1] += mul >> 32;     // add high part of mult to result
      }
   }
   // reduce the whole result to radix 2^32
   for (i = 0; i < 7; i++) {
      res[i + 1] += res[i] >> 32;
      r[i] = (uint32_t)res[i];
   }
   r[7] = (uint32_t)res[7];
}
#endif

/* -----------------------------------------------------------------------------
 * This squarer is dedicated to Thumb-1. Thumb-2 uses multiply.
 * 240c
 */
#if !defined(__thumb2__)
#ifdef __thumb__
void _naked bigint_sqr(uint32_t *r, const uint32_t *x)
{
   // Author: Ana Helena Sánchez, Bjoern Haase (second implementation).
   // Public domain.
   // ASM Square 256 refined Karatsuba.

   // clang-format off
   asm(
      ".syntax unified" br
      // sqr 256 Refined Karatsuba
      "push       {r4-r7, lr}" br
      "mov        r3, r8" br
      "mov        r4, r9" br
      "mov        r5, r10" br
      "mov        r6, r11" br
      "push       {r3-r6}" br
      "mov        lr, r0" br
      "ldm        r1!, {r4-r7}" br
      // sqr 128 Refined Karatsuba.
      // Input in r4..r7, result in r0..r7, clobbers all except r14.
      "mov        r0, r4" br
      "mov        r1, r5" br
      "subs       r0, r6" br
      "sbcs       r1, r7" br
      "sbcs       r2, r2" br
      "eors       r0, r2" br
      "eors       r1, r2" br
      "subs       r0, r2" br
      "sbcs       r1, r2" br
      "mov        r8, r0" br
      "mov        r9, r1" br
      "mov        r10, r6" br
      // sqr 64 Refined Karatsuba.
      // Input in r4,r5, result in r0-r3, clobbers: r4-r6
      // START: sqr 32
      // Input in r4, result in r0 ,r1, clobbers: r2, r3
      "uxth       r0, r4" br
      "lsrs       r1, r4, #16" br
      "mov        r2, r0" br
      "muls       r2, r1" br
      "muls       r0, r0" br
      "muls       r1, r1" br
      "lsrs       r3, r2, #15" br
      "lsls       r2, r2, #17" br
      "adds       r0, r2" br
      "adcs       r1, r3" br
      // End: sqr 32, result in r0 ,r1
      "subs       r4, r5" br
      "sbcs       r6, r6" br
      "eors       r4, r6" br
      "subs       r4, r6" br
      // START: sqr 32
      // Input in r5, result in r2 ,r3, clobbers: r5, r6
      "uxth       r2, r5" br
      "lsrs       r3, r5, #16" br
      "mov        r5, r2" br
      "muls       r5, r3" br
      "muls       r2, r2" br
      "muls       r3, r3" br
      "lsrs       r6, r5, #15" br
      "lsls       r5, #17" br
      "adds       r2, r5" br
      "adcs       r3, r6" br
      // End: sqr 32, result in r2 ,r3
      "movs       r6, #0" br
      "adds       r2, r1" br
      "adcs       r3, r6" br
      // START: sqr 32
      // Input in r4, result in r4 ,r5, clobbers: r1, r6
      "lsrs       r5, r4, #16" br
      "uxth       r4, r4" br
      "mov        r1, r4" br
      "muls       r1, r5" br
      "muls       r4, r4" br
      "muls       r5, r5" br
      "lsrs       r6, r1, #15" br
      "lsls       r1, #17" br
      "adds       r4, r1" br
      "adcs       r5, r6" br
      // End: sqr 32, result in r4 ,r5
      "mov        r1, r2" br
      "subs       r1, r4" br
      "sbcs       r2, r5" br
      "mov        r5, r3" br
      "movs       r6, #0" br
      "sbcs       r3, r6" br
      "adds       r1, r0" br
      "adcs       r2, r5" br
      "adcs       r3, r6" br
      // END: sqr 64 Refined Karatsuba
      // Result in r0,r1,r2,r3, leaves r6 zero.
      "mov        r6, r10" br
      "mov        r10, r0" br
      "mov        r11, r1" br
      "mov        r12, r2" br
      "mov        r1, r3" br
      // sqr 64 Refined Karatsuba
      // Input in r6,r7, result in r2-r5, clobbers: r0, r7, r6
      // START: sqr 32
      // Input in r6, result in r2 ,r3, clobbers: r4, r5
      "uxth       r2, r6" br
      "lsrs       r3, r6, #16" br
      "mov        r4, r2" br
      "muls       r4, r3" br
      "muls       r2, r2" br
      "muls       r3, r3" br
      "lsrs       r5, r4, #15" br
      "lsls       r4, #17" br
      "adds       r2, r4" br
      "adcs       r3, r5" br
      // End: sqr 32, result in r2 ,r3
      "subs       r6, r7" br
      "sbcs       r4, r4" br
      "eors       r6, r4" br
      "subs       r6, r4" br
      // START: sqr 32
      // Input in r7, result in r4 ,r5, clobbers: r0, r7
      "uxth       r4, r7" br
      "lsrs       r5, r7, #16" br
      "mov        r0, r4" br
      "muls       r0, r5" br
      "muls       r4, r4" br
      "muls       r5, r5" br
      "lsrs       r7, r0, #15" br
      "lsls       r0, #17" br
      "adds       r4, r0" br
      "adcs       r5, r7" br
      // End: sqr 32, result in r4 ,r5
      "movs       r7, #0" br
      "adds       r4, r3" br
      "adcs       r5, r7" br
      // START: sqr 32
      // Input in r6, result in r7 ,r0, clobbers: r6, r3
      "uxth       r7, r6" br
      "lsrs       r0, r6, #16" br
      "mov        r6, r7" br
      "muls       r6, r0" br
      "muls       r7, r7" br
      "muls       r0, r0" br
      "lsrs       r3, r6, #15" br
      "lsls       r6, #17" br
      "adds       r7, r6" br
      "adcs       r0, r3" br
      // End: sqr 32, result in r7 ,r0
      "mov        r3, r4" br
      "subs       r3, r7" br
      "sbcs       r4, r0" br
      "mov        r0, r5" br
      "movs       r6, #0" br
      "sbcs       r5, r6" br
      "adds       r3, r2" br
      "adcs       r4, r0" br
      "adcs       r5, r6" br
      // END: sqr 64 Refined Karatsuba
      // Result in r2, r3, r4, r5, leaves r6 zero.
      "mov        r0, r12" br
      "adds       r2, r0" br
      "adcs       r3, r1" br
      "adcs       r4, r6" br
      "adcs       r5, r6" br
      "mov        r12, r2" br
      "mov        r2, r8" br
      "mov        r8, r3" br
      "mov        r3, r9" br
      "mov        r9, r4" br
      // START: sqr 64 Refined Karatsuba
      // Input in r2,r3, result in r6, r7, r0, r1, clobbers: r2, r3, r4
      // START: sqr 32
      // Input in r2. result in r6 ,r7, clobbers: r0, r1
      "uxth       r6, r2" br
      "lsrs       r7, r2, #16" br
      "mov        r0, r6" br
      "muls       r0, r7" br
      "muls       r6, r6" br
      "muls       r7, r7" br
      "lsrs       r1, r0, #15" br
      "lsls       r0, #17" br
      "adds       r6, r0" br
      "adcs       r7, r1" br
      // End: sqr 32
      // Result in r6 ,r7
      "subs       r2, r3" br
      "sbcs       r4, r4" br
      "eors       r2, r4" br
      "subs       r2, r4" br
      // START: sqr 32
      // Input in r3, result in r0, r1, clobbers: r3, r4
      "uxth       r0, r3" br
      "lsrs       r1, r3, #16" br
      "mov        r3, r0" br
      "muls       r3, r1" br
      "muls       r0, r0" br
      "muls       r1, r1" br
      "lsrs       r4, r3, #15" br
      "lsls       r3, #17" br
      "adds       r0, r3" br
      "adcs       r1, r4" br
      // End: sqr 32, result in r0 ,r1
      "movs       r4, #0" br
      "adds       r0, r7" br
      "adcs       r1, r4" br
      // START: sqr 32
      // Input in r2, result in r3, r4, clobbers: r2, r7
      "uxth       r3, r2" br
      "lsrs       r4, r2, #16" br
      "mov        r2, r3" br
      "muls       r2, r4" br
      "muls       r3, r3" br
      "muls       r4, r4" br
      "lsrs       r7, r2, #15" br
      "lsls       r2, #17" br
      "adds       r3, r2" br
      "adcs       r4, r7" br
      // End: sqr 32, result in r3, r4
      "mov        r7, r0" br
      "subs       r7, r3" br
      "sbcs       r0, r4" br
      "mov        r2, r1" br
      "movs       r4, #0" br
      "sbcs       r1, r4" br
      "adds       r7, r6" br
      "adcs       r0, r2" br
      "adcs       r1, r4" br
      // END: sqr 64 Refined Karatsuba
      // Result in r6, r7, r0, r1, returns r4 as zero.
      "mov        r2, r12" br
      "mov        r3, r8" br
      "mov        r4, r9" br
      "subs       r2, r6" br
      "sbcs       r3, r7" br
      "mov        r6, r4" br
      "mov        r7, r5" br
      "sbcs       r4, r0" br
      "sbcs       r5, r1" br
      "movs       r0, #0" br
      "sbcs       r6, r0" br
      "sbcs       r7, r0" br
      "mov        r0, r10" br
      "adds       r2, r0" br
      "mov        r1, r11" br
      "adcs       r3, r1" br
      "mov        r0, r12" br
      "adcs       r4, r0" br
      "mov        r0, r8" br
      "adcs       r5, r0" br
      "movs       r0, #0" br
      "adcs       r6, r0" br
      "adcs       r7, r0" br
      "mov        r0, r10" br
      // END: sqr 128 Refined Karatsuba
      "mov        r8, r7" br
      "mov        r7, lr" br
      "stm        r7!, {r0-r6}" br
      "mov        r6, r8" br
      "stm        r7!, {r6}" br
      "pop        {r3-r6}" br
      "mov        r8, r3" br
      "mov        r9, r4" br
      "mov        r10, r5" br
      "mov        r11, r6" br
      "pop        {r4-r7, pc}" br
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"
   );
   // clang-format on
}

#else
void bigint_sqr(uint32_t *r, const uint32_t *x)
{
   bigint_mul(r, x, x);
}
#endif
#endif

/* vim: set syn=c cin et sw=3 ts=3 tw=80 fo=cjMmnoqr: */
