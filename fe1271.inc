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
      ".syntax unified" __
      "push       {r4-r7, lr}" __
      "ldm        r1!, {r3-r6}" __
      "ldm        r2!, {r1, r7}" __
      "adds       r3, r1" __
      "adcs       r4, r7" __
      "ldm        r2!, {r1, r7}" __
      "adcs       r5, r1" __
      "adcs       r6, r7" __
      "movs       r2, #0" __
      "adcs       r2, r2" __
      "lsls       r6, #1" __
      "adcs       r2, r2" __
      "lsrs       r6, #1" __
      "movs       r7, #0" __
      "adds       r3, r2" __
      "adcs       r4, r7" __
      "adcs       r5, r7" __
      "adcs       r6, r7" __
      "stm        r0!, {r3-r6}" __
      "pop        {r4-r7, pc}" __
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
      ".syntax unified" __
      "push       {r4-r7, lr}" __
      "ldm        r1!, {r3-r6}" __
      "ldm        r2!, {r1, r7}" __
      "subs       r3, r1" __
      "sbcs       r4, r7" __
      "ldm        r2!, {r1, r7}" __
      "sbcs       r5, r1" __
      "sbcs       r6, r7" __
      "sbcs       r2, r2" __
      "rsbs       r2, #0" __
      "lsls       r2, #1" __
      "movs       r7, #0" __
      "subs       r3, r2" __
      "sbcs       r4, r7" __
      "sbcs       r5, r7" __
      "sbcs       r6, r7" __
      "sbcs       r7, r7" __
      "lsls       r7, #1" __
      "adds       r3, r7" __
      "stm        r0!, {r3-r6}" __
      "pop        {r4-r7, pc}" __
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
      ".syntax unified" __
#ifdef __thumb2__
      "push       {r4-r7}" __
      "movs       r7, #0" __
      "ldm        r0, {r3-r6}" __
      "rsbs       r1, r3, #0" __
      "sbcs       r2, r7, r4" __
      "sbcs       r3, r7, r5" __
      "sbcs       r7, r7, r6" __
      "sbcs       r4, r4" __
      "rsbs       r4, #0" __
      "subs       r1, r1, r4, lsl #1" __
      "sbcs       r2, #0" __
      "sbcs       r3, #0" __
      "sbc        r7, #0" __
      "stm        r0!, {r1-r3, r7}" __
      "pop        {r4-r7}" __
      "bx         lr" __
      : : : "r0","r1","r2","r3","cc","memory"
#else
      "push       {r4-r7}" __
      "ldm        r0!, {r3-r6}" __
      "rsbs       r1, r3, #0" __
      "movs       r2, #0" __
      "sbcs       r2, r4" __
      "movs       r3, #0" __
      "sbcs       r3, r5" __
      "movs       r7, #0" __
      "sbcs       r7, r6" __
      "sbcs       r4, r4" __
      "rsbs       r4, #0" __
      "lsls       r4, #1" __
      "subs       r1, r4" __
      "movs       r4, #0" __
      "sbcs       r2, r4" __
      "sbcs       r3, r4" __
      "sbcs       r7, r4" __
      "subs       r0, #16" __
      "stm        r0!, {r1, r2, r3, r7}" __
      "pop        {r4-r7}" __
      "bx         lr" __
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
      ".syntax unified" __
      "push       {r4, r5, lr}" __
#ifdef __thumb2__
      "ldm        r0, {r2-r5}" __
#else
      "ldm        r0!, {r2-r5}" __
#endif
      "lsrs       r1, r5, #31" __
      "lsls       r5, #1" __
      "lsrs       r5, #1" __
      "adds       r2, r1" __
      "movs       r1, #0" __
      "adcs       r3, r1" __
      "adcs       r4, r1" __
      "adcs       r5, r1" __
      "lsls       r5, #1" __
      "adcs       r2, r1" __
      "lsrs       r5, #1" __
#ifndef __thumb2__
      "subs       r0, #16" __
#endif
      "stm        r0!, {r2-r5}" __
      "pop        {r4, r5, pc}" __
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
      ".syntax unified" __
#ifdef __thumb2__
      // M4 pipline -3c uV miscount -6c
      "push       {r4-r8, lr}" __
      "ldm        r1, {r7, r8, r12, lr}" __
      "umull      r1, r3, r2, r7" __
      "movs       r4, #0" __
      "umlal      r3, r4, r2, r8" __
      "movs       r5, #0" __
      "umlal      r4, r5, r2, r12" __
      "movs       r6, #0" __
      "umlal      r5, r6, r2, lr" __
      "lsls       r5, #1" __
      "adcs       r6, r6" __
      "lsrs       r5, #1" __
      "adds       r1, r6" __
      "adcs       r3, #0" __
      "adcs       r4, #0" __
      "adcs       r5, #0" __
      "stm        r0!, {r1, r3-r5}" __
      "pop        {r4-r8, pc}" __
      : : : "r0","r1","r3","r12","lr","cc","memory" // r2 remains

#else
      "push       {r4-r7}" __
      "ldrh       r3, [r1]" __
      "muls       r3, r2" __
      "ldrh       r4, [r1, #2]" __
      "muls       r4, r2" __
      "lsls       r6, r4, #16" __
      "lsrs       r7, r4, #16" __
      "adds       r3, r6" __
      "ldrh       r4, [r1, #4]" __
      "muls       r4, r2" __
      "adcs       r4, r7" __
      "ldrh       r5, [r1, #6]" __
      "muls       r5, r2" __
      "lsls       r6, r5, #16" __
      "lsrs       r7, r5, #16" __
      "adds       r4, r6" __
      "ldrh       r5, [r1, #8]" __
      "muls       r5, r2" __
      "adcs       r5, r7" __
      "ldrh       r6, [r1, #10]" __
      "muls       r6, r2" __
      "lsrs       r7, r6, #16" __
      "lsls       r6, #16" __
      "adds       r5, r6" __
      "ldrh       r6, [r1, #12]" __
      "muls       r6, r2" __
      "adcs       r6, r7" __
      "ldrh       r7, [r1, #14]" __
      "muls       r7, r2" __
      "lsls       r1, r7, #16" __
      "lsrs       r7, #16" __
      "adds       r6, r1" __
      "movs       r2, #0" __
      "adcs       r7, r2" __
      "lsls       r7, #1" __
      "lsls       r6, #1" __
      "adcs       r7, r2" __
      "lsrs       r6, #1" __
      "adds       r3, r7" __
      "adcs       r4, r2" __
      "adcs       r5, r2" __
      "adcs       r6, r2" __
      "stm        r0!, {r3-r6}" __
      "pop        {r4-r7}" __
      "bx         lr" __
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
      ".syntax unified" __
#ifdef __thumb2__
      "push       {r4-r9, lr}" __
      "ldm        r1!, {r8, r9, r12, lr}" __
      "ldm        r1, {r2-r5}" __
      "adds       r2, r8" __
      "adcs       r3, r9" __
      "adcs       r4, r12" __
      "adcs       r5, lr" __
      "movs       r6, #0" __
      "adc        r6, r6, r5, lsr #31" __
      "adc        r6, #0" __
      "bic        r5, #0x80000000" __
      "adds       r2, r6" __
      "adcs       r3, #0" __
      "adcs       r4, #0" __
      "adcs       r5, #0" __
      "stm        r0!, {r2-r5}" __ // a[0]+a[1]

      "ldm        r1!, {r2-r5}" __
      "subs       r2, r8" __
      "sbcs       r3, r9" __
      "sbcs       r4, r12" __
      "sbcs       r5, lr" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "subs       r2, r2, r6, lsl #1" __
      "sbcs       r3, #0" __
      "sbcs       r4, #0" __
      "sbcs       r5, #0" __
      "sbcs       r7, r7" __
      "add        r3, r3, r7, lsl #1" __
      "stm        r0!, {r2-r5}" __ // a[1]-a[0]

      "ldm        r1!, {r2-r9}" __ // a[2] & a[3] lower 2 in r6, r7
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "adcs       r4, r8" __
      "adcs       r5, r9" __
      "movs       r6, #0" __
      "adc        r6, r6, r5, lsr #31" __
      "adc        r6, #0" __
      "bic        r5, #0x80000000" __
      "adds       r2, r6" __
      "adcs       r3, #0" __
      "adcs       r4, #0" __
      "adcs       r5, #0" __
      "mov        r8, r2" __ // store for later
      "mov        r9, r3" __
      "mov        r12, r4" __
      "mov        lr, r5" __

      "subs       r1, #32" __ // restore pointer
      "ldm        r1!, {r2-r7}" __ // a[2] & a[3] lower 2 in r6, r7
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "ldm        r1!, {r6, r7}" __ // a[3] upper two words
      "sbcs       r4, r6" __
      "sbcs       r5, r7" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "subs       r2, r2, r6, lsl #1" __
      "sbcs       r3, #0" __
      "sbcs       r4, #0" __
      "sbcs       r5, #0" __
      "sbcs       r7, r7" __
      "add        r3, r3, r7, lsl #1" __
      "adds       r0, #16" __
      "stm        r0!, {r2-r5}" __

      "subs       r0, #64" __ // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "ldm        r0!, {r6, r7}" __
      "sbcs       r4, r6" __
      "sbcs       r5, r7" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "subs       r2, r2, r6, lsl #1" __
      "sbcs       r3, #0" __
      "sbcs       r4, #0" __
      "sbcs       r5, #0" __
      "sbcs       r7, r7" __
      "add        r3, r3, r7, lsl #1" __
      "adds       r0, #16" __ // pointer to r[2]
      "stm        r0!, {r2-r5}" __

      "ldm        r0!, {r2-r5}" __ // load d
      "subs       r0, #64" __ // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "ldm        r0!, {r6, r7}" __
      "adcs       r4, r6" __
      "adcs       r5, r7" __
      "movs       r6, #0" __
      "adc        r6, r6, r5, lsr #31" __
      "adc        r6, #0" __
      "bic        r5, #0x80000000" __
      "adds       r2, r6" __
      "adcs       r3, #0" __
      "adcs       r4, #0" __
      "adcs       r5, #0" __
      "adds       r0, #32" __ // pointer to r[3]
      "stm        r0!, {r2-r5}" __

      "subs       r0, #48" __ // pointer to r[1]
      "ldm        r0!, {r2-r5}" __
      "adds       r2, r8" __
      "adcs       r3, r9" __
      "adcs       r4, r12" __
      "adcs       r5, lr" __
      "movs       r6, #0" __
      "adc        r6, r6, r5, lsr #31" __
      "adc        r6, #0" __
      "bic        r5, #0x80000000" __
      "adds       r2, r6" __
      "adcs       r3, #0" __
      "adcs       r4, #0" __
      "adcs       r5, #0" __
      "subs       r0, #32" __ // pointer to r[0]
      "stm        r0!, {r2-r5}" __

      "ldm        r0, {r2-r5}" __
      "subs       r2, r8" __
      "sbcs       r3, r9" __
      "sbcs       r4, r12" __
      "sbcs       r5, lr" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "subs       r2, r2, r6, lsl #1" __
      "sbcs       r3, #0" __
      "sbcs       r4, #0" __
      "sbcs       r5, #0" __
      "sbcs       r7, r7" __
      "add        r3, r3, r7, lsl #1" __
      "stm        r0!, {r2-r5}" __
      "pop        {r4-r9, pc}" __
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"

#else
      "push       {r4-r7}" __
      "ldm        r1!, {r2-r5}" __
      "push       {r2-r5}" __
      "ldm        r1!, {r2-r5}" __
      "pop        {r6, r7}" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "pop        {r6, r7}" __
      "adcs       r4, r6" __
      "adcs       r5, r7" __
      "sub        sp, #16" __
      "movs       r6, #0" __
      "adcs       r6, r6" __
      "lsls       r5, #1" __
      "adcs       r6, r6" __
      "lsrs       r5, #1" __
      "movs       r7, #0" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "adcs       r4, r7" __
      "adcs       r5, r7" __
      "stm        r0!, {r2-r5}" __ // a[0]+a[1]

      "subs       r1, #16" __ // restore pointer
      "ldm        r1!, {r2-r5}" __
      "pop        {r6, r7}" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "pop        {r6, r7}" __
      "sbcs       r4, r6" __
      "sbcs       r5, r7" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "lsls       r6, #1" __
      "movs       r7, #0" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "sbcs       r4, r7" __
      "sbcs       r5, r7" __
      "sbcs       r7, r7" __
      "lsls       r7, #1" __
      "adds       r3, r7" __
      "stm        r0!, {r2-r5}" __ // a[1]-a[0]

      "ldm        r1!, {r2-r7}" __ // a[2] & a[3] lower 2 in r6, r7
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "ldm        r1!, {r6, r7}" __ // a[3] upper two words
      "adcs       r4, r6" __
      "adcs       r5, r7" __
      "movs       r6, #0" __
      "adcs       r6, r6" __
      "lsls       r5, #1" __
      "adcs       r6, r6" __
      "lsrs       r5, #1" __
      "movs       r7, #0" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "adcs       r4, r7" __
      "adcs       r5, r7" __
      "push       {r2-r5}" __ // store for later

      "subs       r1, #32" __ // restore pointer
      "ldm        r1!, {r2-r7}" __ // a[2] & a[3] lower 2 in r6, r7
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "ldm        r1!, {r6, r7}" __ // a[3] upper two words
      "sbcs       r4, r6" __
      "sbcs       r5, r7" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "lsls       r6, #1" __
      "movs       r7, #0" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "sbcs       r4, r7" __
      "sbcs       r5, r7" __
      "sbcs       r7, r7" __
      "lsls       r7, #1" __
      "adds       r3, r7" __
      "adds       r0, #16" __
      "stm        r0!, {r2-r5}" __

      // c = a[1]+a[0] in r[0]
      // a = a[1]-a[0] in r[1]
      // b = a[2]+a[3] in [r8, r9, r12, lr]
      // d = a[2]-a[3] in [r2, r3, r4, r5] and r[3]

      "subs       r0, #64" __ // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "ldm        r0!, {r6, r7}" __
      "sbcs       r4, r6" __
      "sbcs       r5, r7" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "lsls       r6, #1" __
      "movs       r7, #0" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "sbcs       r4, r7" __
      "sbcs       r5, r7" __
      "sbcs       r7, r7" __
      "lsls       r7, #1" __
      "adds       r3, r7" __
      "adds       r0, #16" __ // pointer to r[2]
      "stm        r0!, {r2-r5}" __

      "ldm        r0!, {r2-r5}" __ // load d
      "subs       r0, #64" __ // restore pointer to c in r[0]
      "ldm        r0!, {r6, r7}" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "ldm        r0!, {r6, r7}" __
      "adcs       r4, r6" __
      "adcs       r5, r7" __
      "movs       r6, #0" __
      "adcs       r6, r6" __
      "lsls       r5, #1" __
      "adcs       r6, r6" __
      "lsrs       r5, #1" __
      "movs       r7, #0" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "adcs       r4, r7" __
      "adcs       r5, r7" __
      "adds       r0, #32" __ // pointer to r[3]
      "stm        r0!, {r2-r5}" __

      "subs       r0, #48" __ // pointer to r[1]
      "ldm        r0!, {r2-r5}" __
      "pop        {r6, r7}" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "pop        {r6, r7}" __
      "adcs       r4, r6" __
      "adcs       r5, r7" __
      "sub        sp, #16" __
      "movs       r6, #0" __
      "adcs       r6, r6" __
      "lsls       r5, #1" __
      "adcs       r6, r6" __
      "lsrs       r5, #1" __
      "movs       r7, #0" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "adcs       r4, r7" __
      "adcs       r5, r7" __
      "subs       r0, #32" __ // pointer to r[0]
      "stm        r0!, {r2-r5}" __

      "ldm        r0!, {r2-r5}" __
      "pop        {r6, r7}" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "pop        {r6, r7}" __
      "sbcs       r4, r6" __
      "sbcs       r5, r7" __
      "sbcs       r6, r6" __
      "rsbs       r6, #0" __
      "lsls       r6, #1" __
      "movs       r7, #0" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "sbcs       r4, r7" __
      "sbcs       r5, r7" __
      "sbcs       r7, r7" __
      "lsls       r7, #1" __
      "adds       r3, r7" __
      "subs       r0, #16" __
      "stm        r0!, {r2-r5}" __
      "pop        {r4-r7}" __
      "bx         lr" __
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
      ".syntax unified" __
#ifdef __thumb2__
      "push       {r4-r7, lr}" __
      "ldm        r1, {r2-r7, r12, lr}" __
      "movs       r1, #0" __
      "adds       r6, r6" __
      "adcs       r7, r7" __
      "adcs       r12, r12" __
      "adcs       lr, lr" __
      "adcs       r1, r1" __
      "adds       r5, lr" __
      "adcs       r1, #0" __
      "lsls       r5, #1" __
      "adcs       r1, r1" __
      "lsrs       r5, #1" __
      "adds       r2, r6" __
      "adcs       r3, r7" __
      "adcs       r4, r12" __
      "adcs       r5, #0" __
      "adds       r2, r1" __
      "adcs       r3, #0" __
      "adcs       r4, #0" __
      "adcs       r5, #0" __
      "stm        r0!, {r2-r5}" __
      "pop        {r4-r7, pc}" __
      : : : "r0","r1","r2","r3","r12","lr","cc","memory"

#else
      "push       {r4-r7, lr}" __
      "ldm        r1!, {r4-r7}" __  // lower half
      "mov        r12, r4" __
      "mov        lr, r5" __
      "ldm        r1!, {r2-r5}" __  // upper half
// First double upper half, save carry into R1
      "movs       r1, #0" __        // for carries
      "adds       r2, r2" __
      "adcs       r3, r3" __
      "adcs       r4, r4" __
      "adcs       r5, r5" __
      "adcs       r1, r1" __        // high-half carry in r1
// Do top word first, to avoid carry later
      "adds       r7, r5" __
      "movs       r5, #0" __
      "adcs       r1, r5" __        // store carry in R1
      "lsls       r7, #1" __
      "adcs       r1, r1" __        // carry*2 + top bit
      "lsrs       r7, #1" __        // and clear top-bit of low-half
// Now start from bottom again
      "mov        r5, r12" __
      "adds       r5, r2" __
      "mov        r2, lr" __
      "adcs       r2, r3" __
      "adcs       r6, r4" __
      "movs       r3, #0" __
      "adcs       r7, r3" __
// Finally do carry bits
      "adds       r1, r5" __
      "adcs       r2, r3" __
      "adcs       r6, r3" __
      "adcs       r7, r3" __        // cannot overflow
      "stm        r0!, {r1, r2, r6, r7}" __
      "pop        {r4-r7, pc}" __
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
      ".syntax unified" __
      "mov.w      r2, r1" __
      // Thumb-2 MUL is fast enough, use it for SQR too.
      ".thumb_func" __
      // ".global    bigint_mul" __
   "bigint_mul:" __
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
      "push       {r4-r9, lr}" __
      "ldm        r1, {r8-r9, r12, lr}" __
      "ldr        r1, [r2]" __
      "umull      r4, r3, r1, r8" __
      "movs       r5, #0" __
      "umlal      r3, r5, r1, r9" __
      "movs       r6, #0" __
      "umlal      r5, r6, r1, r12" __
      "str        r4, [r0]" __
      "movs       r7, #0" __
      "umlal      r6, r7, r1, lr" __

      "ldr        r1, [r2, #4]" __
      "movs       r4, #0" __
      "umlal      r3, r4, r1, r8" __
      "umaal      r4, r5, r1, r9" __
      "str        r3, [r0, #4]" __
      "umaal      r5, r6, r1, r12" __
      "umaal      r6, r7, r1, lr" __

      "ldr        r1, [r2, #8]" __
      "movs       r3, #0" __
      "umlal      r4, r3, r1, r8" __
      "umaal      r3, r5, r1, r9" __
      "str        r4, [r0, #8]" __
      "umaal      r5, r6, r1, r12" __
      "umaal      r6, r7, r1, lr" __

      "ldr        r1, [r2, #12]" __
      "movs       r4, #0" __
      "umlal      r3, r4, r1, r8" __
      "str        r3, [r0, #12]" __
      "umaal      r4, r5, r1, r9" __
      "str        r4, [r0, #16]" __
      "umaal      r5, r6, r1, r12" __
      "str        r5, [r0, #20]" __
      "umaal      r6, r7, r1, lr" __
      "str        r6, [r0, #24]" __
      "str        r7, [r0, #28]" __
      "pop        {r4-r9, pc}" __
      : : : "r1","r2","r3","r12","lr","cc","memory" // r0 remains

#else
      /*
       * Thumb-2 without UMAAL. uV:181c
       *
       * Translate UMAAL to UMULL and 2 ADD/ADC pairs. slightly better than
       * MOV #0, UMLAL and 1 ADD/ADC pair.
       */
      "push       {r4-r11, lr}" __
      "ldm        r1, {r8-r11}" __
      "ldr        r1, [r2]" __
      "umull      r4, r3, r1, r8" __
      "movs       r5, #0" __
      "umlal      r3, r5, r1, r9" __
      "movs       r6, #0" __
      "umlal      r5, r6, r1, r10" __
      "mov        r12, #0" __
      "umlal      r6, r12, r1, r11" __
      "str        r4, [r0], #4" __

      "ldr        r1, [r2, #4]" __
      "movs       r4, #0" __
      "umlal      r3, r4, r1, r8" __
      "umull      r7, lr, r1, r9" __
      "adds       r7, r5" __
      "adc        lr, #0" __
      "adds       r4, r7" __
      "adc        r5, lr, #0" __
      "umull      r7, lr, r1, r10" __
      "adds       r7, r6" __
      "adc        lr, #0" __
      "adds       r5, r7" __
      "adc        r6, lr, #0" __
      "umull      r7, lr, r1, r11" __
      "adds       r7, r12" __
      "adc        lr, #0" __
      "adds       r6, r7" __
      "adc        r12, lr, #0" __
      "str        r3, [r0], #4" __

      "ldr        r1, [r2, #8]" __
      "movs       r3, #0" __
      "umlal      r4, r3, r1, r8" __
      "umull      r7, lr, r1, r9" __
      "adds       r7, r5" __
      "adc        lr, #0" __
      "adds       r3, r7" __
      "adc        r5, lr, #0" __
      "umull      r7, lr, r1, r10" __
      "adds       r7, r6" __
      "adc        lr, #0" __
      "adds       r5, r7" __
      "adc        r6, lr, #0" __
      "umull      r7, lr, r1, r11" __
      "adds       r7, r12" __
      "adc        lr, #0" __
      "adds       r6, r7" __
      "adc        r12, lr, #0" __
      "str        r4, [r0], #4" __

      "ldr        r1, [r2, #12]" __
      "movs       r4, #0" __
      "umlal      r3, r4, r1, r8" __
      "umull      r7, lr, r1, r9" __
      "adds       r7, r5" __
      "adc        lr, #0" __
      "adds       r4, r7" __
      "adc        r5, lr, #0" __
      "umull      r7, lr, r1, r10" __
      "adds       r7, r6" __
      "adc        lr, #0" __
      "adds       r5, r7" __
      "adc        r6, lr, #0" __
      "umull      r7, lr, r1, r11" __
      "adds       r7, r12" __
      "adc        lr, #0" __
      "adds       r6, r7" __
      "adc        r12, lr, #0" __
      "stm        r0, {r3-r6, r12}" __
      "pop        {r4-r11, pc}" __
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
      ".syntax unified" __
      "push       {r4-r7, lr}" __
      "mov        r3, r8" __
      "mov        r4, r9" __
      "mov        r5, r10" __
      "push       {r3-r5}" __
      "mov        lr, r0" __
      "mov        r12, r1" __
      "mov        r10, r2" __
      "ldm        r2!, {r4, r5}" __
      "ldm        r1!, {r2, r3, r6, r7}" __
      // MUL128
      // MUL64
      "mov        r6, r5" __
      "mov        r1, r2" __
      "subs       r5, r4" __
      "sbcs       r0, r0" __
      "eors       r5, r0" __
      "subs       r5, r0" __
      "subs       r1, r3" __
      "sbcs       r7, r7" __
      "eors       r1, r7" __
      "subs       r1, r7" __
      "eors       r7, r0" __
      "mov        r9, r1" __
      "mov        r8, r5" __
// r4xr2->r1:r0 t:r5
      "lsrs       r1, r4, #16" __
      "uxth       r4, r4" __
      "mov        r0, r4" __
      "uxth       r5, r2" __
      "lsrs       r2, #16" __
      "muls       r0, r5" __   //00
      "muls       r5, r1" __   //10
      "muls       r4, r2" __   //01
      "muls       r1, r2" __   //11
      "lsls       r2, r4, #16" __
      "lsrs       r4, #16" __
      "adds       r0, r2" __
      "adcs       r1, r4" __
      "lsls       r2, r5, #16" __
      "lsrs       r4, r5, #16" __
      "adds       r0, r2" __
      "adcs       r1, r4" __
// r6xr3->r3:r2 t:r4,r5
      "lsrs       r4, r6, #16" __
      "uxth       r6, r6" __
      "uxth       r5, r3" __
      "lsrs       r3, r3, #16" __
      "mov        r2, r6" __
      "muls       r2, r5" __
      "muls       r5, r4" __
      "muls       r6, r3" __
      "muls       r3, r4" __
      "lsls       r4, r5, #16" __
      "lsrs       r5, #16" __
      "adds       r2, r4" __
      "adcs       r3, r5" __
      "lsls       r4, r6, #16" __
      "lsrs       r5, r6, #16" __
      "adds       r2, r4" __
      "adcs       r3, r5" __

      "eors       r6, r6" __
      "adds       r2, r1" __
      "adcs       r3, r6" __
      "mov        r1, r9" __
      "mov        r5, r8" __
      "mov        r8, r0" __
// r1xr5->r0:r1 t:r4,r6
      "lsrs       r0, r1, #16" __
      "uxth       r1, r1" __
      "mov        r4, r1" __
      "lsrs       r6, r5, #16" __
      "uxth       r5, r5" __
      "muls       r1, r5" __
      "muls       r4, r6" __
      "muls       r5, r0" __
      "muls       r0, r6" __
      "lsls       r6, r4, #16" __
      "lsrs       r4, #16" __
      "adds       r1, r6" __
      "adcs       r0, r4" __
      "lsls       r6, r5, #16" __
      "lsrs       r5, #16" __
      "adds       r1, r6" __
      "adcs       r0, r5" __

      "eors       r1, r7" __
      "eors       r0, r7" __
      "eors       r4, r4" __
      "asrs       r7, #1" __
      "adcs       r1, r2" __
      "adcs       r2, r0" __
      "adcs       r7, r4" __
      "mov        r0, r8" __
      "adds       r1, r0" __
      "adcs       r2, r3" __
      "adcs       r3, r7" __
// -------------------------
      "mov        r4, lr" __
      "stm        r4!, {r0, r1}" __
      "push       {r4}" __
      "push       {r0, r1}" __
      "mov        r1, r10" __
      "mov        r10, r2" __
      "ldm        r1, {r0, r1, r4, r5}" __
      "mov        r2, r4" __
      "mov        r7, r5" __
      "subs       r2, r0" __
      "sbcs       r7, r1" __
      "sbcs       r6, r6" __
      "eors       r2, r6" __
      "eors       r7, r6" __
      "subs       r2, r6" __
      "sbcs       r7, r6" __
      "push       {r2, r7}" __
      "mov        r2, r12" __
      "mov        r12, r3" __
      "ldm        r2, {r0, r1, r2, r3}" __
      "subs       r0, r2" __
      "sbcs       r1, r3" __
      "sbcs       r7, r7" __
      "eors       r0, r7" __
      "eors       r1, r7" __
      "subs       r0, r7" __
      "sbcs       r1, r7" __
      "eors       r7, r6" __
      "mov        lr, r7" __
      "push       {r0, r1}" __
      // MUL64
      "mov        r6, r5" __
      "mov        r1, r2" __
      "subs       r5, r4" __
      "sbcs       r0, r0" __
      "eors       r5, r0" __
      "subs       r5, r0" __
      "subs       r1, r3" __
      "sbcs       r7, r7" __
      "eors       r1, r7" __
      "subs       r1, r7" __
      "eors       r7, r0" __
      "mov        r9, r1" __
      "mov        r8, r5" __
// r4xr2->r1:r0 t:r5
      "lsrs       r1, r4, #16" __
      "uxth       r4, r4" __
      "mov        r0, r4" __
      "uxth       r5, r2" __
      "lsrs       r2, #16" __
      "muls       r0, r5" __   //00
      "muls       r5, r1" __   //10
      "muls       r4, r2" __   //01
      "muls       r1, r2" __   //11
      "lsls       r2, r4, #16" __
      "lsrs       r4, #16" __
      "adds       r0, r2" __
      "adcs       r1, r4" __
      "lsls       r2, r5, #16" __
      "lsrs       r4, r5, #16" __
      "adds       r0, r2" __
      "adcs       r1, r4" __
// r6xr3->r3:r2 t:r4,r5
      "lsrs       r4, r6, #16" __
      "uxth       r6, r6" __
      "uxth       r5, r3" __
      "lsrs       r3, #16" __
      "mov        r2, r6" __
      "muls       r2, r5" __
      "muls       r5, r4" __
      "muls       r6, r3" __
      "muls       r3, r4" __
      "lsls       r4, r5, #16" __
      "lsrs       r5, #16" __
      "adds       r2, r4" __
      "adcs       r3, r5" __
      "lsls       r4, r6, #16" __
      "lsrs       r5, r6, #16" __
      "adds       r2, r4" __
      "adcs       r3, r5" __

      "eors       r6, r6" __
      "adds       r2, r1" __
      "adcs       r3, r6" __
      "mov        r1, r9" __
      "mov        r5, r8" __
      "mov        r8, r0" __
// r1xr5->r0:r1 t:r0,r6
      "lsrs       r0, r1, #16" __
      "uxth       r1, r1" __
      "mov        r4, r1" __
      "lsrs       r6, r5, #16" __
      "uxth       r5, r5" __
      "muls       r1, r5" __
      "muls       r4, r6" __
      "muls       r5, r0" __
      "muls       r0, r6" __
      "lsls       r6, r4, #16" __
      "lsrs       r4, #16" __
      "adds       r1, r6" __
      "adcs       r0, r4" __
      "lsls       r6, r5, #16" __
      "lsrs       r5, #16" __
      "adds       r1, r6" __
      "adcs       r0, r5" __

      "eors       r1, r7" __
      "eors       r0, r7" __
      "eors       r4, r4" __
      "asrs       r7, #1" __
      "adcs       r1, r2" __
      "adcs       r2, r0" __
      "adcs       r7, r4" __
      "mov        r0, r8" __
      "adds       r1, r0" __
      "adcs       r2, r3" __
      "adcs       r3, r7" __
      "mov        r4, r10" __
      "mov        r5, r12" __
      "eors       r6, r6" __
      "adds       r0, r4" __
      "adcs       r1, r5" __
      "adcs       r2, r6" __
      "adcs       r3, r6" __
      "mov        r10, r2" __
      "mov        r12, r3" __
      "pop        {r2-r5}" __
      "push       {r0, r1}" __
      "mov        r6, r5" __
      "mov        r1, r2" __
      "subs       r5, r4" __
      "sbcs       r0, r0" __
      "eors       r5, r0" __
      "subs       r5, r0" __
      "subs       r1, r3" __
      "sbcs       r7, r7" __
      "eors       r1, r7" __
      "subs       r1, r7" __
      "eors       r7, r0" __
      "mov        r9, r1" __
      "mov        r8, r5" __
// r4xr2->r1:r0 t:r1,r5
      "lsrs       r1, r4, #16" __
      "uxth       r4, r4" __
      "mov        r0, r4" __
      "uxth       r5, r2" __
      "lsrs       r2, #16" __
      "muls       r0, r5" __   //00
      "muls       r5, r1" __   //10
      "muls       r4, r2" __   //01
      "muls       r1, r2" __   //11
      "lsls       r2, r4, #16" __
      "lsrs       r4, #16" __
      "adds       r0, r2" __
      "adcs       r1, r4" __
      "lsls       r2, r5, #16" __
      "lsrs       r4, r5, #16" __
      "adds       r0, r2" __
      "adcs       r1, r4" __
// r6xr3->r3:r2 t:r4,r5
      "lsrs       r4, r6, #16" __
      "uxth       r6, r6" __
      "uxth       r5, r3" __
      "lsrs       r3, #16" __
      "mov        r2, r6" __
      "muls       r2, r5" __
      "muls       r5, r4" __
      "muls       r6, r3" __
      "muls       r3, r4" __
      "lsls       r4, r5, #16" __
      "lsrs       r5, #16" __
      "adds       r2, r4" __
      "adcs       r3, r5" __
      "lsls       r4, r6, #16" __
      "lsrs       r5, r6, #16" __
      "adds       r2, r4" __
      "adcs       r3, r5" __

      "eors       r6, r6" __
      "adds       r2, r1" __
      "adcs       r3, r6" __
      "mov        r1, r9" __
      "mov        r5, r8" __
      "mov        r8, r0" __
// r1xr5->r0:r1 t:r4,r6
      "lsrs       r0, r1, #16" __
      "uxth       r1, r1" __
      "mov        r4, r1" __
      "lsrs       r6, r5, #16" __
      "uxth       r5, r5" __
      "muls       r1, r5" __
      "muls       r4, r6" __
      "muls       r5, r0" __
      "muls       r0, r6" __
      "lsls       r6, r4, #16" __
      "lsrs       r4, #16" __
      "adds       r1, r6" __
      "adcs       r0, r4" __
      "lsls       r6, r5, #16" __
      "lsrs       r5, #16" __
      "adds       r1, r6" __
      "adcs       r0, r5" __

      "eors       r1, r7" __
      "eors       r0, r7" __
      "eors       r4, r4" __
      "asrs       r7, #1" __
      "adcs       r1, r2" __
      "adcs       r2, r0" __
      "adcs       r7, r4" __
      "mov        r0, r8" __
      "adds       r1, r0" __
      "adcs       r2, r3" __
      "adcs       r3, r7" __
      "pop        {r4, r5}" __
      "mov        r6, lr" __
      "mov        r7, lr" __
      "eors       r0, r6" __
      "eors       r1, r6" __
      "eors       r2, r6" __
      "eors       r3, r6" __
      "asrs       r6, #1" __
      "adcs       r0, r4" __
      "adcs       r1, r5" __
      "adcs       r4, r2" __
      "adcs       r5, r3" __
      "eors       r2, r2" __
      "adcs       r6, r2" __
      "adcs       r7, r2" __
      "pop        {r2, r3}" __
      "mov        r8, r2" __
      "mov        r9, r3" __
      "adds       r2, r0" __
      "adcs       r3, r1" __
      "mov        r0, r10" __
      "mov        r1, r12" __
      "adcs       r4, r0" __
      "adcs       r5, r1" __
      "adcs       r6, r0" __
      "adcs       r7, r1" __
      // MUL128 END
      "pop        {r0}" __
      "stm        r0!, {r2-r7}" __
      "pop        {r3-r5}" __
      "mov        r8, r3" __
      "mov        r9, r4" __
      "mov        r10, r5" __
      "pop        {r4-r7, pc}" __
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
      ".syntax unified" __
      // sqr 256 Refined Karatsuba
      "push       {r4-r7, lr}" __
      "mov        r3, r8" __
      "mov        r4, r9" __
      "mov        r5, r10" __
      "mov        r6, r11" __
      "push       {r3-r6}" __
      "mov        lr, r0" __
      "ldm        r1!, {r4-r7}" __
      // sqr 128 Refined Karatsuba.
      // Input in r4..r7, result in r0..r7, clobbers all except r14.
      "mov        r0, r4" __
      "mov        r1, r5" __
      "subs       r0, r6" __
      "sbcs       r1, r7" __
      "sbcs       r2, r2" __
      "eors       r0, r2" __
      "eors       r1, r2" __
      "subs       r0, r2" __
      "sbcs       r1, r2" __
      "mov        r8, r0" __
      "mov        r9, r1" __
      "mov        r10, r6" __
      // sqr 64 Refined Karatsuba.
      // Input in r4,r5, result in r0-r3, clobbers: r4-r6
      // START: sqr 32
      // Input in r4, result in r0 ,r1, clobbers: r2, r3
      "uxth       r0, r4" __
      "lsrs       r1, r4, #16" __
      "mov        r2, r0" __
      "muls       r2, r1" __
      "muls       r0, r0" __
      "muls       r1, r1" __
      "lsrs       r3, r2, #15" __
      "lsls       r2, r2, #17" __
      "adds       r0, r2" __
      "adcs       r1, r3" __
      // End: sqr 32, result in r0 ,r1
      "subs       r4, r5" __
      "sbcs       r6, r6" __
      "eors       r4, r6" __
      "subs       r4, r6" __
      // START: sqr 32
      // Input in r5, result in r2 ,r3, clobbers: r5, r6
      "uxth       r2, r5" __
      "lsrs       r3, r5, #16" __
      "mov        r5, r2" __
      "muls       r5, r3" __
      "muls       r2, r2" __
      "muls       r3, r3" __
      "lsrs       r6, r5, #15" __
      "lsls       r5, #17" __
      "adds       r2, r5" __
      "adcs       r3, r6" __
      // End: sqr 32, result in r2 ,r3
      "movs       r6, #0" __
      "adds       r2, r1" __
      "adcs       r3, r6" __
      // START: sqr 32
      // Input in r4, result in r4 ,r5, clobbers: r1, r6
      "lsrs       r5, r4, #16" __
      "uxth       r4, r4" __
      "mov        r1, r4" __
      "muls       r1, r5" __
      "muls       r4, r4" __
      "muls       r5, r5" __
      "lsrs       r6, r1, #15" __
      "lsls       r1, #17" __
      "adds       r4, r1" __
      "adcs       r5, r6" __
      // End: sqr 32, result in r4 ,r5
      "mov        r1, r2" __
      "subs       r1, r4" __
      "sbcs       r2, r5" __
      "mov        r5, r3" __
      "movs       r6, #0" __
      "sbcs       r3, r6" __
      "adds       r1, r0" __
      "adcs       r2, r5" __
      "adcs       r3, r6" __
      // END: sqr 64 Refined Karatsuba
      // Result in r0,r1,r2,r3, leaves r6 zero.
      "mov        r6, r10" __
      "mov        r10, r0" __
      "mov        r11, r1" __
      "mov        r12, r2" __
      "mov        r1, r3" __
      // sqr 64 Refined Karatsuba
      // Input in r6,r7, result in r2-r5, clobbers: r0, r7, r6
      // START: sqr 32
      // Input in r6, result in r2 ,r3, clobbers: r4, r5
      "uxth       r2, r6" __
      "lsrs       r3, r6, #16" __
      "mov        r4, r2" __
      "muls       r4, r3" __
      "muls       r2, r2" __
      "muls       r3, r3" __
      "lsrs       r5, r4, #15" __
      "lsls       r4, #17" __
      "adds       r2, r4" __
      "adcs       r3, r5" __
      // End: sqr 32, result in r2 ,r3
      "subs       r6, r7" __
      "sbcs       r4, r4" __
      "eors       r6, r4" __
      "subs       r6, r4" __
      // START: sqr 32
      // Input in r7, result in r4 ,r5, clobbers: r0, r7
      "uxth       r4, r7" __
      "lsrs       r5, r7, #16" __
      "mov        r0, r4" __
      "muls       r0, r5" __
      "muls       r4, r4" __
      "muls       r5, r5" __
      "lsrs       r7, r0, #15" __
      "lsls       r0, #17" __
      "adds       r4, r0" __
      "adcs       r5, r7" __
      // End: sqr 32, result in r4 ,r5
      "movs       r7, #0" __
      "adds       r4, r3" __
      "adcs       r5, r7" __
      // START: sqr 32
      // Input in r6, result in r7 ,r0, clobbers: r6, r3
      "uxth       r7, r6" __
      "lsrs       r0, r6, #16" __
      "mov        r6, r7" __
      "muls       r6, r0" __
      "muls       r7, r7" __
      "muls       r0, r0" __
      "lsrs       r3, r6, #15" __
      "lsls       r6, #17" __
      "adds       r7, r6" __
      "adcs       r0, r3" __
      // End: sqr 32, result in r7 ,r0
      "mov        r3, r4" __
      "subs       r3, r7" __
      "sbcs       r4, r0" __
      "mov        r0, r5" __
      "movs       r6, #0" __
      "sbcs       r5, r6" __
      "adds       r3, r2" __
      "adcs       r4, r0" __
      "adcs       r5, r6" __
      // END: sqr 64 Refined Karatsuba
      // Result in r2, r3, r4, r5, leaves r6 zero.
      "mov        r0, r12" __
      "adds       r2, r0" __
      "adcs       r3, r1" __
      "adcs       r4, r6" __
      "adcs       r5, r6" __
      "mov        r12, r2" __
      "mov        r2, r8" __
      "mov        r8, r3" __
      "mov        r3, r9" __
      "mov        r9, r4" __
      // START: sqr 64 Refined Karatsuba
      // Input in r2,r3, result in r6, r7, r0, r1, clobbers: r2, r3, r4
      // START: sqr 32
      // Input in r2. result in r6 ,r7, clobbers: r0, r1
      "uxth       r6, r2" __
      "lsrs       r7, r2, #16" __
      "mov        r0, r6" __
      "muls       r0, r7" __
      "muls       r6, r6" __
      "muls       r7, r7" __
      "lsrs       r1, r0, #15" __
      "lsls       r0, #17" __
      "adds       r6, r0" __
      "adcs       r7, r1" __
      // End: sqr 32
      // Result in r6 ,r7
      "subs       r2, r3" __
      "sbcs       r4, r4" __
      "eors       r2, r4" __
      "subs       r2, r4" __
      // START: sqr 32
      // Input in r3, result in r0, r1, clobbers: r3, r4
      "uxth       r0, r3" __
      "lsrs       r1, r3, #16" __
      "mov        r3, r0" __
      "muls       r3, r1" __
      "muls       r0, r0" __
      "muls       r1, r1" __
      "lsrs       r4, r3, #15" __
      "lsls       r3, #17" __
      "adds       r0, r3" __
      "adcs       r1, r4" __
      // End: sqr 32, result in r0 ,r1
      "movs       r4, #0" __
      "adds       r0, r7" __
      "adcs       r1, r4" __
      // START: sqr 32
      // Input in r2, result in r3, r4, clobbers: r2, r7
      "uxth       r3, r2" __
      "lsrs       r4, r2, #16" __
      "mov        r2, r3" __
      "muls       r2, r4" __
      "muls       r3, r3" __
      "muls       r4, r4" __
      "lsrs       r7, r2, #15" __
      "lsls       r2, #17" __
      "adds       r3, r2" __
      "adcs       r4, r7" __
      // End: sqr 32, result in r3, r4
      "mov        r7, r0" __
      "subs       r7, r3" __
      "sbcs       r0, r4" __
      "mov        r2, r1" __
      "movs       r4, #0" __
      "sbcs       r1, r4" __
      "adds       r7, r6" __
      "adcs       r0, r2" __
      "adcs       r1, r4" __
      // END: sqr 64 Refined Karatsuba
      // Result in r6, r7, r0, r1, returns r4 as zero.
      "mov        r2, r12" __
      "mov        r3, r8" __
      "mov        r4, r9" __
      "subs       r2, r6" __
      "sbcs       r3, r7" __
      "mov        r6, r4" __
      "mov        r7, r5" __
      "sbcs       r4, r0" __
      "sbcs       r5, r1" __
      "movs       r0, #0" __
      "sbcs       r6, r0" __
      "sbcs       r7, r0" __
      "mov        r0, r10" __
      "adds       r2, r0" __
      "mov        r1, r11" __
      "adcs       r3, r1" __
      "mov        r0, r12" __
      "adcs       r4, r0" __
      "mov        r0, r8" __
      "adcs       r5, r0" __
      "movs       r0, #0" __
      "adcs       r6, r0" __
      "adcs       r7, r0" __
      "mov        r0, r10" __
      // END: sqr 128 Refined Karatsuba
      "mov        r8, r7" __
      "mov        r7, lr" __
      "stm        r7!, {r0-r6}" __
      "mov        r6, r8" __
      "stm        r7!, {r6}" __
      "pop        {r3-r6}" __
      "mov        r8, r3" __
      "mov        r9, r4" __
      "mov        r10, r5" __
      "mov        r11, r6" __
      "pop        {r4-r7, pc}" __
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
