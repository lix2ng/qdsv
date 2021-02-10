/*
 * main.c
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "supp.h"
#include "qdsv.h"

void dump_bytes(const char *title, uint8_t *b, uint n)
{
   printf("%s:\n", title);
   for (int i = 0; i < n; i++) {
      printf("0x%02x, ", b[i]);
      if (i % 8 == 7) printf("\n");
   }
   if (n % 8) printf("\n");
}

uint8_t _align4 seed[32];
uint8_t _align4 pk[32];
uint8_t _align4 sk[64];
uint8_t _align4 msg[32];
uint8_t _align4 sig[64];

int devrand;

int test_sign_verify()
{
   int n = read(devrand, seed, 32);
   n += read(devrand, msg, 32);
   qdsa_keypair(pk, sk, seed);
   qdsa_sign(sig, msg, pk, sk);
   return qdsa_verify(sig, pk, msg);
}

int main(void)
{
   devrand = open("/dev/random", O_RDONLY);
   if (devrand < 0) {
      printf("Can't open /dev/random\n");
      return -1;
   }

   printf("Sign-verify test with random seeds and messages:\n");

   for (int i = 0; i < 10; i++) {
      if (test_sign_verify() == 0) {
         printf("Pass %d\n", i + 1);
      } else {
         printf("Fail!\n");
         dump_bytes("seed", seed, 32);
         dump_bytes("msg", msg, 32);
         break;
      }
   }
   close(devrand);
   return 0;
}

/* vim: set syn=c cin et sw=3 ts=3 tw=80 fo=cjMmnoqr: */
