/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
   /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
   char * number_str = BN_bn2hex(a);
   printf("%s %s\n", msg, number_str);
   OPENSSL_free(number_str);
}

void privKey(BIGNUM *pkey){

  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *phin = BN_new();
  BIGNUM *one = BN_new();
  BIGNUM *po = BN_new();
  BIGNUM *qo = BN_new();

  BN_hex2bn(&one, "1");
  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  BIGNUM *n = BN_new();

  BN_mul(n, p, q, ctx);

  BN_sub(po, p, one);
  BN_sub(qo, q, one);
  BN_mul(phin, po, qo, ctx);

  BN_mod_inverse(pkey, e, phin, ctx);


}

int main ()
{
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *res = BN_new();


  // Initialize a, b, n
  // BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
  BN_hex2bn(&a, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
  BN_hex2bn(&b, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  //BN_rand(n, NBITS, 0, 0);

  // res = a*b
  BN_mul(res, a, b, ctx);
  printBN("a * b = ", res);

  // res = a^b mod n
  BN_mod_exp(res, a, b, n, ctx);
  printBN("a^b mod n = ", res);

  BIGNUM *pkey = BN_new();
  privKey(pkey);
  printBN("Private key:", pkey);

  return 0;
}