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

void privKey(BIGNUM *pkey)
{
  BN_CTX *ctx = BN_CTX_new(); // Structure to hold BIGNUM temporary variables
  BIGNUM *p = BN_new();       // first prime, p
  BIGNUM *q = BN_new();       // second prime, q
  BIGNUM *e = BN_new();       // public exponent, e
  BIGNUM *phin = BN_new();    // phi of n, φ(n)
  BIGNUM *one = BN_new();     // the integer, 1
  BIGNUM *po = BN_new();      // (p - 1)
  BIGNUM *qo = BN_new();      // (q - 1)

  // Assign values
  BN_hex2bn(&one, "1");
  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  BN_sub(po, p, one);         // (p - 1)
  BN_sub(qo, q, one);         // (q - 1)
  BN_mul(phin, po, qo, ctx);  // φ(n) = (p - 1)(q - 1)
  BN_mod_inverse(pkey, e, phin, ctx);   // find a private key s.t. (such that) d * e ≡ 1 (mod φ(n))
}

void encryptMSG(BIGNUM *msg)
{
  BN_CTX *ctx = BN_CTX_new();    // Structure to hold BIGNUM temporary variables
  BIGNUM *CIPHERTEXT = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new();
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  // ENCRYPTION:To encrypt the message, calculate (msg)^(e) (mod n). The result is the desired ciphertext.
  BN_mod_exp(CIPHERTEXT, msg, e, n, ctx);     // (msg)^(e) (mod n)
  printBN("Encrypted message: ", CIPHERTEXT);
}

void decryptMSG(BIGNUM *C)
{
  BN_CTX *ctx = BN_CTX_new(); // Structure to hold BIGNUM temporary variables
  BIGNUM *PLAINTEXT = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new(); 
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  // DECRYPTION: To decrypt the message, calculate (C)^(d) (mod n). The result is the desired plaintext, albeit in hex format. Encode the result hex plaintext to UTF-8 to get a human-readable plaintext.
  BN_mod_exp(PLAINTEXT, C, d, n, ctx);
  printBN("Decrypted message: ", PLAINTEXT);  // Password is dees
}

void signMSG(BIGNUM *msg)
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *SIGNED_MSG = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new();
  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  // Signing a message: calculate (msg)^(d) (mod n).
  BN_mod_exp(SIGNED_MSG, msg, d, n, ctx); 
  printBN("Signed message: ", SIGNED_MSG);
}

void verifySIGN(BIGNUM *sign)
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *ORIG_MSG = BN_new();
  BIGNUM *X = BN_new();
  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&ORIG_MSG, "4c61756e63682061206d697373696c652e");

  // Verifying a signature: calculate (sign)^(e) (mod n).
  BN_mod_exp(X, sign, e, n, ctx); 
  printBN("Verification: ", X);
  printBN("Original message: ", ORIG_MSG);
  if (BN_cmp(X, ORIG_MSG) == 0) {
    printf("%s\n", "Signatures match together.");
  } else {
    printf("%s\n", "Signature DO NOT MATCH!");
  }
}

int main ()
{
  // BN_CTX *ctx = BN_CTX_new();

  // BIGNUM *a = BN_new();
  // BIGNUM *b = BN_new();
  // BIGNUM *n = BN_new();
  // BIGNUM *res = BN_new();


  // // Initialize a, b, n
  // // BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
  // BN_hex2bn(&a, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
  // BN_hex2bn(&b, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  // BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  // //BN_rand(n, NBITS, 0, 0);

  // // res = a*b
  // BN_mul(res, a, b, ctx);
  // printBN("a * b = ", res);

  // // res = a^b mod n
  // BN_mod_exp(res, a, b, n, ctx);
  // printBN("a^b mod n = ", res);

  BIGNUM *pkey = BN_new();
  
  BIGNUM *msg = BN_new();
  // "A top secret!"
  // BN_hex2bn(&msg, "4120746f702073656372657421");
  // "I owe you $2000."
  // BN_hex2bn(&msg, "49206f776520796f752024323030302e");
  // "I owe you $3000."
  BN_hex2bn(&msg, "49206f776520796f752024333030302e");
  
  BIGNUM *C = BN_new();
  BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

  BIGNUM *S = BN_new();
  // BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
  BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  privKey(pkey);
  // printBN("Private key:", pkey);
  // encryptMSG(msg);
  // decryptMSG(C);
  // signMSG(msg);
  verifySIGN(S);

  return 0;
}