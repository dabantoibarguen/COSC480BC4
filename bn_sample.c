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
  BN_hex2bn(&n, "BB021528CCF6A094D30F12EC8D5592C3F882F199A67A4288A75D26AAB52BB9C54CB1AF8E6BF975C8A3D70F4794145535578C9EA8A23919F5823C42A94E6EF53BC32EDB8DC0B05CF35938E7EDCF69F05A0B1BBEC094242587FA3771B313E71CACE19BEFDBE43B45524596A9C153CE34C852EEB5AEED8FDE6070E2A554ABB66D0E97A540346B2BD3BC66EB66347CFA6B8B8F572999F830175DBA726FFB81C5ADD286583D17C7E709BBF12BF786DCC1DA715DD446E3CCAD25C188BC60677566B3F118F7A25CE653FF3A88B647A5FF1318EA9809773F9D53F9CF01E5F5A6701714AF63A4FF99B3939DDC53A706FE48851DA169AE2575BB13CC5203F5ED51A18BDB15");
  BN_hex2bn(&e, "010001"); // Task 6
  //BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); // Task 5
  //BN_hex2bn(&e, "010001"); // Task 5
  //BN_hex2bn(&ORIG_MSG, "4c61756e63682061206d697373696c652e"); // Task 5
  BN_hex2bn(&ORIG_MSG, "37beee1b8af243cf5cc7666a66e56623480a09731206cfd8d28d1e9f70f8d6963dcc4511685ce85f68564c666f182035cca78e8d16aead6eca0a65a2ae92900acd9acc73b60cb037d4866ed4a454afb17a62ccb895016cf635719269c34222f56227608df59585058d67cdccac61587cb4ca997def664bcae1fb0e2269a9946261d8d748fb21e2ceb081e621316162a0f1f9c28286cedffb618f691f9f6b7e6dcd7cad3abf36b6884721dc8698db981ea429e8ee4b1de9618d9ab9209e0900d30d58098370dfde98f3176b5ed9af11350f635e7ef3883777ddb1da1c6f6e4274c965fc44e8b66958e4862923a8542dad25ba80a2d70d759acf7376209185549c"); // Task 6

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
  // Password is dees
  //BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
  // A top secret!
  BN_hex2bn(&C, "6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC");

  BIGNUM *S = BN_new();
  //BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"); // Task 5

  BN_hex2bn(&S, "8de1edea3a0e213af1d32ed648f3f828447eb8ac24168c45541f5069aa1917b6"); // Task 6

  //BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  // A top secret!
  //privKey(pkey);
  // printBN("Private key:", pkey);
  // encryptMSG(msg);
  //decryptMSG(C);
  // signMSG(msg);
  verifySIGN(S);

  return 0;
}