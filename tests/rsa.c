/*
  message m = 123

  P = 61                  <-- 1st prime, keep secret and destroy after generating E and D
  Q = 53                  <-- 2nd prime, keep secret and destroy after generating E and D
  N = P * Q = 3233        <-- modulo factor, give to others

  T = totient(N)          <-- used for key generation
    = (P - 1) * (Q - 1)
    = 3120

  E = 1 < E < totient(N)  <-- public exponent, give to others
  E is chosen to be 17

  find a number D such that ((E * D) / T) % T == 1
  D is chosen to be 2753  <-- private exponent, keep secret


  encrypt(T) = (T ^ E) mod N     where T is the clear-text message
  decrypt(C) = (C ^ D) mod N     where C is the encrypted cipher


  Public key consists of  (N, E)
  Private key consists of (N, D)


  RSA wikipedia example (with small-ish factors):

    public key  : n = 3233, e = 17
    private key : n = 3233, d = 2753
    message     : n = 123

    cipher = (123 ^ 17)   % 3233 = 855
    clear  = (855 ^ 2753) % 3233 = 123  

*/


#include <stdio.h>
#include <string.h> /* for memcpy */
#include "bn.h"

/* O(log n) */
void pow_mod_faster(struct bn* a, struct bn* b, struct bn* n, struct bn* res)
{
  bignum_from_int(res, 1); /* r = 1 */

  struct bn tmpa;
  struct bn tmpb;
  struct bn tmp;
  bignum_assign(&tmpa, a);
  bignum_assign(&tmpb, b);

  while (1)
  {
    if (tmpb.array[0] & 1)     /* if (b % 2) */
    {
      bignum_mul(res, &tmpa, &tmp);  /*   r = r * a % m */
      bignum_mod(&tmp, n, res);
    }
    bignum_rshift(&tmpb, &tmp, 1); /* b /= 2 */
    bignum_assign(&tmpb, &tmp);

    if (bignum_is_zero(&tmpb))
      break;

    bignum_mul(&tmpa, &tmpa, &tmp);
    bignum_mod(&tmp, n, &tmpa);
  }
}

static void test_rsa_1(void)
{
  /* Testing with very small and simple terms */
  char buf[8192];
  struct bn M, C, E, D, N;


  const int p = 11;
  const int q = 13;
  const int n = p * q;
//int t = (p - 1) * (q - 1);
  const int e = 7;
  const int d = 103;
  const int m = 9;
  const int c = 48;
  int m_result, c_result;

  bignum_init(&M);
  bignum_init(&C);
  bignum_init(&D);
  bignum_init(&E);
  bignum_init(&N);

  bignum_from_int(&D, d);
  bignum_from_int(&C, 48);
  bignum_from_int(&N, n);

  printf("\n");

  printf("  Encrypting message m = %d \n", m);
  printf("  %d ^ %d mod %d = %d ? \n", m, e, n, c);
  bignum_from_int(&M, m);
  bignum_from_int(&E, e);
  bignum_from_int(&N, n);
  pow_mod_faster(&M, &E, &N, &C);
  c_result = bignum_to_int(&C);
  bignum_to_string(&C, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", m, e, n, c_result);
  printf("  %d ^ %d mod %d = %s \n", m, e, n, buf);

  printf("\n");

  printf("  Decrypting message c = %d \n", c);
  printf("  %d ^ %d mod %d = %d ? \n", c, d, n, m);
  pow_mod_faster(&C, &D, &N, &M);
  m_result = bignum_to_int(&M);
  bignum_to_string(&M, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", c, d, n, m_result);
  printf("  %d ^ %d mod %d = %s \n", c, d, n, buf);

  printf("\n");
}





void test_rsa_2(void)
{
  char buf[8192];
  struct bn M, C, E, D, N;


  const int p = 61;
  const int q = 53;
  const int n = p * q;
//int t = (p - 1) * (q - 1);
  const int e = 17;
  const int d = 2753;
  const int m = 123;
  const int c = 855;
  int m_result, c_result;

  bignum_init(&M);
  bignum_init(&C);
  bignum_init(&D);
  bignum_init(&E);
  bignum_init(&N);

  bignum_from_int(&D, d);
  bignum_from_int(&C, 1892);
  bignum_from_int(&N, n);

  printf("\n");

  printf("  Encrypting message m = %d \n", m);
  printf("  %d ^ %d mod %d = %d ? \n", m, e, n, c);
  bignum_from_int(&M, m);
  bignum_from_int(&E, e);
  bignum_from_int(&N, n);
  pow_mod_faster(&M, &E, &N, &C);
  c_result = bignum_to_int(&C);
  bignum_to_string(&C, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", m, e, n, c_result);
  printf("  %d ^ %d mod %d = %s \n", m, e, n, buf);

  printf("\n");

  printf("  Decrypting message c = %d \n", c);
  printf("  %d ^ %d mod %d = %d ? \n", c, d, n, m);
  pow_mod_faster(&C, &D, &N, &M);
  m_result = bignum_to_int(&M);
  bignum_to_string(&M, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %s \n", c, d, n, buf);
  printf("  %d ^ %d mod %d = %d \n", c, d, n, m_result);

  printf("\n");
}


void test_rsa_3(void)
{
  char buf[8192];
  struct bn M, C, E, D, N;


  const int p = 2053;
  const int q = 8209;
  const int n = p * q;
//int t = (p - 1) * (q - 1);
  const int e = 17;
  const int d = 2753;
  const int m = 123;
  const int c = 14837949;
  int m_result, c_result;

  bignum_init(&M);
  bignum_init(&C);
  bignum_init(&D);
  bignum_init(&E);
  bignum_init(&N);

  bignum_from_int(&D, d);
  bignum_from_int(&C, c);
  bignum_from_int(&N, n);

  printf("\n");

  printf("  Encrypting message m = %d \n", m);
  printf("  %d ^ %d mod %d = %d ? \n", m, e, n, c);
  bignum_from_int(&M, m);
  bignum_from_int(&E, e);
  bignum_from_int(&N, n);
  pow_mod_faster(&M, &E, &N, &C);
  c_result = bignum_to_int(&C);
  bignum_to_string(&C, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %d \n", m, e, n, c_result);
  printf("  %d ^ %d mod %d = %s \n", m, e, n, buf);

  printf("\n");

  printf("  Decrypting message c = %d \n", c);
  printf("  %d ^ %d mod %d = %d ? \n", c, d, n, m);
  pow_mod_faster(&C, &D, &N, &M);
  m_result = bignum_to_int(&M);
  bignum_to_string(&M, buf, sizeof(buf));
  printf("  %d ^ %d mod %d = %s \n", c, d, n, buf);
  printf("  %d ^ %d mod %d = %d \n", c, d, n, m_result);

  printf("\n");
}




static void test_rsa1024(void)
{
  char public[]  = "F528780A0AA649F0C08D539789175E9972F396AD9E9B6FD00865A7E76F926DB7B150591413C225EBACBA88FFE506BA70114328542C39C7FC357399E3ED120BE0F5827C2E8AD257213D04FCF7479F498C060F67B916CA349821F4548EFDFBDCBF38B747BC60DB197E47A3C586AC1F06BC6E61CAD49A873A463C4CD1BD86A7E2A1";
  char private[] = "DCA98811D9722A87FF7D4F972AB2FD8F1CA83928BE585FA84828A5C5A9A17612E6F24F4FF2F9135C85ACE6BF26A02C3F2D44F8121000BD6C5E69F5AA3F839AAD056CBC739A1A04D4BCC61EC75265360FB86266BE5B5CEE5C1521085982860628DAFE8356725E8835FA53D2F0037DFCCF5F1A2CD8D9D8751716851731A2229603";
  char buf[8192];

  struct bn n; /* public  key */
  struct bn d; /* private key */
  struct bn e; /* public exponent */
  struct bn m; /* clear text message */
  struct bn c; /* cipher text */

  //int len_pub = strlen(public);
  //int len_prv = strlen(private);

  int x = 54321;

  bignum_init(&n);
  bignum_init(&d);
  bignum_init(&e);
  bignum_init(&m);
  bignum_init(&c);

  bignum_from_string(&n, public,  256);
  bignum_from_string(&d, private, 256);
  bignum_from_int(&e, 65537);
  bignum_init(&m);
  bignum_init(&c);

  bignum_from_int(&m, x);
  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);

//printf("  Copied %d bytes into m\n", i);

  printf("  Encrypting number x = %d \n", x);
  pow_mod_faster(&m, &e, &n, &c);
  printf("  Done...\n\n");

  bignum_to_string(&c, buf, sizeof(buf));
  printf("  Decrypting cipher text '");
  int i = 0;
  while (buf[i] != 0)
  {
    printf("%c", buf[i]);
    i += 1;
  }
  printf("'\n");

  /* Clear m */
  bignum_init(&m); 

  pow_mod_faster(&c, &d, &n, &m);
  printf("  Done...\n\n");


  bignum_to_string(&m, buf, sizeof(buf));
  printf("m = %s \n", buf);
}


int main()
{
  printf("\n");
  printf("Testing RSA encryption implemented with bignum. \n");



  test_rsa_1();
  test_rsa_2();
  test_rsa_3();

  test_rsa1024();

  printf("\n");
  printf("\n");



  return 0;
}



#if 0
/* O(n) */
void pow_mod_fast(struct bn* b, struct bn* e, struct bn* m, struct bn* res)
{
/*
  Algorithm in Python / Pseudo-code :

    def pow_mod2(b, e, m):
      if m == 1:
        return 0
      c = 1
      while e > 0:
        c = (c * b) % m
        e -= 1
      return c
*/

  struct bn tmp;
  bignum_from_int(&tmp, 1);

  bignum_init(res); // c = 0

  if (bignum_cmp(&tmp, m) == EQUAL)
  {
    return;  // return 0
  }

  bignum_inc(res); // c = 1

  while (!bignum_is_zero(e))
  {
    bignum_mul(res, b, &tmp);
    bignum_mod(&tmp, m, res);
    bignum_dec(e);
  }
}

void pow_mod_naive(struct bn* b, struct bn* e, struct bn* m, struct bn* res)
{
/*
  Algorithm in Python / Pseudo-Code:

    def pow_mod(b, e, m):
      res = 0
      if m != 1:
        res = 1
        b = b % m
        while e > 0:
          if e & 1:
            res *= b
            res %= m
          e /= 2
          b *= b
          b %= m
      return res
*/ 
  struct bn one;
  bignum_init(&one);
  bignum_inc(&one);

  if (bignum_cmp(&one, m) == EQUAL)      // if m == 1:
  {                                      // {
    bignum_init(res);                    //   return 0
  }                                      // }
  else                                   // else:
  {                                      // {
    struct bn tmp;                       //
    struct bn two;
    bignum_init(&two);
    bignum_inc(&two); bignum_inc(&two);
    bignum_init(res);                    //
    bignum_inc(res);                     //   result = 1
    bignum_mod(b, m, &tmp);              //   b = b % m
    bignum_assign(b, &tmp);              //
                                         //   while e > 0:
    while (!bignum_is_zero(e))           //   {  
    {                                    //
      bignum_and(e, &one, &tmp);         //   
      if (!bignum_is_zero(&tmp))         //     if e & 1:
      {                                  //     {
        bignum_mul(res, b, &tmp);        //
        bignum_assign(res, &tmp);        //       result *= b
        bignum_mod(res, m, &tmp);        //
        bignum_assign(res, &tmp);        //       result %= b
      }                                  //
      bignum_div(e, &two, &tmp);         //     }
      bignum_assign(e, &tmp);            //     e /= 2
      bignum_mul(b, b, &tmp);            //
      bignum_assign(b, &tmp);            //     b *= b
    }                                    //   }
                                         //   return result
  }                                      // }
}
#endif



