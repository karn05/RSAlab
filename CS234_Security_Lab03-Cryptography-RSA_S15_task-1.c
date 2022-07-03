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
int main ()
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *t = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *res = BN_new();
	
	// Assign the first large prime
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	//return the number's length in hexadecimal or decimal digits
	BN_dec2bn(&x, "1");
	//c = p - x
	BN_sub(c, p, x);
	//converts the string str containing a hexadecimal number to a BIGNUM
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	//d = q - x
	BN_sub(d, q, x);
	//converts the string str containing a hexadecimal number to a BIGNUM
	BN_hex2bn(&e, "0D88C3");
	//t = c*d
	BN_mul(t, c, d, ctx);
	printBN("Toilent =", t);
	
	//res = inverse
	BN_mod_inverse(res, e, t, ctx);
	//print private key
	printBN("Private Key is ", res);
	printf("Good Bye nya~ (◐ω◑ )");
	return 0;
}