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
	//for more details look in each file taskx.c
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *t = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *res = BN_new();
	BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *S = BN_new();
	BIGNUM *message = BN_new(); //message
	BIGNUM *key1 = BN_new(); //first public key
	BIGNUM *key2 = BN_new(); //second public key
	BIGNUM *cipher = BN_new(); //Cipher Text
	BIGNUM *n = BN_new();
	
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
	printf("Good Bye nya~ (◐ω◑ ) \n ===========End Task 1===========\n");
	
	///=============== end task 1 ====================
	
	//initialize/assign values
	BN_hex2bn(&key1, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	//"A toph secret!" : hex--> : 4120746f702073656372657421
	BN_hex2bn(&message, "4120746f702073656372657421"); 
	//return the number's length in hexadecimal or decimal digits
	BN_dec2bn(&key2, "65537");
	//cipher = message ^ key2 mod key1
	BN_mod_exp(cipher, message, key2, key1, ctx);
	printBN("The Cipher Text is : ", cipher);
	printf("Good Bye nya~ (◐ω◑ ) \n ===========End Task 2===========\n");
	//================ end task 2 ======================
	//declare attributes
	
	//initialize/assign values
	BN_hex2bn(&key1, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	//"A toph secret!" : hex--> : 4120746f702073656372657421
	BN_hex2bn(&cipher, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F"); 
	//dec2bn as explained in previous question
	BN_dec2bn(&key2, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	//message = cipher ^ key2 mod key1
	BN_mod_exp(message, cipher, key2, key1, ctx);
	//print out message
	printBN("The Message is : ", message);
	printf("Good Bye nya~ (◐ω◑ ) \n ===========End Task 3===========\n");
	//================ end task 3 ======================
	//message = I owe you $2000 = 49206f776520796f75202432303030
	BN_hex2bn(&message, "49206f776520796f75202432303030");
	//public key
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	//private key d
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	//(this hex value equals to decimal 65537)
	BN_hex2bn(&e, "010001");
	//calculate res = message^d mod n and print it as s
	BN_mod_exp(res, message, d, n, ctx);
	printBN("signature of I owe you $2000 = ", res);
	//message = I owe you $3000 = in hex : 49206f776520796f75202433303030
	BN_hex2bn(&message, "49206f776520796f75202433303030");
	//public key
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	//private key d
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&e, "010001");
	//calculate res = message^d mod n and print it as s
	BN_mod_exp(res, message, d, n, ctx);
	printBN("signature of I owe you $3000 = ", res);

	printf("Good Bye nya~ (◐ω◑ ) \n ===========End Task 4===========\n");
	//=========================== end Task 4 ==============================
	// initialization values

    // assign values
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); //pulic key of alice
    BN_dec2bn(&e, "65537"); //public key of alice
    BN_hex2bn(&M, "4c61756e63682061206d697373696c652e"); //hex encode for " Launch a missile."
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"); //signature

    //get S^e mod: if S=M^d mod n, C=M
    BN_mod_exp(C, S, e, n, ctx);

    // verify the signature
    if (BN_cmp(C, M) == 0) //compare C, M
    {
        printf("0 :Valid Signature! \n"); //signature is valid
    }
    else
    {
        printf("0 :Verification fails! \n"); //signature is not valid
    }
	
	//change 1 character
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); //pulic key of alice
    BN_dec2bn(&e, "65537"); //public key of alice
    BN_hex2bn(&M, "4d61756e63682061206d697373696c652e"); //hex encode for " Launch a missile."
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"); //signature

    //get S^e mod: if S=M^d mod n, C=M
    BN_mod_exp(C, S, e, n, ctx);
	
	  if (BN_cmp(C, M) == 0) //compare C, M
    {
        printf("1 :Valid Signature! \n"); //signature is valid
    }
    else
    {
        printf("1 : Verification fails! \n"); //signature is not valid
    }
	
	//change 1 character
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); //pulic key of alice
    BN_dec2bn(&e, "65537"); //public key of alice
    BN_hex2bn(&M, "4c61756e63682061206d697373696c652d"); //hex encode for " Launch a missile."
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"); //signature

    //get S^e mod: if S=M^d mod n, C=M
    BN_mod_exp(C, S, e, n, ctx);
	
	  if (BN_cmp(C, M) == 0) //compare C, M
    {
        printf("2 : Valid Signature! \n"); //signature is valid
    }
    else
    {
        printf("2 : Verification fails! \n"); //signature is not valid
    }
	
	
    return 0; //end
}