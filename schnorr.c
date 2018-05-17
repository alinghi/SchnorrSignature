/*------------------------------------------------------------------------------------------------------------------------------------------------------------
Name : Na, Yun Seok
Student ID: 20176141
KAIST EE817 HW5 Problem 5
Schnorr Signature Implementation
------------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*------------------------------------------------------------------------------------------------------------------------------------------------------------
Build Guide
sudo apt-get install libssl-dev
https://stackoverflow.com/questions/3016956/how-do-i-install-the-openssl-libraries-on-ubuntu
 Compiler Option : -lcrypto
 -lssl
------------------------------------------------------------------------------------------------------------------------------------------------------------*/

//Preprocessor
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

 
//When DEBUG and DEV
#define DEBUG

//Global Variable
DSA* key;


//Function prototype
//mainMenu Function - actual menu selection
char mainMenu(void);

//Sign Function
int sign(void);

//Verify Function
int verify(void);

int hash(void* input, unsigned long length, unsigned char* md);

//Main Function - just do menu selection
int main(void)
{
	*DSA_SIG_new();
	//OPENSSL Check
	//Code from https://wiki.openssl.org/index.php/Libcrypto_API
	/* Load the human readable error strings for libcrypto */
  	ERR_load_crypto_strings();

  	/* Load all digest and cipher algorithms */
  	OpenSSL_add_all_algorithms();

  	/* Load config file, and other important initialisation */
  	OPENSSL_config(NULL);

  	//Version Check
  	#ifdef DEBUG
  	printf("%s\n",SSLeay_version(SSLEAY_VERSION));
  	#endif

  	/* ... Do some crypto stuff here ... */
  	
/*------------------------------------------------------------------------------------------------------------------------------------------------------------
//https://www.openssl.org/docs/man1.0.2/crypto/DSA_generate_parameters_ex.html
DSA_generate_parameters_ex() generates primes p and q and a generator g for use in the DSA and stores the result in dsa.
------------------------------------------------------------------------------------------------------------------------------------------------------------*/
 /*------------------------------------------------------------------------------------------------------------------------------------------------------------
Key Generation for the DSA
SUMMARY: each entity creates a public key and corresponding private key.
Each entity A should do the following
1. Select a prime number q such that 2^159<q<2^160
2. Choose t so that 0<=t<=8, and select a prime number p where 2^{511+64t}<p<2^{512+64t}
, with the porperty that q divides (p-1)
3. (Select a generator alpha of the unique cyclic group of order q in Zp*)
	3.1 Select an element g in Zp* and compute alpha=g^{p-1/q} mod p
	3.2 If alpha = 1 then go to step 3.1.
4. Select a random integer a such that 1<=a<=q-1
5. Compute y=alpha^a mod p
6. A's public key is (p,q,alpha,y); A's private key is a.
------------------------------------------------------------------------------------------------------------------------------------------------------------*/

  	//init
  	key=DSA_new();
  	//generate p,q,g
  	DSA_generate_parameters_ex(key,2048,NULL,0,NULL,NULL, NULL);
  	//generate priv_key, pub_key
  	
/*
struct
        {
        BIGNUM *p;              // prime number (public)
        BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
        BIGNUM *g;              // generator of subgroup (public)
        BIGNUM *priv_key;       // private key x
        BIGNUM *pub_key;        // public key y = g^x
        // ...
        }
DSA;
*/
  	#ifdef DEBUG
  	printf("Generate Key Fine?: %d\n",DSA_generate_key(key));
  	#endif

	char menu='a';
	menu=mainMenu();
	while(menu!='3')
	{
		if(menu=='1')
		{
			sign();
			
		}
		else if(menu=='2')
		{
			verify();

		}
		menu=mainMenu();
	}

  	/* Clean up */

  	/* Removes all digests and ciphers */
  	EVP_cleanup();

  	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  	CRYPTO_cleanup_all_ex_data();

  	/* Remove error strings */
  	ERR_free_strings();
	return 0;
}


//mainMenu Function - actual menu selection
char mainMenu(void)
{
	char select;
	printf("----------------------------------------------------\n");
	printf("--------------Schnorr Signature---------------------\n");
	printf("--------------1. Sign   ----------------------------\n");
	printf("--------------2. Veirfy ----------------------------\n");
	printf("--------------3. Exit   ----------------------------\n");	
	printf("Select the number : \n");
	scanf(" %c",&select);
	return select;
}




/*------------------------------------------------------------------------------------------------------------------------------------------------------------
General Explanation for Schnorr Sign
This technique employs a subgroup of order q in Zp*, where p is some large prime number.
The method also requires a hash function h:{0,1}*->Zq.
Key generation for the Schnorr signature scheme is the same as DSA key generation(Algo 11.54)
,except that there are no constraints on the sizes of p and q.
------------------------------------------------------------------------------------------------------------------------------------------------------------*/

int sign(void)
{
	BIGNUM k;
	BIGNUM r;
	int returnValue=0;
	//Check out
	#ifdef DEBUG
	printf("sign\n");
	printf("number: %d\n",BN_num_bits(key->q));
	BN_print_fp(stdout,key->p);
	#endif

	//Select a random secret integer k, 1<=k<=q-1.
	BN_rand_range(&k,key->q);
	//Compute r=alpha^k mod p, e=h(m||r), and s =ae+k mod q
	//A's Signature for m is the pair(s,e)


	//return 1 means success
	//return -1 means error
	return returnValue;
}
int verify(void)
{
	unsigned char md[SHA256_DIGEST_LENGTH]; 
	char* a="a";

	
	int returnValue=0;
	//Check out
	#ifdef DEBUG
	printf("verify\n");
	#endif
	//Obtain A's authentic public key
	//Compute v=alpha^s y^{-e} mod p and e'=h(m||v)
	//Accept the signature if and only if e'=e.


	//SHA TEST
	#ifdef DEBUG
	printf("strlen : %d\n")
	if(!hash(a, 1, md))
	{
		printf("HASH error");
	}
	else
	{
		printf("Hash: %d\n",md[0]);
		printf("Hash: %d\n",md[1]);
		printf("Hash: %d\n",md[2]);
	}
	#endif

	//return 0 means false(not accepted - invalid signature)
	//return 1 means true(accepted - valid signature)
	//return -1 means error
	return returnValue;
}

int hash(void* input, unsigned long length, unsigned char* md)
{
	SHA256_CTX context;
	if(!SHA256_Init(&context))
		return 0;
	if(!SHA256_Update(&context, (unsigned char*)input, length))
		return 0;
	if(!SHA256_Final(md, &context))
		return 0;
	return 1;
}