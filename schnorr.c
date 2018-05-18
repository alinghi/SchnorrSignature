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
 Compiler Option : -lssl
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


#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

 
//When DEBUG and DEV
//#define DEBUG

//Global Variable
DSA* key;
DSA* key_input;


//Function prototype
//mainMenu Function - actual menu selection
char mainMenu(void);

//Sign Function
int sign(void);

//Verify Function
int verify(void);

int hash(void* input, unsigned long length, unsigned char* md);
void hash_test(char* input);
void keygen(void);

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
  	key_input=DSA_new();

  	//generate p,q,g
  	DSA_generate_parameters_ex(key,512,NULL,0,NULL,NULL, NULL);
  	//generate priv_key, pub_key
  	/*
  	#ifdef DEBUG
  	printf("Generate Key Fine?: %d\n",DSA_generate_key(key));
  	printf("\nKey p\n");
  	BN_print_fp(stdout,key->p);
    	printf("\nKey q\n");
  	BN_print_fp(stdout,key->q);
    	printf("\nKey g\n");
  	BN_print_fp(stdout,key->g);
    	printf("\nKey pub_key\n");
  	BN_print_fp(stdout,key->pub_key);
  	printf("\n");
  	#endif
  	*/
  	
	char menu='a';
	menu=mainMenu();
	while(menu!='4')
	{
		if(menu=='1')
		{
			sign();
			
		}
		else if(menu=='2')
		{
			verify();
			

		}
		else if(menu=='3')
		{
			keygen();
		}
		menu=mainMenu();
		/*------Hash Test
			#ifdef DEBUG
			//CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB
			char* q="a";
			hash_test(q);
			#endif
		*/
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
	printf("--------------3. KeyGeneration ---------------------\n");
	printf("--------------4. Exit   ----------------------------\n");	
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

	char string_p[1025];
	char string_q[1025];
	char string_g[1025];
	char string_pub_key[1025];
	char string_priv_key[1025];

	BIGNUM* k=BN_new();
	BN_init(k);
	BIGNUM* r=BN_new();
	BN_init(r);
	BIGNUM* s=BN_new();
	BN_init(s);
	BIGNUM* e=BN_new();
	BN_init(e);
	BIGNUM* temp=BN_new();
	BN_init(temp);

	unsigned char* r_char = malloc((512) * sizeof(char));
	memset(r_char,0,512);
	unsigned char message[90001];
	unsigned char* input;

	//Obtain A's authentic public key
	printf(BLU "\n Input Public Key p: \n" RESET);
	scanf("%s",string_p);
	BN_hex2bn(&(key->p),string_p);
	printf(BLU "\n Input Public Key q: \n" RESET);
	scanf("%s",string_q);
	BN_hex2bn(&(key->q),string_q);
	printf(BLU "\n Input Public Key g: \n" RESET);
	scanf("%s",string_g);
	BN_hex2bn(&(key->g),string_g);
	printf(BLU "\n Input Public Key pub_key: \n" RESET);
	scanf("%s",string_pub_key);
	BN_hex2bn(&(key->pub_key),string_pub_key);
	printf(BLU "\n Input Private Key priv_key: \n" RESET);
	scanf("%s",string_priv_key);
	BN_hex2bn(&(key->priv_key),string_priv_key);

	
	BN_CTX *ctx; //Temporary Variable ctx
	ctx = BN_CTX_new();
	int returnValue=0;

	//Check out
	/*
	#ifdef DEBUG
	printf("sign\n");
	printf("number: %d\n",BN_num_bits(key->q));
	BN_print_fp(stdout,key->p);
	#endif
	*/
	//Select a random secret integer k, 1<=k<=q-1.
	BN_rand_range(k,key->q);
	//OpenSSL man: BN_mod_exp() computes a to the p-th power modulo m (r=a^p % m).
	//OpenSSL man: This function uses less time and space than BN_exp().
	// int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,const BIGNUM *m, BN_CTX *ctx);
	/*-------------------------------------------------------------------------------------------------------------------------------------*/
	//BN_CTX -> temporary variable used by library functions.
	//Book: Compute r=alpha^k mod p, e=h(m||r), and s =ae+k mod q
	BN_mod_exp(r, key->g, k,key->p,ctx);
	
	unsigned char e_hash[SHA256_DIGEST_LENGTH]; 
	printf(BLU "\nInput your message to sign!(length limit 90000)\n" RESET);
	scanf("%s", message);
	printf("Your input: %s\n", message);
	BN_bn2bin(r,r_char);


	// m||r
	input=strcat(message,r_char);
	// h(m||r)
	if(!hash(input, strlen(input), e_hash))
	{
		printf("HASH error");
	}

	//hash digest=>BN e
	BN_bin2bn(e_hash,sizeof(e_hash),e);

	// s=ae+k mod q
		//a * e -> temp
	BN_mod_mul(temp,key->priv_key,e,key->q,ctx);
		//temp + k -> s
	BN_mod_add(s,temp,k,key->q,ctx);
	/*
	struct
	        {
	        BIGNUM *p;              // prime number (public)
	        BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
	        BIGNUM *g;              // generator of subgroup (public)  -> alpha
	        BIGNUM *priv_key;       // private key x -> a
	        BIGNUM *pub_key;        // public key y = g^x -> alpha^a
	        // ...
	        }
	DSA;
	*/
	//A's Signature for m is the pair(s,e)
		/* Get the message */
	printf(BLU "\nSignature pair s : \n" RESET);
	BN_print_fp(stdout,s);
	printf(BLU "\nSignature pair e : \n" RESET);
	BN_print_fp(stdout,e);
	printf("\n\n");
	//return 1 means success
	//return -1 means error
	return returnValue;
}
int verify(void)
{
	int returnValue=0;
	char string_s[1025];
	char string_e[1025];
	char string_p[1025];
	char string_q[1025];
	char string_g[1025];
	char string_pub_key[1025];
	unsigned char* v_char = malloc((512) * sizeof(char));
	memset(v_char,0,512);
	unsigned char message[90001];
	unsigned char* input;

	BIGNUM* v=BN_new();
	BN_init(v);
	BIGNUM* inv_pub_key=BN_new();
	BN_init(inv_pub_key);
	BIGNUM* s=BN_new();
	BN_init(s);
	BIGNUM* e=BN_new();
	BN_init(e);
	BIGNUM* p=BN_new();
	BN_init(p);
	BIGNUM* q=BN_new();
	BN_init(q);
	BIGNUM* g=BN_new();
	BN_init(g);
	BIGNUM* pub_key=BN_new();
	BN_init(pub_key);
	BIGNUM* temp1=BN_new();
	BN_init(temp1);
	BIGNUM* temp2=BN_new();
	BN_init(temp2);
	BIGNUM* e_prime=BN_new();
	BN_init(e_prime);


	BN_CTX *ctx; //Temporary Variable ctx
	ctx = BN_CTX_new();

	// int BN_hex2bn(BIGNUM **a, const char *str);

	//Check out
	#ifdef DEBUG
	printf("verify\n");
	#endif
	//Get signature
	printf(BLU "\n Input Signature pair s: \n" RESET);
	scanf("%s",string_s);
	BN_hex2bn(&s,string_s);
	printf(BLU "\n Input Signature pair e: \n" RESET);
	scanf("%s",string_e);
	BN_hex2bn(&e,string_e);
	//Obtain A's authentic public key
	printf(BLU "\n Input Public Key p: \n" RESET);
	scanf("%s",string_p);
	BN_hex2bn(&p,string_p);
	printf(BLU "\n Input Public Key q: \n" RESET);
	scanf("%s",string_q);
	BN_hex2bn(&q,string_q);
	printf(BLU "\n Input Public Key g: \n" RESET);
	scanf("%s",string_g);
	BN_hex2bn(&g,string_g);
	printf(BLU "\n Input Public Key pub_key: \n" RESET);
	scanf("%s",string_pub_key);
	BN_hex2bn(&pub_key,string_pub_key);


	unsigned char e_hash[SHA256_DIGEST_LENGTH]; 
	//Obtain message
	printf(BLU "\nInput your message to verify!(length limit 90000)\n" RESET);
	scanf("%s", message);
	printf("Your input: %s\n", message);
	//printf("message len %i\n",strlen(message));
	//Compute v=alpha^s y^{-e} mod p and e'=h(m||v)
		//Handbook : alpha^s ->temp1
		//Here : g^s -> temp1
		BN_mod_exp(temp1,g,s,p,ctx);

		//Handbook : y^-e -> temp2
		//Here : inv_pub_key^e -> temp2
			//Calculate inverse of y
			//pub_key -> inv_pub_key
			BN_mod_inverse(inv_pub_key,pub_key,p,ctx);
			//inv_pub_key^e 
			BN_mod_exp(temp2,inv_pub_key,e,p,ctx);
		//temp1 * temp2
		BN_mod_mul(v,temp1,temp2,p,ctx);
		

		BN_bn2bin(v,v_char);
	
	
		//m||v
		input=strcat(message,v_char);
		//h(m||v)
		if(!hash(input, strlen(input), e_hash))
		{
			printf("HASH error");
		}

	//hash digest=>BN e
	BN_bin2bn(e_hash,sizeof(e_hash),e_prime);
	//Accept the signature if and only if e'=e.
	printf(BLU "\nSignature pair e : \n" RESET);
	BN_print_fp(stdout,e);
	printf(BLU "\nSignature pair e_prime: \n" RESET);
	BN_print_fp(stdout,e_prime);
	printf("\n");
	if(BN_cmp(e,e_prime)==0)
	{
		printf(GRN "\n\nValid Signature!\n\n" RESET);
	}
	else
	{
		printf(RED "\n\nInvalid Signature\n\n" RESET);
	}
	//return 0 means false(not accepted - invalid signature)
	//return 1 means true(accepted - valid signature)
	//return -1 means error
	return returnValue;
}

//SHA256
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

void hash_test(char* input)
{
	//input = a
	//hash = CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB
	BIGNUM* ret=BN_new();
	BN_init(ret);
	unsigned char md[SHA256_DIGEST_LENGTH]; 
	//SHA TEST
	printf("strlen : %i\n",strlen(input));
	if(!hash(input, strlen(input), md))
	{
		printf("HASH error");
	}
	else
	{
		printf("Hash: %d\n",md[0]);
		printf("Hash: %d\n",md[1]);
		printf("Hash: %d\n",md[2]);
	}
	BN_bin2bn(md,sizeof(md),ret);
	BN_print_fp(stdout,ret);
	printf("\n");
	printf("--------   Hash Test Done   --------\n");
}

void keygen(void)
{
	printf("Generate Key\n");
  	//generate p,q,g
  	DSA_generate_parameters_ex(key,1024,NULL,0,NULL,NULL, NULL);
  	//generate priv_key, pub_key
  	if(!DSA_generate_key(key))
  	{
  		printf("key generation error");
  		return;
  	}
  	printf(BLU "\nKey p\n" RESET);
  	BN_print_fp(stdout,key->p);
    	printf(BLU "\nKey q\n" RESET);
  	BN_print_fp(stdout,key->q);
    	printf(BLU "\nKey g\n" RESET);
  	BN_print_fp(stdout,key->g);
    	printf(BLU "\nKey pub_key\n" RESET);
  	BN_print_fp(stdout,key->pub_key);
  	printf(BLU "\nKey priv_key\n" RESET);
  	BN_print_fp(stdout,key->priv_key);
  	printf("\n\n");
}