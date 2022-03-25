#pragma once

#include <string>
#include <iostream>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>

typedef struct EncKey {
	ASN1_OCTET_STRING* salt;
	ASN1_OCTET_STRING* nonce;
	ASN1_OCTET_STRING* AESkeyEncrypted;
}EncKey;

typedef struct MY_AES_KEY {
	ASN1_INTEGER* keySize;
	EncKey* encryptedKey;
	ASN1_UTCTIME* from;
	ASN1_UTCTIME* to;
}MY_AES_KEY;

//Class for seed and key generation
class KeyGenerator {
private:
	static unsigned char* ChaChaKey;
	static const int ChaChaKeyLength = 256 / 8;
	static unsigned char* AesKey;
	static int AesKeyLength;
	static unsigned char* AesEncryptionSalt;
	static unsigned char* AesEncryptionIV;
	static int Validity;

	static unsigned char* EncryptUsingPassword(const char* password, int keyLength, int* outLen);
public:
	//Initialization function
	static void Init();

	//Generate seed and key
	static unsigned char* GenerateSeed(int length);
	static unsigned char* GenerateChaChaKeyFromSeed(unsigned char* seed, int seedLen);

	//Generate AES key
	static unsigned char* GenerateAesKey(unsigned char* seed, int seedLen, int bitsSize, int validity);
	
	//Save key in PEM format in file
	static void SaveKeyPEM(const char* filename);
	//Save the AES key in file encrypted using a password
	static MY_AES_KEY* SaveAesKey(const char* filename, const char* password);

	//Load keys from file
	static unsigned char* LoadChaChaKey(const char* filename);
	static unsigned char* LoadAesKey(const char* filename);

	//Check AES key validity
	static bool CheckAesKeyValidity(MY_AES_KEY* myAesKey);

	//Getters
	static unsigned char* GetLastChaChaKey();
	static unsigned char* GetLastAesKey();
	
	//Finalization function
	static void Finalize();
};