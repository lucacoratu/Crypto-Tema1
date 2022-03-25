#define _CRT_SECURE_NO_WARNINGS
#pragma warning	(disable:4996)

#include "KeyGenerator.h"
#include "Utils.h"

#include <time.h>

#include <openssl/rand.h>
#include <openssl/evp.h>

//Structures for aes key sequences
ASN1_SEQUENCE(EncKey) {
	ASN1_SIMPLE(EncKey, salt, ASN1_OCTET_STRING),
	ASN1_SIMPLE(EncKey, nonce, ASN1_OCTET_STRING),
	ASN1_SIMPLE(EncKey, AESkeyEncrypted, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(EncKey);

DECLARE_ASN1_FUNCTIONS(EncKey);
IMPLEMENT_ASN1_FUNCTIONS(EncKey);


ASN1_SEQUENCE(MY_AES_KEY) {
	ASN1_SIMPLE(MY_AES_KEY, keySize, ASN1_INTEGER),
	ASN1_SIMPLE(MY_AES_KEY, encryptedKey, EncKey),
	ASN1_SIMPLE(MY_AES_KEY, from, ASN1_UTCTIME),
	ASN1_SIMPLE(MY_AES_KEY, to, ASN1_UTCTIME)
}ASN1_SEQUENCE_END(MY_AES_KEY);

DECLARE_ASN1_FUNCTIONS(MY_AES_KEY);
IMPLEMENT_ASN1_FUNCTIONS(MY_AES_KEY);
//===================================================================================================

//Define the block size for the key generation algorithm
#define KEYSTREAM_BLOCK_SIZE 9

//Defines for time periods of validity
#define MONTH6 (6 * 30 * 24 * 60 * 60)
#define YEAR (12 * 30 *24 * 60 * 60)
#define YEAR3 (3 * 12 * 30 * 24 * 60 * 60)


//Initialization of the static member variables
unsigned char* KeyGenerator::ChaChaKey = nullptr;
unsigned char* KeyGenerator::AesKey = nullptr;
unsigned char* KeyGenerator::AesEncryptionSalt = nullptr;
unsigned char* KeyGenerator::AesEncryptionIV = nullptr;
int KeyGenerator::AesKeyLength = 0;
int KeyGenerator::Validity = 0;

static unsigned char stateArray[] = { 0,1,2,3,4,5,6,7,8 };

//============================KEY GENERATION ALGORITHM FROM EX5 Lab5=================================
static unsigned char RotateByteRight(unsigned char byte, int count) {
	//Rotates the bits from a byte to the right count times
	if (count <= 0)
		return byte;

	unsigned char copyByte = byte;
	for (int i = 0; i < count; i++) {
		// Get LSB of num before it gets dropped
		unsigned char lastBit = byte & 1;

		byte = (byte >> 1) & (~(1 << 7));

		// Set its dropped LSB as new MSB
		byte = byte | (lastBit << 7);
	}

	return byte;
}

static void RotateArrayLeft(unsigned char** arr, int len, int count) {
	//Rotates the array count times to the left
	for (int i = 0; i < count; i++) {
		unsigned char copy = (*arr)[0];
		for (int j = 0; j < len - 1; j++) {
			(*arr)[j] = (*arr)[j + 1];
		}
		(*arr)[len - 1] = copy;
	}
}

static void InitMyKeystreamCipher(unsigned char* seed, int seedLen) {
	//Initializes the keystream cipher by updating the state array according to the seed given
	int padding = KEYSTREAM_BLOCK_SIZE - seedLen % KEYSTREAM_BLOCK_SIZE;
	int numberBlocks = (seedLen + padding) / KEYSTREAM_BLOCK_SIZE;

	unsigned char* block = new unsigned char[KEYSTREAM_BLOCK_SIZE];
	for (int i = 0; i < numberBlocks - 1; i++) {
		memcpy(block, &seed[i * KEYSTREAM_BLOCK_SIZE], KEYSTREAM_BLOCK_SIZE);
		for (int j = 0; j < KEYSTREAM_BLOCK_SIZE; j++) {
			stateArray[j] ^= block[j];
		}
	}

	memcpy(block, &seed[KEYSTREAM_BLOCK_SIZE * (numberBlocks - 1)], seedLen % KEYSTREAM_BLOCK_SIZE);
	memcpy(&block[seedLen % KEYSTREAM_BLOCK_SIZE], &stateArray[seedLen % KEYSTREAM_BLOCK_SIZE], padding);
	//Add the padding
	while (padding--) {
		unsigned char byte = block[KEYSTREAM_BLOCK_SIZE - padding];
		byte = RotateByteRight(byte, padding);
		byte ^= seed[(padding + seedLen) % seedLen];
		block[KEYSTREAM_BLOCK_SIZE - padding] = byte;
		for (int i = 0; i < KEYSTREAM_BLOCK_SIZE; i++) {
			stateArray[i] ^= block[i];
		}
		RotateArrayLeft(&block, KEYSTREAM_BLOCK_SIZE, padding);
	}
}


static unsigned char* MyKeystreamCipher(unsigned char* seed, int seedLen, int cipherLen) {
	//Generates cipherLen pseudo random bytes based on the seed given
	InitMyKeystreamCipher(seed, seedLen);

	//printf("Initial state:\n");
	//for (int i = 0; i < 3; i++, printf("\n")) {
	//	for (int j = 0; j < 3; j++) {
	//		printf("%.02x ", stateArray[i * 3 + j]);
	//	}
	//}

	unsigned char* stream = new unsigned char[cipherLen];
	if (stream == nullptr)
		return nullptr;

	//For every byte in the stream
	for (int i = 0; i < cipherLen; i++) {
		if (i != 0 && i % KEYSTREAM_BLOCK_SIZE == 0) {
			//Xor the stateArray with the stream generated
			for (int j = 0; j < KEYSTREAM_BLOCK_SIZE; j++) {
				stateArray[j] ^= stream[i - KEYSTREAM_BLOCK_SIZE + j];
			}
		}


		//Rotate column 1 up
		unsigned char aux = stateArray[0];
		stateArray[0] = stateArray[3];
		stateArray[3] = stateArray[6];
		stateArray[6] = aux;


		//Rotate column 2 up 2 times
		for (int j = 0; j < 2; j++) {
			aux = stateArray[1];
			stateArray[1] = stateArray[4];
			stateArray[4] = stateArray[7];
			stateArray[7] = aux;
		}

		//Rotate row 2 right 1 time
		aux = stateArray[5];
		stateArray[5] = stateArray[4];
		stateArray[4] = stateArray[3];
		stateArray[3] = aux;

		//Rotate row 3 right 2 times
		for (int j = 0; j < 2; j++) {
			aux = stateArray[8];
			stateArray[7] = stateArray[6];
			stateArray[8] = stateArray[7];
			stateArray[6] = aux;
		}

		//Take currentByte = i % KEYSTREAM_BLOCK_LENGTH
		unsigned char currentByte = stateArray[i % KEYSTREAM_BLOCK_SIZE];
		//Shift the currentByte left with 2
		currentByte = (currentByte << 1) ^ (seed[i % seedLen] & stateArray[(i + 1) % KEYSTREAM_BLOCK_SIZE]);
		//Add the seed len to the equation
		currentByte ^= (seedLen << (i % 8));
		if (i != 0) {
			currentByte ^= stream[i - 1];
		}

		//Put the value in the stream
		stream[i] = currentByte;
	}

	return stream;
}

//====================================END KEY Generation algorithm====================================

unsigned char* KeyGenerator::EncryptUsingPassword(const char* password, int keyLength, int* outLen)
{
	//Encrypts the password with PBKDF with random salt (of size 4 bytes)
	//keyLength is specified as number of bytes (not number of bits)
	ASSERT(password == nullptr, "Password cannot be null!");
	ASSERT(AesKey == nullptr, "Aes key cannot be null!");

	//Initialize the keys for the 3-Des algorithm
	const int desKeySize = (64 / 8) * 3;
	unsigned char* key1 = new unsigned char[desKeySize];
	ASSERT(key1 == nullptr, "Cannot allocate memory for the keys!");
	memset(key1, 0x01, 8);
	memset(&key1[8],0x55,8);
	memset(&key1[16], 0x00, 8);

	unsigned char* resultKey = new unsigned char[static_cast<long long>(keyLength) + desKeySize];
	ASSERT(resultKey == nullptr, "Cannot allocate memory for the result key!");

	int res = 1;
	int outLenUpdate = -1, outLenFinal = -1;

	//PBKDF
	RAND_bytes(AesEncryptionSalt, 4);

	res = PKCS5_PBKDF2_HMAC(password, strlen(password), AesEncryptionSalt, 4, 4096, EVP_sha1(), keyLength, resultKey);
	ASSERT(res != 1, "PKCS5 function failed!");
	
	RAND_bytes(AesEncryptionIV, 8);

	//Encrypt using 3-DES with the 3 keys defined above
	//Encrypt using key 1
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	res = EVP_EncryptInit(ctx, EVP_des_ede3_ecb(), key1, AesEncryptionIV);
	ASSERT(res != 1, "Evp_EncryptInit failed!");
	res = EVP_EncryptUpdate(ctx, resultKey, &outLenUpdate, resultKey, keyLength);
	ASSERT(res != 1, "Evp_EncryptUpdate failed!");
	res = EVP_EncryptFinal(ctx, &resultKey[outLenUpdate], &outLenFinal);
	ASSERT(res != 1, "EVP_EcnryptFinal failed!");

	//Xor the Aes key with the key generated after PBKDF and 3-DES
	for (int i = 0; i < outLenFinal + outLenUpdate; i++) {
		resultKey[i] ^= AesKey[i % keyLength];
	}

	*outLen = (outLenFinal + outLenUpdate);
	return resultKey;
}

void KeyGenerator::Init()
{
	/*Initialize the memeber variables of the class*/
	ChaChaKey = new unsigned char[ChaChaKeyLength];
	ASSERT(ChaChaKey == nullptr, "Key could not be initialized!");

	AesEncryptionSalt = new unsigned char[4];
	ASSERT(AesEncryptionSalt == nullptr, "Salt memory allocation failed!");

	AesEncryptionIV = new unsigned char[8];
	ASSERT(AesEncryptionIV == nullptr, "IV memory allocation failed!");
}

unsigned char* KeyGenerator::GenerateSeed(int length)
{
	/*Generates a seed of length specified as the parameter*/
	
	//Check if length is not negative or 0
	ASSERT(length <= 0,"Seed length cannot be negative or 0!");

	//Generate length random bytes with openssl RAND_bytes
	unsigned char* seed = new unsigned char[length];
	ASSERT(seed == nullptr, "New operator failed at seed!");

	RAND_bytes(seed, length);

	return seed;
}

unsigned char* KeyGenerator::GenerateChaChaKeyFromSeed(unsigned char* seed, int seedLen)
{
	/*Generate 256 bits key for the ChaCha20 algorithm from the seed given as a parameter*/

	//Check if seed == nullptr
	ASSERT(seed == nullptr, "Seed cannot be null when generating the key!");
	 
	//Check if seedLen is positive
	ASSERT(seedLen <= 0, "Seed length cannot be negative or 0!");

	//Generate the key based on the seed given
	ChaChaKey = MyKeystreamCipher(seed, seedLen, ChaChaKeyLength);

	return ChaChaKey;
}

unsigned char* KeyGenerator::GenerateAesKey(unsigned char* seed, int seedLen, int bitsSize, int validity)
{
	//Generates the keys for AES algorithm of size specified in the argument bitsSize
	//Supported values are 128 bits, 192 bits, 256 bits

	//Check for possible errors in the parameters received
	ASSERT(seed == nullptr, "Seed cannot be null when generating a key!");
	ASSERT(seedLen <= 0, "Seed length cannot be negative or 0!");
	ASSERT(bitsSize != 128 && bitsSize != 192 && bitsSize != 256, "Suported keys sizes are 128, 192, 256 bits!");
	ASSERT(validity < 0 || validity >= 3, "Posible values for validity are 0,1,2!");


	AesKeyLength = bitsSize / 8;
	//Generate the key using MyKeystreamCipher
	AesKey = new unsigned char[bitsSize / 8];
	ASSERT(AesKey == nullptr, "AesKey cannot be allocated!");

	AesKey = MyKeystreamCipher(seed, seedLen, bitsSize / 8);

	Validity = validity;

	return AesKey;
}

void KeyGenerator::SaveKeyPEM(const char* filename)
{
	ASSERT(ChaChaKey == nullptr, "Cannot save a null key in file!");

	//Create the header and the footer for PEM format
	std::string tag = "KEY STREAM";
	std::string header = "-----BEGIN " + tag + "-----\n";
	std::string footer = "\n-----END " + tag + "-----";

	//Open the output file
	FILE* outFile = fopen(filename, "wb");
	ASSERT(outFile == nullptr, "PEM file cannot be created!");

	//Create the ASN1_OCTET_STRING object
	ASN1_OCTET_STRING* keyString = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(keyString, ChaChaKey, ChaChaKeyLength);

	//Encode the key
	unsigned char* ber, * myber;
	int len = i2d_ASN1_OCTET_STRING(keyString, nullptr);
	ber = (unsigned char*)OPENSSL_malloc(len);
	ASSERT(ber == nullptr, "Cannot allocate memory for ber!");
	myber = ber;
	i2d_ASN1_OCTET_STRING(keyString, &myber);

	//Save the key in the file
	fwrite(header.data(), 1, header.size(), outFile);
	fwrite(ber, 1, len, outFile);
	fwrite(footer.data(), 1, footer.size(), outFile);

	//Deallocate memory of ASN1_OCTET_STRING variable
	ASN1_OCTET_STRING_free(keyString);

	//Close the file
	fclose(outFile);
}

MY_AES_KEY* KeyGenerator::SaveAesKey(const char* filename, const char* password) 
{
	//Saves the aes key in Der format defined by the structures at the start of this file
	ASSERT(filename == nullptr, "Filename cannot be null when saving aes key!");

	FILE* outFile = fopen(filename, "wb");
	ASSERT(outFile == nullptr, "Out file cannot be opened to save AES keys!");

	//Encrypt the aes key with pbkdf and 3-DES
	int outLen = -1;
	unsigned char* encryptedKey = EncryptUsingPassword(password, AesKeyLength, &outLen);

	//Initialize the structures for the DER encoding
	EncKey* encKey = EncKey_new();
	encKey->salt = ASN1_OCTET_STRING_new();
	encKey->nonce = ASN1_OCTET_STRING_new();
	encKey->AESkeyEncrypted = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(encKey->salt, AesEncryptionSalt, 4);
	ASN1_OCTET_STRING_set(encKey->nonce, AesEncryptionIV, 8);
	ASN1_OCTET_STRING_set(encKey->AESkeyEncrypted, encryptedKey, outLen);

	MY_AES_KEY* myAesKey = MY_AES_KEY_new();
	myAesKey->encryptedKey = encKey;
	myAesKey->keySize = ASN1_INTEGER_new();
	myAesKey->from = ASN1_UTCTIME_new();
	myAesKey->to = ASN1_UTCTIME_new();
	ASN1_INTEGER_set(myAesKey->keySize, AesKeyLength);

	switch (Validity)
	{
	case 0:
		//6 Months validity
		ASN1_UTCTIME_set(myAesKey->from, time(0) - 5);
		ASN1_UTCTIME_set(myAesKey->to, time(0) + MONTH6);
		break;
	case 1:
		//1 Year validity
		ASN1_UTCTIME_set(myAesKey->from, time(0) - 5);
		ASN1_UTCTIME_set(myAesKey->to, time(0) + YEAR);
		break;
	case 2:
		//3 Years validity
		ASN1_UTCTIME_set(myAesKey->from, time(0) - 5);
		ASN1_UTCTIME_set(myAesKey->to, time(0) + YEAR3);
		break;
	default:
		break;
	}

	//Encode the data in the structures
	unsigned char* ber, * myber;
	int len = i2d_MY_AES_KEY(myAesKey, nullptr);
	ber = (unsigned char*)OPENSSL_malloc(len);
	ASSERT(ber == nullptr, "Ber variable memory allocation failed!");
	myber = ber;
	i2d_MY_AES_KEY(myAesKey, &myber);

	//Write the encoded data in the file
	fwrite(ber, 1, len, outFile);

	//Clear the data
	fclose(outFile);

	return myAesKey;
}

unsigned char* KeyGenerator::LoadChaChaKey(const char* filename)
{
	//Loads from the pem file the ChaCha20 key
	//Returns the key and saves it in the static member variable

	//Check if the filename is not null
	ASSERT(filename == nullptr, "Filename cannot be null when loading a key!");

	FILE* inFile = fopen(filename, "rb");
	fseek(inFile, 0, SEEK_END);
	long inFileSize = ftell(inFile);
	ASSERT(inFileSize <= 0, "Input file for key loading cannot be empty!");
	fseek(inFile, 0, SEEK_SET);

	//Read data from file
	unsigned char* buffer = new unsigned char[inFileSize];
	ASSERT(buffer == nullptr, "Buffer memory allocation failed!");
	fread(buffer, 1, inFileSize, inFile);

	//Remove the header and footer
	int pos = -1;
	for (int i = 0; i < inFileSize; i++) {
		if (buffer[i] == '\n') {
			pos = i + 1;
			break;
		}
	}
	memcpy(buffer, &buffer[pos], inFileSize - pos);
	ASSERT(buffer[0] != 0x04, "The file does not contain an OCTET_STRING!");

	//Remove the footer
	int pos2 = -1;
	for (int i = inFileSize - pos - 1; i >= 0; i--) {
		if (buffer[i] == '\n') {
			pos2 = i - 1;
			break;
		}
	}

	ASN1_OCTET_STRING* key = ASN1_OCTET_STRING_new();
	const unsigned char* buf = (const unsigned char*)buffer;
	key = d2i_ASN1_OCTET_STRING(nullptr, &buf, pos2 - 1);

	//unsigned char* result = (unsigned char*)ASN1_STRING_get0_data(key);
	unsigned char* result2 = &buffer[2];
	fclose(inFile);
	return result2;
}

unsigned char* KeyGenerator::LoadAesKey(const char* filename)
{
	return nullptr;
}

bool KeyGenerator::CheckAesKeyValidity(MY_AES_KEY* myAesKey)
{
	ASSERT(myAesKey == nullptr, "Aes key cannot be null when checking validity!");

	return (ASN1_UTCTIME_cmp_time_t(myAesKey->from, time(0)) < 0 && ASN1_UTCTIME_cmp_time_t(myAesKey->to, time(0)) > 0 ) ? false : true;
}

unsigned char* KeyGenerator::GetLastChaChaKey()
{
	//Returns the last key generated for the ChaCha20 algorithm
	return ChaChaKey;
}

unsigned char* KeyGenerator::GetLastAesKey()
{
	//Returns the last key generated for the AES algorithm
	return AesKey;
}

void KeyGenerator::Finalize()
{
	//Delete the key
	ASSERT(ChaChaKey == nullptr, "Key value cannot be null at finalize!");
	delete[] ChaChaKey;
}
