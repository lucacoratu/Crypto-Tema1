#include "Encryptor.h"
#include "Utils.h"
#include <openssl/evp.h>

unsigned char* Encryptor::EncryptAesGcm(unsigned char* data, int dataLen, unsigned char* key, int keyLen, unsigned char* iv)
{
	//Encrypts len bytes from data with AES-GCM algorithm with key of various sizes (specified in the parameter)
	//Supported key lengths are 128,192,256 bits
	//Returns the cipherText concatenated with the tag
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	int res = -1;
	//Initialize the algorith with the correct key size
	if(keyLen == 256 / 8)
		res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),nullptr, nullptr, nullptr);
	if (keyLen == 192 / 8)
		res = EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), nullptr, nullptr, nullptr);
	if(keyLen == 128 / 8)
		res = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	ASSERT(res != 1, "EVP_EncryptInit failed!");

	//Initialize the memory for the cipherText
	unsigned char* cipherText = new unsigned char[static_cast<long long>(dataLen) + 16];
	ASSERT(cipherText == nullptr, "Cipher text memory allocation failed!");

	//Set the key and the iv for the algorithm
	res = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	ASSERT(res != 1, "EVP_EncryptInit_ex failed!");

	int outLenUpdate = -1, outLenFinal = -1;
	//Encrypt the data
	res = EVP_EncryptUpdate(ctx, cipherText, &outLenUpdate, data, dataLen);
	ASSERT(res != 1, "EVP_EncryptUpdate failed!");

	//Finalize the algorithm
	res = EVP_EncryptFinal_ex(ctx, cipherText + outLenUpdate, &outLenFinal);
	ASSERT(res != 1, "EVP_EncryptFinal_ex failed!");

	//Extract the tag and append it to the end of cipher text
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, cipherText + outLenUpdate);
	ASSERT(res != 1, "EVP_CIPHER_CTX_ctrl failed!");

	//Clear the data
	EVP_CIPHER_CTX_free(ctx);

	return cipherText;
}

unsigned char* Encryptor::EncryptChaCha20(unsigned char* data, int dataLen, unsigned char* key)
{
	//Encrypts the data using the ChaCha20-Poly1305 algorithm 
	//Returns the data encrypted and the tag concatenated


	return nullptr;
}

unsigned char* Encryptor::DecryptChaCha20(unsigned char* cipherText, int cipherLen, unsigned char* key)
{
	return nullptr;
}
