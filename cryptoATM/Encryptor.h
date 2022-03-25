#pragma once
#include <iostream>
#include <string>

#include "KeyGenerator.h"

class Encryptor {
private:

public:
	//Encrypt functions
	static unsigned char* EncryptAesGcm(unsigned char* data, int dataLen, unsigned char* key, int keyLen, unsigned char* iv);
	static unsigned char* EncryptChaCha20(unsigned char* data, int dataLen, unsigned char* key);

	//Decrypt functions
	static unsigned char* DecryptChaCha20(unsigned char* cipherText, int cipherLen, unsigned char* key);
};