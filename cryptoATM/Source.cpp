#include "KeyGenerator.h"
#include "Encryptor.h"
#include "Utils.h"
#include "CryptoATM.h"

int main() {

	try {
		CryptoATM* cAtm = CryptoATM::CreateInstance();

		cAtm->Run();
		//unsigned char* encryptedData = Encryptor::EncryptAesGcm(data, 27, KeyGenerator::GetLastAesKey(), 256/8, (unsigned char*)ASN1_STRING_get0_data(myAesKey->encryptedKey->nonce));
		//printf("Encrypted data: ");
		//PRINT_DATA(encryptedData, 27 + 16);

		cAtm->DeleteInstance();
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}


	return 0;
}