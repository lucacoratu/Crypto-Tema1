#define _CRT_SECURE_NO_WARNINGS

#include "CryptoATM.h"
#include "KeyGenerator.h"
#include "Encryptor.h"

#include <conio.h>

CryptoATM* CryptoATM::instance = nullptr;

CryptoATM::CryptoATM() {
	//Initializes the static classes needed for the program to work
	KeyGenerator::Init();
}
CryptoATM::~CryptoATM() {
	//Deallocates the memory used by the program
	KeyGenerator::Finalize();
}

void CryptoATM::PrintMainMenu()
{
	system("cls");
	std::cout << "======================CRYPTO ATM======================\n";
	std::cout << "\t1. Generarea de chei pentru AES si ChaCha20\n";
	std::cout << "\t2. Criptarea fisierelor pe baza cheii generate\n";
	std::cout << "\t3. Realizarea hash-ului datelor criptate\n";
	std::cout << "\t4. Semnarea hashului generat\n";
	std::cout << "\t5. Salvarea datelor criptate si a semnaturii\n";
	std::cout << "\tq. Iesire din program\n";
	std::cout << "\tIntroduceti optiunea: ";
}

void CryptoATM::PrintKeyGenerationMenu()
{
	system("cls");
	std::cout << "==================CRYPTO ATM - Key Generation==================\n";
	std::cout << "\t1. Generare de cheie pentru ChaCha20\n";
	std::cout << "\t2. Generare de cheie pentru AES\n";
	std::cout << "\tq. Revenire la pagina anterioara\n";
	std::cout << "\tIntroduceti optiunea: ";
}

void CryptoATM::PrintEncryptionMenu()
{
	system("cls");
	std::cout << "==================CRYPTO ATM - Encryption======================\n";
	std::cout << "\t1. Criptare folosind ChaCha20 - Poly1305\n";
	std::cout << "\t2. Criptare folosind AES\n";
	std::cout << "\tq. Revenire la pagina anterioara\n";
	std::cout << "\tIntroduceti optiunea: ";
}


CryptoATM* CryptoATM::CreateInstance()
{
	//Creates a instance of this class if an instance doesn't already exits
	if (!instance)
		instance = new CryptoATM();

	return instance;
}

CryptoATM* CryptoATM::GetInstance()
{
	//Returns the instance
	return instance;
}

void CryptoATM::DeleteInstance()
{
	//Deletes the instance if the instance is not null
	if (instance)
		delete instance;
}

void CryptoATM::KeyGeneration() {
	//A new page with a menu for the key generation
	int ch = 0;
	while (ch != 'q') {
		PrintKeyGenerationMenu();
		ch = _getch();
		switch (ch)
		{
		case '1':
			GenerateKeyForChaCha20();
			break;
		case '2':
			GenerateKeyForAes();
			break;
		default:
			break;
		}
	}
}

void CryptoATM::GenerateKeyForChaCha20()
{
	//Generates the seed and the key and saves the result in the file
	system("cls");
	int seedLen = 26;
	//Generate the seed
	unsigned char* seed = KeyGenerator::GenerateSeed(seedLen);
	DEBUG_LOG("Generated seed for ChaCha20, seed length = %d\nSeed: ", seedLen);
	PRINT_DATA(seed, seedLen);

	//Generate the key
	unsigned char* chachaKey = KeyGenerator::GenerateChaChaKeyFromSeed(seed, seedLen);
	DEBUG_LOG("Generated key for ChaCha20: ");
	PRINT_DATA(chachaKey, 256 / 8);

	//Read out filename from stdin
	//TO DO...Check for overflow
	char buffer[256];
	printf("Introduceti numele fisierului de iesire: ");
	(void)scanf("%s", buffer);
	DEBUG_LOG("Out filename is: %s\n", buffer);

	KeyGenerator::SaveKeyPEM(buffer);
	DEBUG_LOG("Saved key in PEM format in file: %s\n", buffer);

	system("pause");
}

void CryptoATM::GenerateKeyForAes()
{
	int keyLength = -1;
	system("cls");
	printf("Introduceti dimensiunea cheii (biti): ");
	(void)scanf("%d", &keyLength);

	if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
		printf("Lungimea cheii poate fi doar: 128, 192, 256 biti\n");
		return;
	}

	int seedLen = 26;
	unsigned char* seed = KeyGenerator::GenerateSeed(seedLen);
	DEBUG_LOG("Generated seed for AES %d, seed length = %d\nSeed: ", keyLength ,seedLen);
	PRINT_DATA(seed, seedLen);

	unsigned char* aesKey = KeyGenerator::GenerateAesKey(seed, 20, keyLength, 0);
	DEBUG_LOG("Generated key for AES %d: ", keyLength);
	PRINT_DATA(aesKey, keyLength / 8);

	printf("Introduceti numele fisierului de iesire: ");
	char buffer[256];
	(void)scanf("%s", buffer);

	printf("Introduceti parola pentru criptarea cheii: ");
	char password[256];
	(void)scanf("%s", password);
	MY_AES_KEY* myAesKey = KeyGenerator::SaveAesKey(buffer, password);
	DEBUG_LOG("AES %d key has been saved in file: %s\n", keyLength, buffer);


	system("pause");
}

void CryptoATM::Encryption()
{
	int ch = 0;
	while (ch != 'q') {
		PrintEncryptionMenu();
		ch = _getch();
		switch (ch)
		{
		case '1':
			EncryptUsingChaCha20();
			break;
		case '2':
			break;
		default:
			break;
		}
	}
}

void CryptoATM::EncryptUsingChaCha20()
{
	//Encrypts the input file given with the key from the key input file
	system("cls");
	printf("Introduceti fisierul cu cheia (format PEM): ");
	char buffer[256];
	(void)scanf("%s", buffer);
	
	unsigned char* key = KeyGenerator::LoadChaChaKey(buffer);
	DEBUG_LOG("Loaded key for ChaCha20 from file: %s\n", buffer);
	PRINT_DATA(key, 256 / 8);

	//Encrypt using ChaCha20-Poly1305

	system("pause");
}

void CryptoATM::Run()
{
	//This function contains the main flow of the program
	int ch = 0;
	while (ch != 'q') {
		PrintMainMenu();
		ch = _getch();
		switch (ch) {
		case '1':
			KeyGeneration();
			break;
		case '2':
			Encryption();
			break;
		case '3':
			break;
		case '4':
			break;
		case '5':
			break;
		default:
			break;
		}
	}

	printf("\nInchiderea programului\n");
}
