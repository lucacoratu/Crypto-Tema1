#pragma once
#include "Utils.h"

class CryptoATM {
private:
	static CryptoATM* instance;
	CryptoATM();
	~CryptoATM();
	CryptoATM(const CryptoATM& other) = delete;

	//Menus for the application
	void PrintMainMenu();
	void PrintKeyGenerationMenu();
	void PrintEncryptionMenu();

	//Functions for every functionality
	void KeyGeneration();
	void GenerateKeyForChaCha20();
	void GenerateKeyForAes();
	void Encryption();
	void EncryptUsingChaCha20();
public:
	static CryptoATM* CreateInstance();
	static CryptoATM* GetInstance();
	static void DeleteInstance();

	void Run();
};