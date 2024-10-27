#include "AESWrapper.h"

#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step


unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 32 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

AESWrapper::~AESWrapper()
{
}

const unsigned char* AESWrapper::getKey() const 
{ 
	return _key; 
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}

std::string AESWrapper::encrypt_file(const std::string& fname)
{
	if (!std::filesystem::exists(fname))
	{
		std::cerr << "Cannot open input file " << fname << std::endl;
		return "";
	}

	std::filesystem::path fpath = fname;
	std::ifstream original_file(fname, std::ios::binary);
	if (!original_file)
	{
		std::cerr << "Failed to open input file " << fname << std::endl;
		return "";
	}

	size_t size = std::filesystem::file_size(fpath);
	std::unique_ptr<char[]> buffer(new char[size]); // using smart pointer to avoid memory leak

	original_file.seekg(0, std::ios::beg);
	original_file.read(buffer.get(), size);
	original_file.close();

	std::string encrypted_data = encrypt(buffer.get(), size);

	std::string encrypted_fname = fname + ".enc";
	std::ofstream encrypted_file(encrypted_fname, std::ios::binary);
	if (!encrypted_file)
	{
		std::cerr << "Failed to create encrypted file " << encrypted_fname << std::endl;
		return "";
	}

	encrypted_file.write(encrypted_data.c_str(), encrypted_data.size());
	encrypted_file.close();

	return encrypted_fname; // Return the name of the encrypted file
}

std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}