#pragma once

#include <osrng.h>
#include <rsa.h>

#include <string>



class RSAPublicWrapper
{
public:
	/**
	 * @brief The key size in bytes
	 * 
	 * @note The key size must be 160 bytes
	 */
	static const unsigned int KEYSIZE = 160;

	/**
	 * @brief The key size in bits
	 * 
	 * @note The key size must be 1024 bits
	 */
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PublicKey _publicKey;

	RSAPublicWrapper(const RSAPublicWrapper& rsapublic);
	RSAPublicWrapper& operator=(const RSAPublicWrapper& rsapublic);
public:

	/**
	 * @brief Construct a new RSAPublicWrapper object
	 * 
	 * @param key The public key to initialize the object with
	 * @param length The length of the key
	 */
	RSAPublicWrapper(const char* key, unsigned int length);

	/**
	 * @brief Construct a new RSAPublicWrapper object
	 * 
	 * @param key The public key to initialize the object with
	 */
	RSAPublicWrapper(const std::string& key);

	/**
	 * @brief Destroy the RSAPublicWrapper object
	 */
	~RSAPublicWrapper();


	/**
	 * @brief Get the public key
	 * 
	 * @return std::string The public key
	 */
	std::string getPublicKey() const;

	/**
	 * @brief Get the public key
	 * 
	 * @param keyout The buffer to store the key
	 * @param length The length of the buffer
	 * @return char* The public key
	 */
	char* getPublicKey(char* keyout, unsigned int length) const;


	/**
	 * @brief Encrypt a plain text
	 * 
	 * @param plain The plain text
	 * @return std::string The cipher text
	 */
	std::string encrypt(const std::string& plain);

	/**
	 * @brief Encrypt a plain text
	 * 
	 * @param plain The plain text
	 * @param length The length of the plain text
	 * @return std::string The cipher text
	 */
	std::string encrypt(const char* plain, unsigned int length);
};


/// @brief 
class RSAPrivateWrapper
{
public:
	/**
	 * @brief The key size in bits
	 * 
	 * @note The key size must be 1024 bits
	 */
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;

	RSAPrivateWrapper(const RSAPrivateWrapper& rsaprivate);
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& rsaprivate);
public:
	/**
	 * @brief Construct a new RSAPrivateWrapper object
	 */
	RSAPrivateWrapper();

	/**
	 * @brief Construct a new RSAPrivateWrapper object
	 * 
	 * @param key The private key to initialize the object with
	 * @param length The length of the key
	 */
	RSAPrivateWrapper(const char* key, unsigned int length);

	/**
	 * @brief Construct a new RSAPrivateWrapper object
	 * 
	 * @param key The private key to initialize the object with
	 */
	RSAPrivateWrapper(const std::string& key);

	/**
	 * @brief Destroy the RSAPrivateWrapper object
	 */
	~RSAPrivateWrapper();


	/**
	 * @brief Get the private key
	 * 
	 * @return std::string The private key
	 */
	std::string getPrivateKey() const;

	/**
	 * @brief Get the private key
	 * 
	 * @param keyout The buffer to store the key
	 * @param length The length of the buffer
	 * @return char* The private key
	 */
	char* getPrivateKey(char* keyout, unsigned int length) const;

	/**
	 * @brief Get the public key corresponding to the private key
	 * 
	 * @return std::string The public key
	 */
	std::string getPublicKey() const;

	/**
	 * @brief Get the public key corresponding to the private key
	 * 
	 * @param keyout The buffer to store the key
	 * @param length The length of the buffer
	 * @return char* The public key
	 */
	char* getPublicKey(char* keyout, unsigned int length) const;


	/**
	 * @brief Decrypt a cipher text
	 * 
	 * @param cipher The cipher text
	 * @return std::string The plain text
	 */
	std::string decrypt(const std::string& cipher);

	/**
	 * @brief Decrypt a cipher text
	 * 
	 * @param cipher The cipher text
	 * @param length The length of the cipher text
	 * @return std::string The plain text
	 */
	std::string decrypt(const char* cipher, unsigned int length);
};
