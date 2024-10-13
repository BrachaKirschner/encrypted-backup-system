/**
 * @file AESWrapper.h
 * @brief Header file for AESWrapper class.
 */

#pragma once

#include <string>

/**
 * @class AESWrapper
 * @brief A wrapper class for AES encryption and decryption
 */
class AESWrapper
{
public:
	/**
	 * @brief The default key length in bytes
	 *
	 * @note The key length must be 16 bytes
	 */
	static const unsigned int DEFAULT_KEYLENGTH = 16;

private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper &aes);

public:
	/**
	 * @brief Generate a random key
	 *
	 * @param buffer The buffer to store the key
	 * @param length The length of the key
	 * @return unsigned char* The generated key
	 */
	static unsigned char *GenerateKey(unsigned char *buffer, unsigned int length);

	/**
	 * @brief Construct a new AESWrapper object with a random key
	 */
	AESWrapper();

	/**
	 * @brief Construct a new AESWrapper object with a given key
	 *
	 * @param key The key
	 * @param size The size of the key
	 */
	AESWrapper(const unsigned char *key, unsigned int size);

	/**
	 * @brief Destroy the AESWrapper object
	 */
	~AESWrapper();

	/**
	 * @brief Get the key
	 *
	 * @return const unsigned char* The key
	 */
	const unsigned char *getKey() const;

	/**
	 * @brief Encrypt a plain text
	 *
	 * @param plain The plain text
	 * @param length The length of the plain text
	 * @return std::string The cipher text
	 */
	std::string encrypt(const char *plain, unsigned int length);

	/**
	 * @brief Decrypt a cipher text
	 *
	 * @param cipher The cipher text
	 * @param length The length of the cipher text
	 * @return std::string The plain text
	 */
	std::string decrypt(const char *cipher, unsigned int length);
};