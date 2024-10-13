#pragma once

#include <string>
#include <base64.h>


class Base64Wrapper
{
public:
	/**
	 * @brief This function encodes a string to base64
	 * 
	 * @param str the string to encode
	 * @return std::string 
	 */
	static std::string encode(const std::string& str);

	/**
	 * @brief This function decodes a base64 string
	 * 
	 * @param str the string to decode
	 * @return std::string 
	 */
	static std::string decode(const std::string& str);
};
