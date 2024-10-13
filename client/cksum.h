#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <string>

/**
 * @brief This function calculates the checksum of a given buffer
 * 
 * @param b the buffer
 * @param n the size of the buffer
 * @return unsigned long the checksum
 */
unsigned long memcrc(char * b, size_t n);

/**
 * @brief This function reads a file and returns its checksum, size and name
 * 
 * @param fname the name of the file
 * @return std::string the checksum, size and name of the file
 */
std::string readfile(std::string fname);

#endif