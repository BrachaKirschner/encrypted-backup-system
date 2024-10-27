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
 * @param fname the name of the file or its path.
 * @note If a file name is given, the file is assumed to be in the same directory as the executable.
 * @return std::string the checksum, size and name of the file in the format "checksum\tsize\tname"
 */
std::string compute_file_crc(std::string fname);

#endif