#ifndef FILE_UTILS
#define FILE_UTILS

/**
 * Will read the contents of a file and fill out an array of strings with the contents of each of the lines
 *
 * @param filename const string of the name of the file to open and read
 * @param lines_out pointer to an array of strings
 * @param num_lines_out number of lines read from the file and placed into the array
 */
int read_lines_from_file(const char* filename, char*** lines_out, size_t* num_lines_out);

/**
 * Takes in an array of strings and concatenates them into one array of uint8_t bytes (similar to Python's join() with no delimiter char)
 *
 * @param lines array of char arrays to concatenate into one array
 * @param num_lines size_t number of strings in the array of strings]
 * @param result_len size_t pointer to the length of the resulting array
 *
 * @returns NULL on error, a pointer to an array of uint8_t bytes on success
 */
uint8_t* concatenate_lines_to_bytes(char** lines, size_t num_lines, size_t* result_len);

#endif
