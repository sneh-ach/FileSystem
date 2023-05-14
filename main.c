#define _GNU_SOURCE
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>

#define NUM_BLOCKS 65536
#define BLOCK_SIZE 1024
#define NUM_INODES 128
#define NUM_FILES 256
#define MAX_BLOCKS_PER_FILE 1024
#define WHITESPACE " \t\n"
#define MAX_COMMAND_SIZE 255
#define MAX_NUM_ARGUMENTS 5
#define MAX_FILENAME_LENGTH 64

unsigned char file_data[NUM_BLOCKS][BLOCK_SIZE];
int used_blocks[NUM_BLOCKS];
char *createfs_name;

struct directory_entry
{
    char *name;
    int valid;
    int inode_idx;
};

struct directory_entry *directory_ptr;
struct inode
{
    time_t date;
    int valid;
    int size;
    int blocks;
};

struct inode *inode_array_ptr;

// This init() function initializes the file system by setting up the directory
// entries and inode array within the file_data 2D array, marking all directory
// entries as invalid (unused) and preparing the inode array for further use.
void init()
{
    int i;
    directory_ptr = (struct directory_entry *)&file_data[0];
    for (i = 0; i < NUM_FILES; i++)
    {
        directory_ptr[i].valid = 0;
    }
    for (i = 1; i < 130; i++)
    {
    }
    inode_array_ptr = (struct inode *)&file_data[0];
}

// This df() function calculates the available disk space in the file system
// by counting the number of free (unused) blocks in the used_blocks array,
// starting from index 130 up to 4225, and then returns the total free space
// in bytes by multiplying the free block count with the block size (BLOCK_SIZE).
int df()
{
    int i = 0;
    int count = 0;

    // Iterate through the used_blocks array.
    for (i = 130; i < 4226; i++)
    {
        // If the block is free (not used), increment the count.
        if (used_blocks[i] == 0)
        {
            count++;
        }
    }

    // Return the free space in bytes.
    return count * BLOCK_SIZE;
}

// The findFreeInode() function searches for the first available (free) inode in the
// inode_array_ptr by iterating through its 128 elements. If it finds an inode with
// a valid value of 0, which indicates a free inode, the function returns the index
// of the found inode. If no free inode is found, the function returns -1.
int findFreeInode()
{
    int i;
    int retval = -1;

    // Iterate through the inode_array_ptr.
    for (i = 0; i < 128; i++)
    {
        // If an invalid (free) inode is found, return its index.
        if (inode_array_ptr[i].valid == 0)
        {
            retval = i;
            break;
        }
    }
    return retval;
}

// The findFreeBlock() function searches for the first available (free) block in the
// used_blocks array by iterating through its elements, starting from index 130 and
// going up to index 4225. If it finds a block with a value of 0, which indicates a
// free block, the function returns the index of the found block. If no free block
// is found, the function returns -1.
int findFreeBlock()
{
    int retval = -1;
    int i = 0;

    // Iterate through the used_blocks array.
    for (i = 130; i < 4226; i++)
    {
        // If a free block is found, return its index.
        if (used_blocks[i] == 0)
        {
            retval = i;
            break;
        }
    }

    return retval;
}

// The findFreeDirectoryEntry() function searches for the first available (free) directory
// entry in the directory_ptr array by iterating through its elements, starting from index
// 0 and going up to index 127. If it finds a directory entry with a valid value of 0, which
// indicates a free directory entry, the function returns the index of the found entry. If
// no free directory entry is found, the function returns -1.
int findFreeDirectoryEntry()
{
    int i = 0;
    int retval = -1;

    // Iterate through the directory_ptr array.
    for (i = 0; i < 128; i++)
    {
        // If an invalid (free) directory entry is found, return its index.
        if (directory_ptr[i].valid == 0)
        {
            retval = i;
            break;
        }
    }

    return retval;
}

// The insert(char *filename) function inserts a file into the file system image by performing
// the following steps:

// 1. Check if the file exists and has enough space in the file system.
// 2. Find a free directory entry and set the file name and inode index.
// 3. Find a free inode and set its size, date, and validity.
// 4. Open the input file for reading.
// 5. Copy the file's content to the file system block by block:
// a. Find a free block.
// b. Mark the block as used.
// c. Set the inode's block to the found block index.
// d. Read content from the input file and write it into the file system block.
// e. Update the copy_size and offset.
// 6. Handle any remaining content in the file, if applicable.
// 7. Close the input file.
void insert(char *filename)
{
    struct stat buf;
    int status = stat(filename, &buf);

    // Check if the file exists.
    if (status == -1)
    {
        printf("insert error: File not found\n");
        return;
    }

    // Check if there is enough space in the file system.
    if (buf.st_size > df())
    {
        printf("insert error: Not enough disk space.\n");
        return;
    }

    // Find a free directory entry.
    int dir_idx = findFreeDirectoryEntry();
    if (dir_idx == -1)
    {
        printf("insert error: Not enough room in the file system.\n");
        return;
    }

    // Check if filename is too long.
    if (strlen(filename) > MAX_FILENAME_LENGTH)
    {
        printf("insert error: File name too long.\n");
        return;
    }

    // Set the values of the directory pointer.
    directory_ptr[dir_idx].valid = 69; // '69' is used as an arbitrary valid value.
    directory_ptr[dir_idx].name = (char *)malloc(strlen(filename) + 1);
    strncpy(directory_ptr[dir_idx].name, filename, strlen(filename));
    directory_ptr[dir_idx].name[strlen(filename)] = '\0';

    // Find a free inode.
    int inode_idx = findFreeInode();
    if (inode_idx == -1)
    {
        printf("insert error: No free inodes.\n");
        return;
    }

    // Set the directory inode index to the corresponding inode index.
    directory_ptr[dir_idx].inode_idx = inode_idx;

    // Set the values of the inode array.
    inode_array_ptr[inode_idx].size = buf.st_size;
    inode_array_ptr[inode_idx].date = time(NULL);
    inode_array_ptr[inode_idx].valid = 1;

    // Open the input file in read-only mode.
    FILE *ifp = fopen(filename, "r");
    int copy_size = buf.st_size;
    int offset = 0;

    // Copy the content of the input file to the file system.
    while (copy_size > 0)
    {
        int block_index = findFreeBlock();
        if (block_index == -1)
        {
            printf("insert error: Can't find free block.\n");
            // Clean up directory and inode.
            return;
        }

        // Mark the block as used.
        used_blocks[block_index] = 1;

        // Find a free block for the inode.
        int inode_block_entry = findFreeBlock();
        if (inode_block_entry == -1)
        {
            printf("insert error: Can't find free inode block.\n");
            return;
        }

        // Set the inode's block to the found block index.
        inode_array_ptr[inode_idx].blocks = block_index;

        // Read the content from the input file.
        fseek(ifp, offset, SEEK_SET);
        int bytes_to_read = (copy_size > BLOCK_SIZE) ? BLOCK_SIZE : copy_size;
        int bytes = fread(file_data[block_index], bytes_to_read, 1, ifp);
        if (bytes != 1 && !feof(ifp))
        {
            printf("insert error: An error occurred reading from the input file.\n");
            return;
        }
        clearerr(ifp);

        // Update copy_size and offset.
        copy_size -= bytes_to_read;
        offset += bytes_to_read;
    }

    fclose(ifp);
    return;
}

// The retrieve() function retrieves a file from the file system image and saves it locally.
// It checks if the file exists, finds its index, and copies its content to a new or existing
// file with the specified name.
void retrieve(char *filename, char *newfilename)
{
    int i = 0;
    int file_idx = -1;
    int offset = 0;

    if (newfilename == NULL)
    {
        newfilename = filename;
    }

    // Find the file index in the directory.
    for (i = 0; i < NUM_FILES; i++)
    {
        if (strcmp(directory_ptr[i].name, filename) == 0)
        {
            file_idx = i;
            break;
        }
    }

    // Check if the file is found.
    if (file_idx == -1)
    {
        printf("Error: file not found\n");
        return;
    }

    // Get the inode of the file.
    int inode_idx = directory_ptr[file_idx].inode_idx;
    struct inode *file_inode = &inode_array_ptr[inode_idx];

    // Initialize the copy_size variable.
    int copy_size = file_inode->size;

    // Open the output file.
    FILE *ofp;
    ofp = fopen(newfilename, "wb");

    // Copy the content of the file from the file system to the output file.
    while (copy_size > 0)
    {
        int bytes;
        if (copy_size < BLOCK_SIZE)
            bytes = copy_size;
        else
            bytes = BLOCK_SIZE;

        int block_index = file_inode->blocks;
        fwrite(file_data[block_index] + offset, bytes, 1, ofp);

        copy_size -= bytes;
        offset += bytes;
    }

    // Close the output file.
    fclose(ofp);
    return;
}

// The delete() function deletes a file from the file system image. It searches for
// the file's index in the directory, and if it is found, marks the file as deleted
// by setting the valid flag of the directory entry to 0.
void delete(char *filename)
{
    int file_idx = -1;
    int i;
    // Find the file index in the directory.
    for (i = 0; i < NUM_FILES; i++)
    {
        if (strcmp(directory_ptr[i].name, filename) == 0)
        {
            file_idx = i;
            break;
        }
    }

    // Check if the file is found.
    if (file_idx == -1)
    {
        printf("Error: file not found\n");
        return;
    }

    // Set the valid flag of the directory entry to indicate deletion.
    directory_ptr[i].valid = 0;
    return;
}

// The undelete_file() function attempts to undelete a file from the file system image. It
// iterates through the directory_ptr array to find the file's index based on the given filename.
// If the file is found and marked as deleted (valid flag is 0), the function sets the valid flag
// to 69, effectively undeleting the file. If the file is not found or not marked as deleted, it
// prints an error message.
void undelete_file(char *filename)
{
    int file_idx = -1;
    int i;

    // Iterate through the directory_ptr array to find the file index.
    for (i = 0; i < NUM_FILES; i++)
    {
        // Check if the filename matches.
        if (strcmp(directory_ptr[i].name, filename) == 0)
        {
            file_idx = i;
            break;
        }
    }

    // If the file is not found, print an error message and return.
    if (file_idx == -1)
    {
        printf("undelete: Can not find the file.\n");
        return;
    }

    // Check if the valid flag of the directory entry is 0 (i.e., the file is deleted).
    if (directory_ptr[i].valid == 0)
    {
        // Set the valid flag to 69 to undelete the file.
        directory_ptr[i].valid = 69;
        printf("File successfully undeleted.\n");
    }
    else
    {
        // If the file is not deleted, print an error message.
        printf("Error: file is not deleted, cannot undelete.\n");
    }

    return;
}

// Opens a file and reads the file data into the file_data array.
void open_filesystem_image(char *filename)
{
    // Open the file in read mode.
    FILE *ifp = fopen(filename, "r");

    // Check if the file exists.
    if (ifp == NULL)
    {
        printf("open: File not found\n");
        return;
    }

    // Read the file content into the file_data array.
    fread(&file_data[0][0], 8192, 4226, ifp);

    // Close the file.
    fclose(ifp);
}

// The "read_bytes_from_fs" function reads a specified number of bytes from a file in the file system,
// starting from a given position. It checks if the file exists and if the starting position is valid.
// If everything is okay, it prints the specified number of bytes from the file in hexadecimal format.
void read_bytes_from_fs(const char *filename, long starting_byte, size_t num_bytes)
{
    int file_idx = -1;

    // Iterate through the directory_ptr array to find the file index.
    for (int i = 0; i < NUM_FILES; i++)
    {
        if (directory_ptr[i].valid == 69 && strcmp(directory_ptr[i].name, filename) == 0)
        {
            file_idx = i;
            break;
        }
    }

    // If the file is not found, print an error message and return.
    if (file_idx == -1)
    {
        printf("Error: file not found\n");
        return;
    }

    // Get the inode index and file size.
    int inode_idx = directory_ptr[file_idx].inode_idx;
    int file_size = inode_array_ptr[inode_idx].size;

    // Check if the starting byte is within the file size.
    if (starting_byte >= file_size)
    {
        printf("Error: starting byte is out of range\n");
        return;
    }

    // Adjust the number of bytes to read if it exceeds the file size.
    if (starting_byte + num_bytes > file_size)
    {
        num_bytes = file_size - starting_byte;
    }

    // Iterate through the specified number of bytes and print their values.
    for (size_t i = 0; i < num_bytes; ++i)
    {
        long current_byte = starting_byte + i;
        int row = current_byte / BLOCK_SIZE;
        int col = current_byte % BLOCK_SIZE;
        printf("%02X ", file_data[row][col]);
    }
    printf("\n");
}

// The "createfs" function sets up the file system by initializing the directory and the inodes. It
// sets the "directory_ptr" to the start of the "file_data" array, sets the "createfs_name" to the name
// of the file system, and sets all the "valid" flags of the directory entries to 0. It also sets the inode
// index to 0 and the "inode_array_ptr" to the start of the "file_data" array.
void createfs(char *filename)
{
    int i;

    // Check if the filename is provided.//
    if (filename == NULL)
    {
        printf("createfs: Filename not provided\n");
        return;
    }

    // Set directory_ptr to point to the beginning of the file_data array.
    directory_ptr = (struct directory_entry *)&file_data[0];

    // Allocate memory and set the createfs_name to the filename specified in the command line.
    createfs_name = (char *)malloc(strlen(filename));
    createfs_name = filename;

    // Initialize the valid flags of all directory entries to 0.
    for (i = 0; i < NUM_FILES; i++)
    {
        directory_ptr[i].valid = 0;
    }
    inode_array_ptr = (struct inode *)&file_data[0];
}

// The "savefs" function saves the current file system image to a file. It first opens the output file for
// writing using the name specified in the "createfs" function. Then, it writes the contents of the "file_data"
// array to the output file. Finally, it closes the output file.
void savefs()
{
    // Open the output file for writing.
    FILE *ofp = fopen(createfs_name, "w");

    // Write the file_data array content to the output file.
    fwrite(&file_data[0][0], 8192, 4226, ofp);

    // Close the output file.
    fclose(ofp);
}

// The "attrib" function changes the attribute of a file to hidden or not hidden, depending on the specified
// attribute. It first searches for the file in the "directory_ptr" array and checks if it exists. If the file
// is not found, it prints an error message and returns. If the file is found, the function checks the attribute
// value and changes the "valid" value of the directory entry accordingly. If the attribute is not supported, it
// prints an error message.
void attrib(char *attribute, char *filename)
{
    int i;
    int file_idx = -1;

    // Search for the specified file in the directory_ptr array.
    for (i = 0; i < NUM_FILES; i++)
    {
        if (strcmp(directory_ptr[i].name, filename) == 0)
        {
            file_idx = i;
            break;
        }
    }

    // If the file is not found, print an error message and return.
    if (file_idx == -1)
    {
        printf("attrib: File not found\n");
        return;
    }

    // If the attribute is "+h", change the directory.valid value to 2 (hidden).
    if (strcmp(attribute, "+h") == 0)
    {
        directory_ptr[file_idx].valid = 2;
    }
    // If the attribute is "-h", change the directory.valid value back to 69 (not hidden).
    else if (strcmp(attribute, "-h") == 0)
    {
        directory_ptr[file_idx].valid = 69;
    }
    // If the attribute is not supported, print an error message.
    else
    {
        printf("Error: attribute not supported\n");
    }
}

// The "listFiles" function lists the files that are currently in the directory. It iterates through the
// "directory_ptr" array to find valid files and checks if the "valid" flag is set to 69 or 2. If the flag is
// set to 69 or if "showHidden" is set to true and the flag is set to 2, the function prints the file size,
// date, and name. If no files are found, the function prints a message indicating that no files were found.
void listFiles(bool showHidden, bool showAttributes)
{
    int i = 0;
    int inode_in = 0;
    int empty = 0;

    // Iterate through the directory_ptr array to find valid files.
    for (i = 0; i < NUM_FILES; i++)
    {
        // If the valid flag is 69 or 2, the file should be listed.
        if (directory_ptr[i].valid == 69 || (showHidden && directory_ptr[i].valid == 2))
        {
            inode_in = directory_ptr[i].inode_idx;
            empty++;

            // Remove the newline character at the end of the ctime string.
            char *temp = (char *)malloc(strlen(ctime(&inode_array_ptr[inode_in].date)));
            strncpy(temp, ctime(&inode_array_ptr[inode_in].date), strlen(ctime(&inode_array_ptr[inode_in].date)) - 1);
            temp[strlen(ctime(&inode_array_ptr[inode_in].date)) - 1] = '\0';

            // Print the file size, date, and name.
            printf("%d %s %s", inode_array_ptr[inode_in].size, temp,
                   directory_ptr[i].name);
            printf("\n");
        }
    }

    // If no files are found, print a message.
    if (empty == 0)
    {
        printf("List: no files found\n");
    }
}

// The "xor_cipher" function applies a XOR cipher to a file. It first searches for the file in the "directory_ptr" array
// and checks if it exists. If the file is not found, it prints an error message and returns. If the file is found, the
// function calculates the inode index and file size. It then iterates through the file data and applies the XOR cipher
// using the cipher and cipher size specified as parameters. The function then prints a message indicating whether the
// file was encrypted or decrypted.
void xor_cipher(const char *filename, unsigned char cipher, int encrypt)
{
    FILE *file = fopen(filename, encrypt ? "rb+" : "rb+");
    if (file == NULL)
    {
        printf("Error: file not found\n");
        return;
    }

    int ch;
    while ((ch = fgetc(file)) != EOF)
    {
        unsigned char encrypted_ch = ch ^ cipher;
        fseek(file, -1, SEEK_CUR);
        fputc(encrypted_ch, file);
        fflush(file);
    }

    fclose(file);

    if (encrypt)
    {
        printf("File %s encrypted with 1-byte cipher\n", filename);
    }
    else
    {
        printf("File %s decrypted with 1-byte cipher\n", filename);
    }
}

void encrypt_file(const char *filename, unsigned char cipher)
{
    xor_cipher(filename, cipher, 1);
}

void decrypt(const char *filename, unsigned char cipher)
{
    xor_cipher(filename, cipher, 0);
}

// The following code is the main function for a shell-like program that implements a file system. It continuously
// displays a prompt "mfs> " and waits for user input. When the user inputs a command, the input string is tokenized
// and each token is compared to a set of predefined commands. If the input matches a command, the corresponding function
// is called with the necessary arguments. If the input does not match any of the predefined commands, an error message is
// displayed. The program continues to run until the user enters the "quit" command.
int main()
{
    // Initialize the file system
    init();
    char *cmd_str = (char *)malloc(MAX_COMMAND_SIZE);

    // Main loop for the shell
    while (1)
    {
        // Display the mfs prompt
        printf("mfs> ");

        // Read the command from the command line
        while (!fgets(cmd_str, MAX_COMMAND_SIZE, stdin))
            ;

        // Parse input into tokens
        char *token[MAX_NUM_ARGUMENTS];
        int token_count = 0;
        char *arg_ptr;
        char *working_str = strdup(cmd_str);
        char *working_root = working_str;

        // Tokenize the input string with whitespace used as the delimiter
        while (((arg_ptr = strsep(&working_str, WHITESPACE)) != NULL) &&
               (token_count < MAX_NUM_ARGUMENTS))
        {
            token[token_count] = strndup(arg_ptr, MAX_COMMAND_SIZE);
            if (strlen(token[token_count]) == 0)
            {
                token[token_count] = NULL;
            }
            token_count++;
        }
        if (token[0] == NULL)
        {
            continue;
        }
        else if (strcmp(token[0], "quit") == 0)
        {
            break;
        }
        else if (strcmp(token[0], "insert") == 0)
        {
            insert(token[1]);
        }
        else if (strcmp(token[0], "retrieve") == 0)
        {
            retrieve(token[1], token[2]);
        }
        else if (strcmp(token[0], "list") == 0)
        {
            bool showHidden = false;
            bool showAttributes = false;

            // Check for additional arguments.
            for (int i = 1; token[i] != NULL; i++)
            {
                if (strcmp(token[i], "-h") == 0)
                {
                    showHidden = true;
                }
                else if (strcmp(token[i], "-a") == 0)
                {
                    showAttributes = true;
                }
                else
                {
                    printf("Error: unrecognized option '%s'\n", token[i]);
                }
            }

            listFiles(showHidden, showAttributes);
        }

        else if (strcmp(token[0], "df") == 0)
        {
            printf("%d bytes free. \n", df());
        }
        else if (strcmp(token[0], "open") == 0)
        {
            open_filesystem_image(token[1]);
        }
        else if (strcmp(token[0], "close") == 0)
        {
            init();
        }
        else if (strcmp(token[0], "createfs") == 0)
        {
            createfs(token[1]);
        }
        else if (strcmp(token[0], "attrib") == 0)
        {
            attrib(token[1], token[2]);
        }
        else if (strcmp(token[0], "savefs") == 0)
        {
            savefs();
        }
        else if (strcmp(token[0], "delete") == 0)
        {
            delete (token[1]);
        }
        else if (strcmp(token[0], "undel") == 0)
        {
            undelete_file(token[1]);
        }
        else if (strcmp(token[0], "read") == 0)
        {
            if (token[1] == NULL || token[2] == NULL || token[3] == NULL)
            {
                printf("Error: missing arguments. Usage: read <filename> <starting_byte> <num_bytes>\n");
            }
            else
            {
                const char *filename = token[1];
                long starting_byte = strtol(token[2], NULL, 10);
                size_t num_bytes = strtoul(token[3], NULL, 10);

                read_bytes_from_fs(filename, starting_byte, num_bytes);
            }
        }
        else if (strcmp(token[0], "encrypt") == 0)
        {
            if (token[1] == NULL || token[2] == NULL)
            {
                printf("Error: missing arguments. Usage: encrypt <filename> <cipher>\n");
            }
            else
            {
                const char *filename = token[1];

                if (strlen(token[2]) == 2) // 1 byte * 2 characters per byte
                {
                    char byte_str[3] = {token[2][0], token[2][1], '\0'};
                    unsigned char cipher = (unsigned char)strtoul(byte_str, NULL, 16);
                    encrypt_file(filename, cipher);
                }
                else
                {
                    printf("Error: invalid cipher. The cipher must be 1 byte long.\n");
                }
            }
        }
        else if (strcmp(token[0], "decrypt") == 0)
        {
            if (token[1] == NULL || token[2] == NULL)
            {
                printf("Error: missing arguments. Usage: decrypt <filename> <cipher>\n");
            }
            else
            {
                const char *filename = token[1];

                if (strlen(token[2]) == 2) // 1 byte * 2 characters per byte
                {
                    char byte_str[3] = {token[2][0], token[2][1], '\0'};
                    unsigned char cipher = (unsigned char)strtoul(byte_str, NULL, 16);
                    decrypt(filename, cipher);
                }
                else
                {
                    printf("Error: invalid cipher. The cipher must be 1 byte long.\n");
                }
            }
        }
        else
        {
            printf("Command not found, try again\n");
        }
        free(working_root);
    }
    return 0;
}