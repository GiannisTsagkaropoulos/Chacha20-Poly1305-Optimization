#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

//L3 is 8MBytes, we give a max of input 4 times this value
#define BLOCKS_NUMBERS 525
#define BLOCKS_JUMP 26

/*
    Input arguments:
    - argv[1]: file_data (the txt file path)
    - argv[2]: func_name (the binary/function to execute)
    Note: The loop variable 'i' is passed as the first argument to the child.
*/

int main(int argc, char **argv) {
    if (argc != 4) {
        // Based on your code logic, you expect 2 arguments + program name
        fprintf(stderr, "Usage: %s <file_data> <binary_path>\n", argv[0]); 
        return -1;
    }

    char* binary_path = argv[1];
    char* file_data = argv[2];
    char* func_name = argv[3];

    // Create or truncate the file (equivalent to std::ios::trunc)
    FILE *file = fopen(file_data, "w");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    fclose(file); // Close it immediately; we just wanted to clear/create it.

    for (int i = 64; i <= BLOCKS_NUMBERS*64; i+= BLOCKS_JUMP*64) {

        pid_t pid = fork();

        if (pid == 0) {
            // Child process
            
            // Convert i to string for the first argument
            char num_str[12]; 
            sprintf(num_str, "%d", i);

            char* args[] = {
                binary_path, // Standard practice: args[0] is the binary path
                num_str,     // Your block size/loop index
                file_data,
                func_name,
                NULL         // Array must be NULL terminated
            };

            // execvp uses args[0] as the file to execute
            execvp(args[0], args);

            // If execvp returns, it failed
            fprintf(stderr, "execvp failed to run %s\n", binary_path);
            exit(1);
        }
        else if (pid > 0) {
            // Parent process
            int status;
            waitpid(pid, &status, 0); // wait for child to finish

            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                // exit_code is available here if needed
            }
        }
        else {
            fprintf(stderr, "fork failed\n");
            return 1;
        }
    }

    return 0;
}