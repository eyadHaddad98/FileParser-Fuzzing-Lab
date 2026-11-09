
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror("File error");
        return 1;
    }

    unsigned char input[1024];
    size_t size = fread(input, 1, sizeof(input), file);
    fclose(file);

    if (size < 5 || memcmp(input, "FUZ1", 4) != 0) {
        printf("Invalid file format\n");
        return 1;
    }

    uint8_t length = input[4];

    if (size < 5 + (size_t)length) {
        printf("Incomplete file\n");
        return 1;
    }

    unsigned char buffer[32];

    // Intentionally vulnerable: missing length check
    memcpy(buffer, input + 5, length);

    // Use the copied data so the compiler retains the operation
    unsigned int checksum = 0;

    for (size_t i = 0; i < length; i++) {
       checksum += buffer[i];
    }

    printf("Successfully parsed %u bytes (checksum: %u)\n", length, checksum);

    return 0;
}
