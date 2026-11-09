
#include <stdio.h>
#include <stdint.h>
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

    if (ferror(file)) {
        perror("File read error");
        fclose(file);
        return 1;
    }

    fclose(file);

    // Validate the header
    if (size < 5 || memcmp(input, "FUZ1", 4) != 0) {
        printf("Invalid file format\n");
        return 1;
    }

    uint8_t length = input[4];

    // Verify that enough payload data exists
    if ((size_t)length > size - 5) {
        printf("Incomplete file\n");
        return 1;
    }

    unsigned char buffer[32];

    // SECURITY FIX: Check destination capacity
    if ((size_t)length > sizeof(buffer)) {
        printf("Error: Payload exceeds buffer capacity\n");
        return 1;
    }

    memcpy(buffer, input + 5, length);

    unsigned int checksum = 0;

    for (size_t i = 0; i < length; i++) {
        checksum += buffer[i];
    }

    printf("Successfully parsed %u bytes (checksum: %u)\n",
           length, checksum);

    return 0;
}
