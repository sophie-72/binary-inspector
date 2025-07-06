#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer = malloc(9);
    
    buffer[0] = 'p';
    buffer[1] = 'a';
    buffer[2] = 's';
    buffer[3] = 's';
    buffer[4] = 'w';
    buffer[5] = 'o';
    buffer[6] = 'r';
    buffer[7] = 'd';
    buffer[8] = '\0';

    char *input = malloc(9);
    
    printf("Enter the 8 letter password: ");
    fgets(input, 9, stdin);
    
    if (strncmp(input, buffer, 8) == 0) {
        printf("You read my memory\n");
    } else {
        printf("You can't read my memory!\n");
    }
    
    return 0;
}
