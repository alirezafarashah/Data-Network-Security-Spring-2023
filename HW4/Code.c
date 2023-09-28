#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *ptr;
    char ch;
    ptr = fopen("q2.txt", "r");
    if (NULL == ptr) {
        printf("can not open the file to read!\n");
    }
    if (ptr != NULL) {
        printf("content of the file is:\n");
        while ((ch = fgetc(ptr)) != EOF) {
            printf("%c", ch);
        }
        printf("\nend of the file\n");
        fclose(ptr);
    }
    ptr = fopen("q2.txt", "w");
    if (ptr == NULL) {
        printf("can not open the file to write!\n");
    }
    if (ptr != NULL) {
        fprintf(ptr, "%s", "modified!");
        fclose(ptr);
        printf("write successfully to the file\n");
    }
    ch = getchar();
    return 0;
}