#include <stdlib.h>
#include <stdio.h>

#define LOOPS 100
#define MAXSIZE 256

int main(int argc, char **argv)
{
    int count = 0;
    char *pointer = NULL;
    for (count = 0; count < LOOPS; count++)
    {
        pointer = (char *)malloc(sizeof(char) * MAXSIZE);
    }
    free(pointer);
    //solucion: free(pointer) en el  bucle para que no se quede sin liberar memory
    //solo libera el ultimo malloc
    return count;
}