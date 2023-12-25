#include <Windows.h>
#include <bcrypt.h> 
#include <stdio.h>
#include <stdlib.h> 

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define PRINT_RANDOM 1 
#define ranLength 16 

BYTE ran = {0, };

void PRINT(BYTE* arr, int size, int flag)
{
    if(flag == PRINT_RANDOM)
    {
        printf("\nrandom arr : ");
        for(int i = 0; i < size; i++){
            if(i % 4 == 0) printf("\n");
            printf("%02x\t", arr[i]);
        }
        printf("\n");
    }


}


void GET_ALG_HANDLE(BCRYPT_ALG_HANDLE* handle)
{   
    NTSTATUS status = BCryptOpenAlgorithmProvider(
                                            handle,                 // Algorithm Handle pointer 
                                            BCRYPT_RNG_ALGORITHM,   // Cryptographic Algorithm name 
                                            NULL,                   // 
                                            0);                     // Flags 

    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptOpenAlgorithmProvider fail\n", status);
        return; 
    }

    return;
}


void GEN_RANDOM(BCRYPT_ALG_HANDLE RNG_HANDLE)
{
    NTSTATUS status = BCryptGenRandom(
                                      RNG_HANDLE,                           // Algorithm Provider Handle 
                                      &ran,                                 // Address of a buffer that receives the random number 
                                      ranLength,                            // Size of the buffer that receives the random number 
                                      BCRYPT_RNG_USE_ENTROPY_IN_BUFFER);    // Flags; Additional entropy for the random number 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptGenRandom fail\n", status);
        return; 
    }

    PRINT(&ran, ranLength, PRINT_RANDOM);
    return; 
}


int main()
{
    BCRYPT_ALG_HANDLE RNG_HANDLE = NULL;
    GET_ALG_HANDLE(&RNG_HANDLE); 
    GEN_RANDOM(RNG_HANDLE);

    BCryptCloseAlgorithmProvider(RNG_HANDLE, 0);
}