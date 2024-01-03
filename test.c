#include <Windows.h>
#include <stdio.h> 
#include <stdlib.h>
#include <bcrypt.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

int main()
{
    NTSTATUS status = 0;
    
    BCRYPT_ALG_HANDLE ALG_HANDLE = NULL; 
    status = BCryptOpenAlgorithmProvider(
                                        &ALG_HANDLE, 
                                        BCRYPT_AES_ALGORITHM,
                                        NULL, 
                                        0); 
    
    if(!NT_SUCCESS(status)) printf("Error code : 0x%02x\n", status);
    
    BCryptCloseAlgorithmProvider(ALG_HANDLE, 0);

    return 0; 
}

