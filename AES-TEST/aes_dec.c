/*
    Win API: Cryptography Next Generation(CNG).  
    This code is test code for RNG, AES, RSA. 

    Created by YongJin Lee from Kookmin University
    Date : 2023.12.19 
*/

/*
    ------------------------------------------------
    [Generate Cipher Algrotihm Handle]
        1. Generate Cipher Algorithm Handle
           - Generate AES Algorithm Handle
    ------------------------------------------------   
    [Decrypting Data]
        1. Generating Symmetric Key
           - Generate 128 or 192 or 256 bit key      
        2. Setting Cipher Algorithm Properties
           - Set Block Chain Mode 
        3. Getting Cipher Algorithm Properties 
           - Calculate Block/IV Length
        4. Decrypting Data  
           - Calculate Plaintext Length
           - Data Decrpytion 
    ------------------------------------------------
    [Clean Up Memory]
        1. Destroy Key Handle 
        2. Destroy Alg Handle
        3. Free Memory 
*/

#include <Windows.h>
#include <bcrypt.h> 
#include <stdio.h>
#include <stdlib.h> 

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define PRINT_PLAINTEXT 1
#define PRINT_CIPHERTEXT 2
#define PRINT_DECRYPT 3

BYTE IV[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
BYTE AES256Key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
BYTE ciphertext[32] = {0xb0, 0xda, 0x8a, 0x89,
                       0xf6, 0x92, 0xbe, 0x04,
                       0x05, 0xd9, 0x84, 0xcf,
                       0xf8, 0xc3, 0x7a, 0x3b,
                       0xe3, 0xe1, 0x5f, 0xeb,
                       0x84, 0x17, 0x27, 0x88,
                       0x1b, 0xcd, 0xb1, 0xe6,
                       0x93, 0x6c, 0xc9, 0x02}; 

PBYTE plaintext = NULL;
DWORD plaintextLength = 0;


void PRINT(BYTE* arr, DWORD size, int flag)
{
    if(flag == PRINT_PLAINTEXT){
        printf("\nplaintext : ");
        for(int i = 0; i < size; i++){
            if(i % 4 == 0) printf("\n");
            printf("%02x\t", arr[i]);
        }
        printf("\n");
    }

    if(flag == PRINT_CIPHERTEXT){
        printf("\nciphertext : ");
        for(int i = 0; i < size; i++){
            if(i % 4 == 0) printf("\n");
            printf("%02x\t", arr[i]);
        }
        printf("\n");
    }

    if(flag == PRINT_DECRYPT){
        printf("\ndecrypt : ");
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
                                            BCRYPT_AES_ALGORITHM,   // Cryptographic Algorithm name 
                                            NULL,                   // 
                                            0);                     // Flags 

    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptOpenAlgorithmProvider fail\n", status);
        BCryptCloseAlgorithmProvider(handle, 0);
        return; 
    }

    return;
}


void AES_Dec_TEST(BCRYPT_ALG_HANDLE ALG_HANDLE)
{
    NTSTATUS status = 0; 
    BCRYPT_KEY_HANDLE KEY_HANDLE = NULL;        // AES Key Handle
    DWORD IVLength = 0;                         // IV Length 
    DWORD BlockLength = 0;                      // Block Length 
    DWORD bufferSize = 0;                       // Size of buffer 
    BYTE iv[16] = {0, };
    memcpy(iv, IV, 16);

    status = BCryptGenerateSymmetricKey(
                                        ALG_HANDLE,         // Algorithm Provider Handle
                                        &KEY_HANDLE,        // A pointer to Key Handle
                                        NULL,               // 
                                        0,                  // 
                                        AES256Key,          // A pointer to a buffer that contains the key material 
                                        sizeof(AES256Key),  // Size of the buffer that contains the key material 
                                        0);                 // Flags 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptGenerateSymmetricKey fail\n");
        BCryptDestroyKey(KEY_HANDLE);
        return;
    }


    status = BCryptSetProperty(
                               KEY_HANDLE,                      // CNG HANDLE
                               BCRYPT_CHAINING_MODE,            // Property name 
                               (PBYTE)BCRYPT_CHAIN_MODE_CBC,    // Buffer that contains new property value 
                               sizeof(BCRYPT_CHAIN_MODE_CBC),   // Size of the buffer that contains new propety value 
                               0);                              // Flags 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptSetProperty fail\n");
        BCryptDestroyKey(KEY_HANDLE);
        return;
    }


    status = BCryptGetProperty(
                               ALG_HANDLE,              // CNG HANDLE
                               BCRYPT_BLOCK_LENGTH,     // Property name 
                               (PBYTE)&IVLength ,       // Buffer which receives the property value 
                               sizeof(DWORD),           // Size of the buffer which receives the property value 
                               &bufferSize,             // Number of bytes that wer copied into the buffer 
                               0);                      // Flags 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptGetProperty fail\n");
        BCryptDestroyKey(KEY_HANDLE);
        return;
    }


    status = BCryptDecrypt(                         // Calculate plaintext length
                           KEY_HANDLE,              // KEY HANDLE 
                           ciphertext,              // Address of the buffer that contains the ciphertext 
                           sizeof(ciphertext),      // Size of the buufer that contains the ciphertext 
                           NULL,                    // A pointer to padding info used with asymetric
                           iv,                      // Address of the buffer that contains the Initial Vector 
                           IVLength,                // Size of the buffer that contains the Initial Vector
                           NULL,                    // Address of the buffer that receives the plaintext. 
                           0,                       // Size of the buffer that receives the plaintext 
                           &plaintextLength,        // Variable that receives number of bytes copied to plaintext buffer
                           BCRYPT_BLOCK_PADDING);   // Flags : Block Padding 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptDecrypt(Calculate plaintextLength) fail\n");
        BCryptDestroyKey(KEY_HANDLE);
        return;
    }
    else 
    {
        plaintext = (PBYTE)calloc(plaintextLength, sizeof(BYTE));        // Free needed
        if(plaintext == NULL) 
        {
            printf("Memory Allocation(plaintext) Fail...\n");
            BCryptDestroyKey(KEY_HANDLE);
            return; 
        }
    }


    status = BCryptDecrypt(                         // Decrypt Data
                           KEY_HANDLE,              // KEY HANDLE 
                           ciphertext,              // Address of the buffer that contains the ciphertext 
                           sizeof(ciphertext),      // Size of the buufer that contains the ciphertext 
                           NULL,                    // A pointer to padding info used with asymetric
                           iv,                      // Address of the buffer that contains the Initial Vector 
                           IVLength,                // Size of the buffer that contains the Initial Vector
                           plaintext,               // Address of the buffer that receives the plaintext. 
                           plaintextLength,         // Size of the buffer that receives the plaintext 
                           &plaintextLength,        // Variable that receives number of bytes copied to plaintext buffer
                           BCRYPT_BLOCK_PADDING);   // Flags : Block Padding 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptDecrypt(Decrypt Data) fail\n");
        BCryptDestroyKey(KEY_HANDLE);
        return;
    }

    PRINT(ciphertext, sizeof(ciphertext), PRINT_CIPHERTEXT);
    PRINT(plaintext, plaintextLength, PRINT_PLAINTEXT);

    BCryptDestroyKey(KEY_HANDLE);
    free(plaintext);
    plaintextLength = 0;
    
    return; 
}


int main()
{   
    for(int i = 0; i < 10; i++)
    {
        BCRYPT_ALG_HANDLE ALG_HANDLE = NULL;
        GET_ALG_HANDLE(&ALG_HANDLE);
        AES_Dec_TEST(ALG_HANDLE);
        BCryptCloseAlgorithmProvider(ALG_HANDLE, 0);
    }
    return 0;
}