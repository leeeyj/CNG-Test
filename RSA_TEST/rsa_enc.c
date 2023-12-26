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
           - Generate RSA Algorithm Handle
    ------------------------------------------------
    [Encrypting Data]
        1. 
        2.
        3.
        4. 
    ------------------------------------------------
    [Clean Up Memory]
        1. Destroy Alg Handle
        2. Free Memory 

    <Reference>
    https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob 
    https://stackoverflow.com/questions/58419870/how-to-use-bcrypt-for-rsa-asymmetric-encryption
    https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/007a0e26-7fc0-4079-9b63-2ad23f866836/bug-in-rsa-encryptiondecryption-using-cng?forum=windowssdk
    https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
*/

/*  
    [BCRYPT_RSAKEY_BLOB Structure]
    typedef struct _BCRYPT_RSAKEY_BLOB {
                                        ULONG Magic;                // Magic number of RSAKEY 
                                        ULONG BitLength;            // The size(bit) of the modulus N  
                                        ULONG cbPublicExp;          // The size(byte) of the Public exponent e
                                        ULONG cbModulus;            // The size(byte) of the modulus N 
                                        ULONG cbPrime1;             // The size(byte) of the p 
                                        ULONG cbPrime2;             // The size(byte) of the q 
                                        } BCRYPT_RSAKEY_BLOB;       

    [RSA Public Key Blob Structure]           
    BCRYPT_RSAKEY_BLOB || PublicExponent[cbPublicExp] || Moduls[cbModulus]                

        [BCRYPT_RSAKEY_BLOB]
        {0x52, 0x53, 0x41, 0x31,            // BCRYPT_RSAPUBLIC_MAGIC; 0x31415352 
         0x00, 0x10, 0x00, 0x00,            // The size(bit) of the modulus N; 4096 = 0x00001000
         0x03, 0x00, 0x00, 0x00,            // The size(byte) of the public exponent e; 65537 = 0x010001 (3-byte)
         0x00, 0x02, 0x00, 0x00,            // The size(byte) of the modulus N; 4096/8 = 512 = 0x00000200 
         0x00, 0x00, 0x00, 0x00,            // The size(byte) of the p
         0x00, 0x00, 0x00, 0x00}            // The size(byte) of the q  

        [PublicExponent]
        {0x01, 0x00, 0x01}                  // Public Exponent e; 65537 = 0x010001; Big Endian  
        
        [Modulus]                           // Modulus N; 512-byte 
        {
            
        }
    
*/

#include <Windows.h>
#include <bcrypt.h> 
#include <stdio.h>
#include <stdlib.h> 

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

void GET_ALG_HANDLE(BCRYPT_ALG_HANDLE* handle)
{   
    NTSTATUS status = BCryptOpenAlgorithmProvider(
                                            handle,                 // Algorithm Handle pointer 
                                            BCRYPT_RSA_ALGORITHM,   // Cryptographic Algorithm name 
                                            NULL,                   // 
                                            0);                     // Flags 

    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptOpenAlgorithmProvider fail\n", status);
        return; 
    }

    return;
}

int main()
{   
    BCRYPT_ALG_HANDLE RSA_ALG = NULL;
    GET_ALG_HANDLE(&RSA_ALG);
    

    BCryptCloseAlgorithmProvider(RSA_ALG, 0);
    return 0; 
}