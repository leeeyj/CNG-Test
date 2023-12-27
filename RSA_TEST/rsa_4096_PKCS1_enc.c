/*
    Win API: Cryptography Next Generation(CNG).  
    This code is test code for RNG, AES, RSA. 

    Created by YongJin Lee from Kookmin University
    Date : 2023.12.28
*/

/*
    ------------------------------------------------
    [Generate Cipher Algrotihm Handle]
        1. Generate Cipher Algorithm Handle
           - Generate RSA Algorithm Handle
    ------------------------------------------------
    [Encrypting Data]
        1. Generate PublicKey Blob
        2. Import PublicKey 
        3. Calculate ciphertext length 
        4. Encrypt Data 
    ------------------------------------------------
    [Clean Up Memory]
        1. Free Memory
        2. Destroy Key Handle 
        3. Destroy Alg Handle
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

    ----------------------------------------------------------------------------------------------------------------------------------------------------------------
    [RSA Public Key Blob Structure]           
    BCRYPT_RSAKEY_BLOB || PublicExponent[cbPublicExp] || Modulus[cbModulus]                
    typedef struct _PublicKey_BLOB {
                                    ULONG Magic;                                // Magic number of RSAKEY 
                                    ULONG BitLength;                            // The size(bit) of the modulus N; 4096-bit
                                    ULONG cbPublicExp;                          // The size(byte) of the Public exponent e; e = 65537 = 0x010001; 3-byte
                                    ULONG cbModulus;                            // The size(byte) of the modulus N; 4096/8 = 512-byte
                                    ULONG cbPrime1;                             // The size(byte) of the p; 
                                    ULONG cbPrime2;                             // The size(byte) of the q; 
                                    BYTE PublicExponent[cbPublicExp];           // Array of Public Exponent e; e = 65537 = 0x010001 = 3-byte
                                    BYTE Modulus[cbModulus];                    // Array of Modulus n; 4096 / 8 = 512-byte
    } PublicKey_BLOB

    BLOB total size = 24-byte(RSA Key BLOB) + 3-byte(Array size of e) + 512-byte(Array size of n) = 539

    ----------------------------------------------------------------------------------------------------------------------------------------------------------------
    [RSA Private Key Blob Structure]           
    BCRYPT_RSAKEY_BLOB || PublicExponent[cbPublicExp] || Moduls[cbModulus] || Prime1[cbPrime1] || Prime2[cbPrime2] 
    typedef struct _PrivateKey_BLOB {
                                    ULONG Magic;                                // Magic number of RSAKEY 
                                    ULONG BitLength;                            // The size(bit) of the modulus N; 4096-bit
                                    ULONG cbPublicExp;                          // The size(byte) of the Public exponent e; e = 65537 = 0x010001; 3-byte
                                    ULONG cbModulus;                            // The size(byte) of the modulus N; 4096/8 = 512-byte 
                                    ULONG cbPrime1;                             // The size(byte) of the p; 256-byte 
                                    ULONG cbPrime2;                             // The size(byte) of the q; 256-byte 
                                    BYTE PublicExponent[cbPublicExp];           // Array of Public Exponent e 
                                    BYTE Modulus[cbModulus];                    // Array of Modulus n
                                    BYTE Prime1[cbPrime1];                      // Array of Prime p 
                                    BYTE Prime2[cbPrime2];                      // Array of Prime q
    } PrivateKey_BLOB


    <Reference>
    https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob 
    https://stackoverflow.com/questions/58419870/how-to-use-bcrypt-for-rsa-asymmetric-encryption
    https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/007a0e26-7fc0-4079-9b63-2ad23f866836/bug-in-rsa-encryptiondecryption-using-cng?forum=windowssdk
    https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair
*/

#include <Windows.h>
#include <bcrypt.h> 
#include <stdio.h>
#include <stdlib.h> 

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define PRINT_PLAINTEXT 1
#define PRINT_CIPHERTEXT 2

#define SUCCESS 1 
#define FAIL 0

#define PulbicKeyBLOB_Size 539

BYTE plaintext[8] = {0x20, 0x19, 0x22, 0x43, 0x20, 0x19, 0x22, 0x43}; 

PBYTE ciphertext = NULL; 
DWORD ciphertextLength = 0;                      

BYTE e[3] = {0x01, 0x00, 0x01};
BYTE n[512] = {
                0xc7, 0xbd, 0xce, 0x0d, 0x93, 0x87, 0x60, 0x00, 0xb1, 0xf1, 0xe8, 0x89, 0x62, 0xd4, 0x99, 0x35, 
                0x1d, 0x78, 0x61, 0x97, 0x9a, 0x8e, 0x1a, 0x7d, 0xa6, 0x7c, 0xff, 0xfe, 0x13, 0xc4, 0x0d, 0xbb, 
                0x7f, 0xd7, 0xc9, 0x3c, 0x29, 0x7e, 0xbe, 0x13, 0x96, 0x22, 0x0f, 0x4b, 0xfc, 0x54, 0x37, 0x8a, 
                0x2a, 0xa2, 0x92, 0xdb, 0xe5, 0xd1, 0x67, 0xf5, 0x25, 0x92, 0x0f, 0x30, 0x53, 0x8f, 0xfb, 0x87, 
                0x59, 0xfd, 0x79, 0xa4, 0x5a, 0x91, 0xd3, 0xea, 0xd4, 0xb7, 0x4d, 0xfa, 0x02, 0x6d, 0xe7, 0x29, 
                0xac, 0x78, 0x94, 0xd4, 0x8d, 0x5d, 0xd7, 0x1a, 0x1c, 0xfc, 0x1f, 0xea, 0x33, 0x2f, 0xa0, 0xc7, 
                0xb9, 0xb2, 0x24, 0x92, 0x60, 0x11, 0x7e, 0x9c, 0xa4, 0xb1, 0xd4, 0x45, 0x2c, 0xee, 0x92, 0xdd, 
                0x4c, 0xab, 0x44, 0x48, 0x8e, 0x14, 0xbf, 0x8c, 0xd3, 0xd3, 0x7a, 0xd2, 0x2b, 0x59, 0xe2, 0xe3, 
                0xc3, 0xe5, 0xf4, 0xae, 0x1d, 0xcf, 0x83, 0x5e, 0x0b, 0x13, 0xbe, 0xac, 0x9c, 0x62, 0xf9, 0x90, 
                0x84, 0x15, 0xb5, 0x77, 0xb7, 0x0d, 0x0b, 0xaa, 0x0b, 0xf2, 0xf3, 0x64, 0xa5, 0x5a, 0x92, 0xf5, 
                0x88, 0x28, 0xa6, 0xcb, 0x12, 0xbe, 0x0c, 0xc1, 0x56, 0xa2, 0xb8, 0x57, 0x26, 0x33, 0x34, 0xb8, 
                0x96, 0x9f, 0x32, 0x6c, 0xf8, 0x49, 0x3f, 0x89, 0xac, 0x72, 0x79, 0x61, 0x96, 0x4c, 0x04, 0xb2, 
                0x45, 0xbb, 0x90, 0x3e, 0x2a, 0xe3, 0x34, 0x87, 0x53, 0x67, 0x3d, 0x30, 0xf2, 0x0d, 0x0e, 0x6d, 
                0xdc, 0xee, 0x18, 0xd4, 0x2c, 0xc2, 0x6a, 0x3f, 0x0a, 0xfe, 0xd3, 0xdc, 0x65, 0xfe, 0xbf, 0x0f, 
                0x44, 0x44, 0x16, 0xd1, 0x90, 0xea, 0xe3, 0x44, 0xde, 0x84, 0x03, 0xda, 0x6d, 0x58, 0x5d, 0xf1, 
                0x45, 0x54, 0x61, 0xe9, 0xc9, 0x52, 0x73, 0x65, 0x1b, 0xea, 0xdb, 0x4d, 0xf1, 0x21, 0x99, 0x77, 
                0x8f, 0x11, 0xdd, 0x14, 0x09, 0xa7, 0x1a, 0x36, 0xd9, 0x65, 0xa7, 0x2a, 0x20, 0x28, 0xf3, 0xcd, 
                0x4a, 0x2c, 0x5f, 0x95, 0xce, 0x8e, 0x0f, 0xec, 0xce, 0x25, 0x59, 0xc0, 0x41, 0xdd, 0x3a, 0xd5, 
                0x5a, 0xc6, 0x16, 0x00, 0x5d, 0x1b, 0xad, 0x52, 0xda, 0x9b, 0x81, 0x14, 0x9d, 0x43, 0x3b, 0x15, 
                0x81, 0x74, 0x00, 0xb0, 0x14, 0xaf, 0x36, 0x35, 0x19, 0x01, 0x85, 0x8c, 0x14, 0x36, 0x16, 0xac, 
                0xd8, 0xe1, 0xc5, 0xd6, 0x0f, 0xb4, 0x81, 0x86, 0x8a, 0x9e, 0xd2, 0xf4, 0x60, 0x7f, 0xa9, 0xf0, 
                0xa9, 0x94, 0x7b, 0xda, 0x13, 0x3b, 0xae, 0xfe, 0x5b, 0xe9, 0x47, 0x7f, 0xa7, 0xd0, 0x83, 0x05, 
                0x39, 0x11, 0x8c, 0xf8, 0x16, 0x14, 0xca, 0xab, 0xe1, 0xd3, 0x89, 0x9d, 0x1e, 0x24, 0x72, 0x3b, 
                0x08, 0x14, 0x6b, 0x84, 0xd6, 0x33, 0xe2, 0xb2, 0xd0, 0xba, 0x31, 0x70, 0xd8, 0x87, 0x89, 0x98, 
                0xee, 0x85, 0x7a, 0x62, 0xbf, 0xc2, 0x0b, 0xd3, 0x20, 0x33, 0x38, 0x64, 0xc7, 0xfc, 0x10, 0x54, 
                0x95, 0x88, 0xf1, 0xf0, 0x6e, 0xde, 0x5f, 0xa9, 0xe0, 0x53, 0x16, 0x1a, 0x33, 0x0f, 0x3e, 0x7c, 
                0x65, 0x45, 0x82, 0x57, 0x45, 0x72, 0x88, 0x6a, 0x9f, 0x08, 0x47, 0x59, 0xfd, 0x10, 0x5f, 0xf9, 
                0x46, 0x55, 0x0b, 0x9c, 0x99, 0xf7, 0x90, 0x77, 0x61, 0xa9, 0x10, 0xca, 0x5f, 0xcd, 0x55, 0x34, 
                0x88, 0xbf, 0x94, 0xf8, 0xd1, 0x90, 0x84, 0xe7, 0xf2, 0x6d, 0xa3, 0x4a, 0xfe, 0x54, 0x8e, 0x66, 
                0x77, 0x12, 0x57, 0x32, 0x8e, 0x03, 0x7d, 0x57, 0xd9, 0xe9, 0xa6, 0x9e, 0x88, 0xa7, 0x22, 0x28, 
                0x12, 0xcf, 0xa5, 0x75, 0x5c, 0x6e, 0xfc, 0xef, 0xa5, 0x14, 0x6f, 0x25, 0xd2, 0xd0, 0x65, 0x0e, 
                0x0e, 0x4a, 0xc3, 0x4a, 0xfe, 0x3a, 0xf9, 0xb5, 0x2c, 0xb8, 0x15, 0x0a, 0x42, 0x73, 0x76, 0x67}; 

typedef struct _PublicKey_BLOB {
                                ULONG Magic;                // Magic number of RSAKEY 
                                ULONG BitLength;            // The size(bit) of the modulus N  
                                ULONG cbPublicExp;          // The size(byte) of the Public exponent e;
                                ULONG cbModulus;            // The size(byte) of the modulus N; 
                                ULONG cbPrime1;             // The size(byte) of the p; 
                                ULONG cbPrime2;             // The size(byte) of the q; 
                                BYTE PublicExponent[3];     // Array of Public Exponent e; e = 65537 = 0x01, 0x00, 0x01
                                BYTE Modulus[512];          // Array of Modulus n; In RSA-4096, n = 4096-bit = 512-byte
} PublicKey_BLOB;


void PRINT(BYTE* arr, DWORD size, int flag)
{
    if(flag == PRINT_PLAINTEXT){
        printf("\nplaintext : ");
        for(int i = 0; i < size; i++){
            if(i % 16 == 0) printf("\n");
            printf("0x%02x\t", arr[i]);
        }
        printf("\n");
    }

    if(flag == PRINT_CIPHERTEXT){
        printf("\nciphertext : ");
        for(int i = 0; i < size; i++){
            if(i % 16 == 0) printf("\n");
            printf("0x%02x\t", arr[i]);
        }
        printf("\n");
    }
}


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


int SettingPublicKeyBLOB(PublicKey_BLOB** BLOB)
{
    *BLOB = (PublicKey_BLOB*)(malloc)(sizeof(PublicKey_BLOB)); 
    if(*BLOB == NULL) return FAIL; 

    (*BLOB)->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    (*BLOB)->BitLength = 4096;
    (*BLOB)->cbPublicExp = 3; 
    (*BLOB)->cbModulus = 512; 
    (*BLOB)->cbPrime1 = 0; 
    (*BLOB)->cbPrime2 = 0; 
    memcpy((*BLOB)->PublicExponent, e, 3); 
    memcpy((*BLOB)->Modulus, n, 512);

    return SUCCESS;
}


void FreePublicKeyBLOB(PublicKey_BLOB** BLOB)
{
    if((*BLOB) == NULL) return; 
    
    free(*BLOB);
    return; 
}


void RSA_4096_Test(BCRYPT_ALG_HANDLE ALG_HANDLE)                // RSA4096/PKCS1
{
    NTSTATUS status = 0;
    DWORD bufferSize = 0;
    BCRYPT_KEY_HANDLE PUBLICKEY_HANDLE = NULL; 

    PublicKey_BLOB* RSA_PUBLICKEY = NULL;                       // PulicKeyBLOB Setting         
    if(!SettingPublicKeyBLOB(&RSA_PUBLICKEY)){
        printf("Memory Allocation Fail...\n");
        FreePublicKeyBLOB(&RSA_PUBLICKEY);
        return;
    }

    status = BCryptImportKeyPair(
                                 ALG_HANDLE,                    // CNG Algorithm Handle 
                                 NULL,                          // Not use 
                                 BCRYPT_RSAPUBLIC_BLOB,         // Type of blob
                                 &PUBLICKEY_HANDLE,             // A pointer to Key Handle
                                 (PBYTE)&RSA_PUBLICKEY->Magic,  // Address of a buffer that contains the key blob
                                 PulbicKeyBLOB_Size,            // Size of the buffer that contains the key blob 
                                 BCRYPT_NO_KEY_VALIDATION);     // Flags 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptImportKeyPair fail\n", status);
        BCryptDestroyKey(PUBLICKEY_HANDLE);
        FreePublicKeyBLOB(&RSA_PUBLICKEY);
        return; 
    }


    status = BCryptEncrypt(                         // Calculate ciphertext length
                           PUBLICKEY_HANDLE,        // KEY HANDLE
                           plaintext,               // Address of the buffer that contains the plaintext 
                           sizeof(plaintext),       // Size of the buffer that contains the plaintext 
                           NULL,                    // A pointer to padding info used with asymetric; OAEP
                           NULL,                    // Address of the buffer that contains the Initial Vector 
                           0,                       // Size of the buffer that contains the Initial Vector
                           NULL,                    // Address of the buffer that receives the ciphertext. 
                           0,                       // Size of the buffer that receives the ciphertext
                           &ciphertextLength,       // Variable that receives number of bytes copied to ciphertext buffer
                           BCRYPT_PAD_PKCS1);       // Flags : Padding 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptEncrypt fail(Calculate ciphertextLength)\n", status);
        BCryptDestroyKey(PUBLICKEY_HANDLE);
        FreePublicKeyBLOB(&RSA_PUBLICKEY);
        return; 
    }
    else
    {
        ciphertext = (PBYTE)calloc(ciphertextLength, sizeof(BYTE));        
        if(ciphertext == NULL)
        {
            printf("Memory Allocation(ciphertext) Fail...\n");
            BCryptDestroyKey(PUBLICKEY_HANDLE);
            FreePublicKeyBLOB(&RSA_PUBLICKEY);
            return;
        }
    }


    status = BCryptEncrypt(                         // Encrypt data
                           PUBLICKEY_HANDLE,        // KEY HANDLE
                           plaintext,               // Address of the buffer that contains the plaintext 
                           sizeof(plaintext),       // Size of the buffer that contains the plaintext 
                           NULL,                    // A pointer to padding info used with asymetric; OAEP
                           NULL,                    // Address of the buffer that contains the Initial Vector 
                           0,                       // Size of the buffer that contains the Initial Vector
                           ciphertext,              // Address of the buffer that receives the ciphertext. 
                           ciphertextLength,        // Size of the buffer that receives the ciphertext
                           &bufferSize,             // Variable that receives number of bytes copied to ciphertext buffer
                           BCRYPT_PAD_PKCS1);       // Flags : Padding 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptEncrypt fail\n", status);
        free(ciphertext);
        BCryptDestroyKey(PUBLICKEY_HANDLE);
        FreePublicKeyBLOB(&RSA_PUBLICKEY);
        return; 
    }

    PRINT(plaintext, sizeof(plaintext), PRINT_PLAINTEXT);
    PRINT(ciphertext, ciphertextLength, PRINT_CIPHERTEXT);

    free(ciphertext);
    BCryptDestroyKey(PUBLICKEY_HANDLE);
    ciphertextLength = 0;
    FreePublicKeyBLOB(&RSA_PUBLICKEY);

    return; 
}


int main()
{   
    BCRYPT_ALG_HANDLE RSA_ALG = NULL;
    GET_ALG_HANDLE(&RSA_ALG);
    RSA_4096_Test(RSA_ALG);                         // RSA4096/PKCS1
    BCryptCloseAlgorithmProvider(RSA_ALG, 0);
    return 0; 
}