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
    [Decrypting Data]
        1. Generate PrivateKey Blob
        2. Import PrivateKey 
        3. Calculate plaintext length 
        4. Decrypt Data 
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

    ----------------------------------------------------------------------------------------------------------------------------
    [RSA Public Key Blob Structure]           
    BCRYPT_RSAKEY_BLOB || PublicExponent[cbPublicExp] || Modulus[cbModulus]                
    typedef struct _PublicKey_BLOB {
                                    ULONG Magic;                                // Magic number of RSAKEY 
                                    ULONG BitLength;                            // The size(bit) of the modulus N; 4096-bit
                                    ULONG cbPublicExp;                          // The size(byte) of the Public exponent e; e = 65537 = 0x010001; 3-byte
                                    ULONG cbModulus;                            // The size(byte) of the modulus N; 4096/8 = 512-byte 
                                    ULONG cbPrime1;                             // The size(byte) of the p 
                                    ULONG cbPrime2;                             // The size(byte) of the q 
                                    BYTE PublicExponent[cbPublicExp];           // Array of Public Exponent e; e = 65537 = 0x010001 = 3-byte
                                    BYTE Modulus[cbModulus];                    // Array of Modulus n; 4096/8 = 512-byte
    } PublicKey_BLOB

    BLOB total size = 24-byte(RSA Key BLOB) + 3-byte(Array size of e) + 512-byte(Array size of n) = 539

    ----------------------------------------------------------------------------------------------------------------------------
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

#define PrivateKeyBLOB_Size 1051

BYTE ciphertext[512] = {
                        0x2a, 0x7d, 0x26, 0x8c, 0x08, 0xa9, 0x55, 0x64, 0xf1, 0x04, 0x76, 0xf4, 0x3f, 0x8e, 0x1f, 0xcd,
                        0x4c, 0xb6, 0x9b, 0xc8, 0xd1, 0x13, 0x74, 0x2c, 0x5e, 0xc9, 0x13, 0x57, 0xd1, 0x5a, 0x6d, 0xb4,
                        0x20, 0x1e, 0x40, 0xbe, 0xe6, 0xaf, 0x03, 0x72, 0x9f, 0xfe, 0x7d, 0x90, 0x84, 0x72, 0x09, 0x3b,
                        0x38, 0x7a, 0x4f, 0xa3, 0x5c, 0x50, 0xb1, 0x47, 0x82, 0xc4, 0xee, 0x05, 0x51, 0xdb, 0xcf, 0x4d,
                        0x07, 0xc1, 0x93, 0xf4, 0x38, 0xe6, 0x5e, 0x6f, 0x2a, 0xc5, 0x5c, 0x59, 0x0c, 0xea, 0x22, 0x80,
                        0x38, 0x2f, 0xe6, 0x97, 0xfa, 0x45, 0xcd, 0xbe, 0x98, 0x59, 0xdd, 0xdf, 0xf8, 0xec, 0xf6, 0x28,
                        0x3a, 0x9b, 0x73, 0xee, 0xfb, 0x49, 0xb0, 0x86, 0x83, 0xa3, 0x71, 0xc2, 0x57, 0xec, 0xe5, 0x9f,
                        0x23, 0x8b, 0xee, 0xb5, 0xfc, 0xb2, 0xb7, 0xda, 0x6d, 0x10, 0xcd, 0xcb, 0xe1, 0xdb, 0xaf, 0xfc,
                        0x96, 0x6a, 0xfb, 0x6d, 0x2f, 0x98, 0x4a, 0xec, 0x4b, 0xd8, 0x9f, 0xef, 0x74, 0x5a, 0xf7, 0xce,
                        0xb5, 0x4c, 0x30, 0xc5, 0x8a, 0x59, 0x03, 0x92, 0x3d, 0x9d, 0x28, 0x37, 0xa3, 0x4b, 0xa7, 0x5c,
                        0xe1, 0x0d, 0x09, 0x35, 0x41, 0xc9, 0xa2, 0x64, 0xbf, 0xeb, 0x6e, 0x5d, 0x9b, 0x7b, 0x55, 0x35, 
                        0xa4, 0x44, 0x21, 0xbc, 0xb3, 0xa8, 0x4e, 0xe0, 0xe4, 0x8b, 0x7d, 0xb8, 0x74, 0x8c, 0xe9, 0x2e,
                        0x02, 0x12, 0x9b, 0x0c, 0x59, 0xa3, 0xdd, 0x14, 0xf0, 0x70, 0x3c, 0xca, 0x07, 0x58, 0x3f, 0x7f,
                        0x93, 0xac, 0x80, 0x66, 0x20, 0xb7, 0x2b, 0x05, 0xf4, 0xd0, 0x77, 0x2a, 0x21, 0x78, 0x5f, 0x77,
                        0x4f, 0x91, 0x0a, 0xb2, 0x93, 0x28, 0xf5, 0x6f, 0x29, 0x8a, 0x2d, 0xab, 0xad, 0xa6, 0x47, 0x3a,
                        0xe5, 0x81, 0xe7, 0x64, 0x3e, 0x8c, 0xca, 0xe5, 0x20, 0x3a, 0x41, 0x91, 0xb5, 0x8f, 0xb0, 0x9b,
                        0xef, 0x4d, 0xdf, 0x83, 0x7c, 0xe8, 0xcc, 0xd8, 0x1a, 0x30, 0x2f, 0x3e, 0xb6, 0xb3, 0xf9, 0xed,
                        0xca, 0x47, 0x16, 0x36, 0x6e, 0x22, 0xc8, 0xc4, 0xe5, 0xdf, 0xd7, 0xcb, 0x6a, 0x69, 0xf7, 0x17,
                        0x7e, 0xff, 0x46, 0x4e, 0x89, 0x75, 0x49, 0xe1, 0x1f, 0xa9, 0x64, 0xfe, 0x0d, 0x47, 0x56, 0x53,
                        0x20, 0x94, 0x80, 0xbb, 0x37, 0x79, 0xda, 0x1e, 0xe8, 0x65, 0xc2, 0x64, 0x67, 0x2e, 0xd4, 0x3e,
                        0x5f, 0xb4, 0x64, 0xd2, 0xb6, 0x1d, 0x6e, 0xae, 0xef, 0xae, 0xda, 0xee, 0xf5, 0x5b, 0x2e, 0x6d,
                        0x5c, 0x36, 0x14, 0x99, 0x92, 0xbc, 0xb5, 0x0e, 0xaf, 0xa1, 0xcc, 0x8b, 0xda, 0xa1, 0xe2, 0x12,
                        0xcf, 0xf2, 0x98, 0xae, 0x39, 0xcc, 0xec, 0xfd, 0x34, 0xb0, 0x1a, 0x6f, 0xdc, 0x1b, 0x17, 0x2d,
                        0xe2, 0x58, 0x29, 0xb0, 0x1b, 0x15, 0x21, 0xed, 0x55, 0x96, 0x40, 0xde, 0xae, 0x96, 0xea, 0xb7,
                        0x6b, 0xfe, 0x4b, 0x01, 0xc1, 0xb2, 0xcb, 0x73, 0x0e, 0xd7, 0x2d, 0x3c, 0x9e, 0xf7, 0x71, 0xc8,
                        0x1c, 0x35, 0x97, 0x63, 0x09, 0xf1, 0x30, 0x6a, 0xc5, 0x64, 0x3f, 0xcf, 0x2f, 0x6a, 0x16, 0x63, 
                        0xbc, 0x5c, 0xce, 0x95, 0xf7, 0xe8, 0x39, 0x64, 0x2e, 0x16, 0xe1, 0xc0, 0x43, 0x11, 0x6a, 0xf5,
                        0x3b, 0x3e, 0x91, 0x88, 0xaa, 0x8e, 0xfd, 0xdd, 0x09, 0x6b, 0xaf, 0x10, 0xd6, 0x49, 0x39, 0x2d,
                        0x42, 0x07, 0xb7, 0x20, 0x24, 0xf1, 0x1d, 0xd4, 0x8c, 0xfe, 0xc8, 0xa1, 0x55, 0x43, 0x04, 0x22,
                        0xbf, 0x2b, 0xb1, 0x14, 0x65, 0xd5, 0x61, 0xcf, 0x48, 0x44, 0xb0, 0xdf, 0x1e, 0x2f, 0xd1, 0xbd,
                        0xaf, 0xc5, 0xd3, 0x18, 0x5f, 0xa8, 0xb4, 0x74, 0x0e, 0xcb, 0x0e, 0x2f, 0x64, 0xf4, 0xcb, 0x57,
                        0x1a, 0x68, 0xaa, 0xe1, 0x5f, 0xa2, 0x8f, 0x66, 0x56, 0x4a, 0x07, 0x68, 0x4b, 0xed, 0xff, 0x0c}; 

PBYTE plaintext = NULL; 
DWORD plaintextLength = 0;                      

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

BYTE p[256] = {
                0xd7, 0xc2, 0xaa, 0x7b, 0x89, 0x3f, 0xb3, 0x2f, 0xf1, 0x13, 0x00, 0x26, 0xff, 0x32, 0xa5, 0x25, 
                0xb8, 0xa1, 0x57, 0x28, 0xe1, 0xfa, 0x35, 0x85, 0x46, 0x3c, 0xff, 0x10, 0x3e, 0xc9, 0x4a, 0xef, 
                0xdf, 0xe1, 0x5c, 0x2d, 0x39, 0x66, 0x74, 0x5b, 0xba, 0x94, 0xaa, 0x10, 0x83, 0x75, 0xf4, 0x03, 
                0x99, 0x58, 0x16, 0x54, 0xfe, 0x0c, 0xbe, 0x8a, 0x9b, 0x14, 0x51, 0x36, 0x77, 0x5c, 0x03, 0xbc, 
                0x0e, 0x19, 0x5e, 0xe3, 0x08, 0xda, 0xbc, 0x20, 0x57, 0x28, 0x79, 0xa1, 0xbd, 0x59, 0x94, 0x3e, 
                0xc3, 0xfc, 0x0d, 0x05, 0x49, 0x84, 0x9a, 0x7a, 0x9d, 0x26, 0xfd, 0x09, 0xa8, 0xbb, 0x7d, 0xf4, 
                0x30, 0x7a, 0x0e, 0xd7, 0x36, 0x48, 0x0a, 0x2a, 0x89, 0x56, 0x3b, 0x75, 0xa9, 0x42, 0x8a, 0xce, 
                0x00, 0x3a, 0x22, 0xef, 0x0c, 0xf9, 0x6d, 0x1f, 0x54, 0x91, 0xcf, 0x6f, 0xa0, 0xea, 0x49, 0x92, 
                0x96, 0x28, 0x61, 0x36, 0xa7, 0x02, 0x4a, 0x9c, 0xf5, 0x30, 0x9b, 0x79, 0x0e, 0xc3, 0x54, 0x53, 
                0x76, 0xe9, 0xd9, 0x10, 0x92, 0x39, 0x54, 0xe5, 0x25, 0xaf, 0xe2, 0x31, 0x5a, 0x0c, 0x46, 0x6e, 
                0x25, 0x5a, 0xe0, 0x92, 0x9b, 0x4c, 0xa3, 0x7d, 0x51, 0x42, 0x31, 0x84, 0x9c, 0xa6, 0xe3, 0xdf, 
                0x22, 0x2c, 0x97, 0x3d, 0x3c, 0x03, 0x58, 0x51, 0xb2, 0x7e, 0x65, 0xdd, 0x86, 0xf1, 0xe4, 0xb2, 
                0x83, 0x6a, 0xc8, 0x55, 0x48, 0x7e, 0xb1, 0xfc, 0x68, 0x17, 0xb0, 0x89, 0xb4, 0xec, 0x25, 0xb4, 
                0x20, 0x79, 0x49, 0x08, 0x07, 0xbf, 0xd6, 0x50, 0x8b, 0xaa, 0x68, 0x1f, 0x73, 0x6c, 0xf8, 0xa3, 
                0x39, 0x00, 0x01, 0xcc, 0x44, 0x6b, 0x5a, 0x5b, 0x93, 0x99, 0xb9, 0xb3, 0x8b, 0x6f, 0x9b, 0x0f, 
                0x99, 0x7a, 0xec, 0x20, 0x74, 0x57, 0x09, 0xa9, 0xb5, 0x11, 0x82, 0x22, 0xe0, 0x24, 0x89, 0xb9}; 

BYTE q[256] = {
                0xec, 0xfe, 0x52, 0xc0, 0x6f, 0x52, 0x9f, 0xd9, 0x7a, 0x32, 0xdb, 0x8d, 0xe9, 0x83, 0xc5, 0x1e, 
                0x12, 0xce, 0x11, 0x38, 0x36, 0x97, 0xa3, 0x3b, 0x0b, 0xe9, 0x81, 0x61, 0xf6, 0xc4, 0x42, 0xa5, 
                0xe5, 0x4b, 0xb1, 0xc1, 0x78, 0xb2, 0x8b, 0x0b, 0x95, 0xbc, 0x4b, 0xf7, 0x85, 0x0e, 0x58, 0xd4, 
                0x69, 0x94, 0x00, 0xe5, 0xd4, 0x08, 0xbc, 0xbf, 0x09, 0x46, 0x96, 0x1d, 0xf9, 0x67, 0x96, 0x4f, 
                0xc1, 0x69, 0x85, 0xa1, 0x6a, 0x1d, 0x1a, 0x48, 0xfb, 0x8b, 0x84, 0x57, 0x6e, 0xf3, 0xd9, 0xad, 
                0x00, 0x99, 0xe2, 0xd0, 0xd9, 0xbb, 0xe0, 0x57, 0x83, 0x11, 0x74, 0xb3, 0xce, 0x5b, 0xcf, 0xbb, 
                0xc3, 0x95, 0xf3, 0x78, 0x8c, 0xd7, 0xc9, 0x0f, 0x75, 0xca, 0xeb, 0xcf, 0x52, 0x2f, 0xa9, 0xc0, 
                0x85, 0xda, 0x73, 0x49, 0xea, 0x91, 0xf2, 0xee, 0xd7, 0x3c, 0xaa, 0xcb, 0xa3, 0x18, 0xf1, 0x9c, 
                0xc1, 0xab, 0x6f, 0x1e, 0x8c, 0x90, 0x39, 0xa7, 0xa9, 0x63, 0x46, 0x24, 0x8a, 0x3e, 0xe0, 0x43, 
                0x3c, 0x90, 0xeb, 0xff, 0x6e, 0x93, 0x33, 0x4b, 0x6c, 0xe7, 0x10, 0x35, 0x98, 0xb1, 0xe8, 0x48, 
                0x26, 0x0a, 0x43, 0xd0, 0xa5, 0x3c, 0xf6, 0x96, 0xf6, 0x4f, 0xb8, 0x4d, 0xca, 0x6f, 0x8c, 0xd1, 
                0x76, 0x0b, 0x97, 0x84, 0x3a, 0x99, 0x66, 0xb3, 0x22, 0xe2, 0x10, 0x24, 0x9f, 0x88, 0xff, 0x15, 
                0x27, 0xc9, 0xb4, 0x36, 0x66, 0x81, 0x98, 0x39, 0xf0, 0x27, 0xc1, 0xbf, 0x68, 0x09, 0xd6, 0x89, 
                0xe8, 0x80, 0x52, 0x14, 0x90, 0xf1, 0x21, 0x88, 0x66, 0x93, 0x45, 0xda, 0xdc, 0xc6, 0xb0, 0xfd, 
                0xdd, 0x4a, 0x5a, 0x68, 0x40, 0xcc, 0x05, 0xd8, 0x35, 0x56, 0x73, 0x2d, 0xc0, 0x52, 0x11, 0xf8, 
                0xd4, 0xce, 0x2c, 0x83, 0x37, 0x3e, 0x6f, 0x3e, 0x30, 0x22, 0xfc, 0xab, 0x2a, 0xad, 0x91, 0x1f};


typedef struct _PrivateKey_BLOB {
                                ULONG Magic;                // Magic number of RSAKEY 
                                ULONG BitLength;            // The size(bit) of the modulus N  
                                ULONG cbPublicExp;          // The size(byte) of the Public exponent e
                                ULONG cbModulus;            // The size(byte) of the modulus N 
                                ULONG cbPrime1;             // The size(byte) of the p 
                                ULONG cbPrime2;             // The size(byte) of the q 
                                BYTE PublicExponent[3];     // Array of Public Exponent e; e = 65537 = 0x01, 0x00, 0x01
                                BYTE Modulus[512];          // Array of Modulus n; In RSA-4096, n = 4096-bit = 512-byte
                                BYTE p[256];                // Array of Prime p
                                BYTE q[256];                // Array of Prime q
} PrivateKey_BLOB;


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


int SettingPublicKeyBLOB(PrivateKey_BLOB** BLOB)
{
    *BLOB = (PrivateKey_BLOB*)(malloc)(sizeof(PrivateKey_BLOB));      
    if(*BLOB == NULL) return FAIL; 

    (*BLOB)->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    (*BLOB)->BitLength = 4096;
    (*BLOB)->cbPublicExp = 3; 
    (*BLOB)->cbModulus = 512; 
    (*BLOB)->cbPrime1 = 256; 
    (*BLOB)->cbPrime2 = 256; 
    memcpy((*BLOB)->PublicExponent, e, 3); 
    memcpy((*BLOB)->Modulus, n, 512);
    memcpy((*BLOB)->p, p, 256);
    memcpy((*BLOB)->q, q, 256);

    return SUCCESS;
}


void FreePrivateKeyBLOB(PrivateKey_BLOB** BLOB)
{
    if((*BLOB) == NULL) return; 
    
    free(*BLOB);
    return; 
}


void RSA_4096_Test(BCRYPT_ALG_HANDLE ALG_HANDLE)                // RSA4096/PKCS1
{
    NTSTATUS status = 0;
    DWORD bufferSize = 0;
    BCRYPT_KEY_HANDLE PRIVATEKEY_HANDLE = NULL; 

    PrivateKey_BLOB* RSA_PRIVATEKEY = NULL;                       // PrivateKeyBLOB Setting         
    if(!SettingPublicKeyBLOB(&RSA_PRIVATEKEY)){
        printf("Memory Allocation Fail...\n");
        FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
        return;
    }

    status = BCryptImportKeyPair(
                                 ALG_HANDLE,                        // CNG Algorithm Handle 
                                 NULL,                              // Not use 
                                 BCRYPT_RSAPRIVATE_BLOB,            // Type of blob
                                 &PRIVATEKEY_HANDLE,                // A pointer to Key Handle
                                 (PBYTE)&RSA_PRIVATEKEY->Magic,     // Address of a buffer that contains the key blob
                                 PrivateKeyBLOB_Size,               // Size of the buffer that contains the key blob 
                                 BCRYPT_NO_KEY_VALIDATION);         // Flags 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptImportKeyPair fail\n", status);
        BCryptDestroyKey(PRIVATEKEY_HANDLE);
        FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
        return; 
    }


    status = BCryptDecrypt(                         // Calculate plaintext length
                           PRIVATEKEY_HANDLE,       // KEY HANDLE
                           ciphertext,              // Address of the buffer that contains the ciphertext 
                           sizeof(ciphertext),      // Size of the buffer that contains the ciphertext 
                           NULL,                    // A pointer to padding info used with asymetric; OEAP
                           NULL,                    // Address of the buffer that contains the Initial Vector 
                           0,                       // Size of the buffer that contains the Initial Vector
                           NULL,                    // Address of the buffer that receives the plaintext. 
                           0,                       // Size of the buffer that receives the plaintext
                           &plaintextLength,        // Variable that receives number of bytes copied to plaintext buffer
                           BCRYPT_PAD_PKCS1);       // Flags : Padding 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptDecrypt fail(Calculate plaintextLength)\n", status);
        BCryptDestroyKey(PRIVATEKEY_HANDLE);
        FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
        return; 
    }
    else
    {
        plaintext = (PBYTE)calloc(plaintextLength, sizeof(BYTE));        
        if(plaintext == NULL)
        {
            printf("Memory Allocation(plaintext) Fail...\n");
            BCryptDestroyKey(PRIVATEKEY_HANDLE);
            FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
            return;
        }
    }


    status = BCryptDecrypt(                         // Decrypt data
                           PRIVATEKEY_HANDLE,       // KEY HANDLE
                           ciphertext,              // Address of the buffer that contains the ciphertext 
                           sizeof(ciphertext),      // Size of the buffer that contains the ciphertext 
                           NULL,                    // A pointer to padding info used with asymetric; OAEP
                           NULL,                    // Address of the buffer that contains the Initial Vector 
                           0,                       // Size of the buffer that contains the Initial Vector
                           plaintext,               // Address of the buffer that receives the plaintext. 
                           plaintextLength,         // Size of the buffer that receives the plaintext
                           &plaintextLength,        // Variable that receives number of bytes copied to plaintext buffer
                           BCRYPT_PAD_PKCS1);       // Flags : Padding 
    if(!NT_SUCCESS(status))
    {
        printf("Error Code : %x \n BCryptDecrypt fail\n", status);
        free(plaintext);
        BCryptDestroyKey(PRIVATEKEY_HANDLE);
        FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
        return; 
    }

    PRINT(plaintext, plaintextLength, PRINT_PLAINTEXT);
    PRINT(ciphertext, sizeof(ciphertext), PRINT_CIPHERTEXT);

    free(plaintext);
    BCryptDestroyKey(PRIVATEKEY_HANDLE);
    plaintextLength = 0;
    FreePrivateKeyBLOB(&RSA_PRIVATEKEY);

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