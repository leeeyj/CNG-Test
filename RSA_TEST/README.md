    [BCRYPT_RSAKEY_BLOB Structure]   
        
        typedef struct _BCRYPT_RSAKEY_BLOB {
                                            ULONG Magic;                // Magic number of RSAKEY 
                                            ULONG BitLength;            // The size(bit) of the modulus N  
                                            ULONG cbPublicExp;          // The size(byte) of the Public exponent e
                                            ULONG cbModulus;            // The size(byte) of the modulus N 
                                            ULONG cbPrime1;             // The size(byte) of the p 
                                            ULONG cbPrime2;             // The size(byte) of the q 
                                            } BCRYPT_RSAKEY_BLOB;       

    ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
    ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
   
      BLOB total size = 24-byte(RSA Key BLOB) + 3-byte(Array size of e) + 512-byte(Array size of n) + 256-byte(Array size of p) + 256-byte(Array size of q) = 1051-byte      
