
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
    [Encrypting Data]
        1. Generating Symmetric Key
           - Generate 128 or 192 or 256 bit key      
        2. Setting Cipher Algorithm Properties
           - Set Block Chain Mode 
        3. Getting Cipher Algorithm Properties 
           - Get Block/IV Length
        4. Encrypting Data  
           - Calculate Ciphertext Length
           - Data Encrpytion 
    ------------------------------------------------   
    [Clean Up Memory]
        1. Destroy Key Handle 
        2. Destroy Alg Handle
        3. Free Memory 
