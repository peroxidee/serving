int AESDecrypt(unsigned char* payload, DWORD payload_len, char* key, size_t keylen) {

    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    BOOL CryptAcquire = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (CryptAcquire == false) {
        //printf("CryptAcquireContextW Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptCreate = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    if (CryptCreate == false) {
        //printf("CryptCreateHash Failed: %d\n", GetLastError());
        return -1;
    }


    BOOL CryptHash = CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
    if (CryptHash == false) {
        //printf("CryptHashData Failed: %d\n", GetLastError());
        return -1;
    }



    BOOL CryptDerive = CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    if (CryptDerive == false) {
        //printf("CryptDeriveKey Failed: %d\n", GetLastError());
        return -1;
    }



    BOOL Crypt_Decrypt = CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len);
    if (Crypt_Decrypt == false) {
        //printf("CryptDecrypt Failed: %d\n", GetLastError());
        return -1;
    }



    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}
