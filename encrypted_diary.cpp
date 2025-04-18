#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>

using namespace std;

class EncryptedDiary {
private:
    string password;
    const int SALT_SIZE = 8;
    const int KEY_SIZE = 32;  // 256 bits
    const int IV_SIZE = 16;   // 128 bits
    
    bool deriveKeyAndIV(const string& password, const unsigned char* salt,
                      unsigned char* key, unsigned char* iv) {
        return PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
                                     salt, SALT_SIZE, 1000, KEY_SIZE, key) == 1 &&
               PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
                                     salt, SALT_SIZE, 1000, IV_SIZE, iv) == 1;
    }

public:
    EncryptedDiary(const string& pwd) : password(pwd) {
        OpenSSL_add_all_algorithms();
    }
    
    ~EncryptedDiary() {
        EVP_cleanup();
    }
    
    bool encrypt(const string& plaintext, const string& filename) {
        ofstream outFile(filename, ios::binary);
        if (!outFile) {
            cerr << "Error: Could not open file for writing: " << filename << endl;
            return false;
        }
        
        unsigned char salt[SALT_SIZE];
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            cerr << "Error: Failed to generate random salt" << endl;
            return false;
        }
        
        outFile.write(reinterpret_cast<char*>(salt), SALT_SIZE);
        
        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        if (!deriveKeyAndIV(password, salt, key, iv)) {
            cerr << "Error: Failed to derive key and IV" << endl;
            return false;
        }
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error: Failed to create cipher context" << endl;
            return false;
        }
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            cerr << "Error: Failed to initialize encryption" << endl;
            return false;
        }
        
        int ciphertext_len;
        int len;
        vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                            reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                            plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            cerr << "Error: Failed during encryption" << endl;
            return false;
        }
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            cerr << "Error: Failed to finalize encryption" << endl;
            return false;
        }
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        outFile.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        outFile.close();
        
        return true;
    }
    
    string decrypt(const string& filename) {
        ifstream inFile(filename, ios::binary);
        if (!inFile) {
            cerr << "Error: Could not open file for reading: " << filename << endl;
            return "";
        }
        
        unsigned char salt[SALT_SIZE];
        inFile.read(reinterpret_cast<char*>(salt), SALT_SIZE);
        if (inFile.gcount() != SALT_SIZE) {
            cerr << "Error: Failed to read salt from file" << endl;
            return "";
        }
        
        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        if (!deriveKeyAndIV(password, salt, key, iv)) {
            cerr << "Error: Failed to derive key and IV" << endl;
            return "";
        }
        
        vector<unsigned char> ciphertext(
            (istreambuf_iterator<char>(inFile)),
            istreambuf_iterator<char>()
        );
        inFile.close();
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            cerr << "Error: Failed to create cipher context" << endl;
            return "";
        }
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            cerr << "Error: Failed to initialize decryption" << endl;
            return "";
        }
        
        int plaintext_len;
        int len;
        vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                            ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            cerr << "Error: Failed during decryption" << endl;
            return "";
        }
        plaintext_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            cerr << "Error: Failed to finalize decryption. Wrong password?" << endl;
            return "";
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }
};

int main() {
    string choice;
    string filename;
    string password;
    
    cout << "===== Encrypted Diary =====" << endl;
    cout << "1. Encrypt diary entry" << endl;
    cout << "2. Decrypt diary entry" << endl;
    cout << "Enter your choice (1 or 2): ";
    getline(cin, choice);
    
    cout << "Enter the filename: ";
    getline(cin, filename);
    
    cout << "Enter your password: ";
    getline(cin, password);
    
    EncryptedDiary diary(password);
    
    if (choice == "1") {
        string entry;
        cout << "Enter your diary entry (type 'END' on a new line when finished):" << endl;
        string line;
        while (getline(cin, line) && line != "END") {
            entry += line + "\n";
        }
        
        if (diary.encrypt(entry, filename)) {
            cout << "Diary entry encrypted and saved to " << filename << endl;
        } else {
            cout << "Failed to encrypt diary entry." << endl;
        }
    } else if (choice == "2") {
        string decrypted = diary.decrypt(filename);
        if (!decrypted.empty()) {
            cout << "\n===== Decrypted Diary Entry =====" << endl;
            cout << decrypted << endl;
            cout << "=================================" << endl;
        } else {
            cout << "Failed to decrypt diary entry." << endl;
        }
    } else {
        cout << "Invalid choice. Please run the program again." << endl;
    }
    
    return 0;
}
