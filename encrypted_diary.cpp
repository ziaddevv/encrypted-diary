#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>

class EncryptedDiary {
private:
    std::string password;
    const int SALT_SIZE = 8;
    const int KEY_SIZE = 32;  // 256 bits
    const int IV_SIZE = 16;   // 128 bits
    
    bool deriveKeyAndIV(const std::string& password, const unsigned char* salt,
                      unsigned char* key, unsigned char* iv) {
        // Use OpenSSL's key derivation function
        return PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
                                     salt, SALT_SIZE, 1000, KEY_SIZE, key) == 1 &&
               PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(),
                                     salt, SALT_SIZE, 1000, IV_SIZE, iv) == 1;
    }

public:
    EncryptedDiary(const std::string& pwd) : password(pwd) {
        // Initialize OpenSSL library
        OpenSSL_add_all_algorithms();
    }
    
    ~EncryptedDiary() {
        // Clean up OpenSSL
        EVP_cleanup();
    }
    
    bool encrypt(const std::string& plaintext, const std::string& filename) {
        std::ofstream outFile(filename, std::ios::binary);
        if (!outFile) {
            std::cerr << "Error: Could not open file for writing: " << filename << std::endl;
            return false;
        }
        
        // Generate a random salt
        unsigned char salt[SALT_SIZE];
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            std::cerr << "Error: Failed to generate random salt" << std::endl;
            return false;
        }
        
        // Write salt to file
        outFile.write(reinterpret_cast<char*>(salt), SALT_SIZE);
        
        // Derive key and IV from password and salt
        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        if (!deriveKeyAndIV(password, salt, key, iv)) {
            std::cerr << "Error: Failed to derive key and IV" << std::endl;
            return false;
        }
        
        // Create and initialize the context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error: Failed to create cipher context" << std::endl;
            return false;
        }
        
        // Initialize the encryption operation
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "Error: Failed to initialize encryption" << std::endl;
            return false;
        }
        
        // Determine required buffer size
        int ciphertext_len;
        int len;
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        
        // Encrypt the plaintext
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                            reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                            plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "Error: Failed during encryption" << std::endl;
            return false;
        }
        ciphertext_len = len;
        
        // Finalize the encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "Error: Failed to finalize encryption" << std::endl;
            return false;
        }
        ciphertext_len += len;
        
        // Clean up
        EVP_CIPHER_CTX_free(ctx);
        
        // Write the encrypted data to file
        outFile.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        outFile.close();
        
        return true;
    }
    
    std::string decrypt(const std::string& filename) {
        std::ifstream inFile(filename, std::ios::binary);
        if (!inFile) {
            std::cerr << "Error: Could not open file for reading: " << filename << std::endl;
            return "";
        }
        
        // Read the salt
        unsigned char salt[SALT_SIZE];
        inFile.read(reinterpret_cast<char*>(salt), SALT_SIZE);
        if (inFile.gcount() != SALT_SIZE) {
            std::cerr << "Error: Failed to read salt from file" << std::endl;
            return "";
        }
        
        // Derive key and IV from password and salt
        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        if (!deriveKeyAndIV(password, salt, key, iv)) {
            std::cerr << "Error: Failed to derive key and IV" << std::endl;
            return "";
        }
        
        // Read the ciphertext
        std::vector<unsigned char> ciphertext(
            (std::istreambuf_iterator<char>(inFile)),
            std::istreambuf_iterator<char>()
        );
        inFile.close();
        
        // Create and initialize the context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error: Failed to create cipher context" << std::endl;
            return "";
        }
        
        // Initialize the decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "Error: Failed to initialize decryption" << std::endl;
            return "";
        }
        
        // Determine required buffer size
        int plaintext_len;
        int len;
        std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
        
        // Decrypt the ciphertext
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                            ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "Error: Failed during decryption" << std::endl;
            return "";
        }
        plaintext_len = len;
        
        // Finalize the decryption
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "Error: Failed to finalize decryption. Wrong password?" << std::endl;
            return "";
        }
        plaintext_len += len;
        
        // Clean up
        EVP_CIPHER_CTX_free(ctx);
        
        // Convert plaintext to string and return
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }
};

int main() {
    std::string choice;
    std::string filename;
    std::string password;
    
    std::cout << "===== Encrypted Diary =====" << std::endl;
    std::cout << "1. Encrypt diary entry" << std::endl;
    std::cout << "2. Decrypt diary entry" << std::endl;
    std::cout << "Enter your choice (1 or 2): ";
    std::getline(std::cin, choice);
    
    std::cout << "Enter the filename: ";
    std::getline(std::cin, filename);
    
    std::cout << "Enter your password: ";
    std::getline(std::cin, password);
    
    EncryptedDiary diary(password);
    
    if (choice == "1") {
        std::string entry;
        std::cout << "Enter your diary entry (type 'END' on a new line when finished):" << std::endl;
        std::string line;
        while (std::getline(std::cin, line) && line != "END") {
            entry += line + "\n";
        }
        
        if (diary.encrypt(entry, filename)) {
            std::cout << "Diary entry encrypted and saved to " << filename << std::endl;
        } else {
            std::cout << "Failed to encrypt diary entry." << std::endl;
        }
    } else if (choice == "2") {
        std::string decrypted = diary.decrypt(filename);
        if (!decrypted.empty()) {
            std::cout << "\n===== Decrypted Diary Entry =====" << std::endl;
            std::cout << decrypted << std::endl;
            std::cout << "=================================" << std::endl;
        } else {
            std::cout << "Failed to decrypt diary entry." << std::endl;
        }
    } else {
        std::cout << "Invalid choice. Please run the program again." << std::endl;
    }
    
    return 0;
}
