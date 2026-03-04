#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>  
#include "types.h"
#include <openssl/sha.h>  
#include <openssl/evp.h>


struct User {
    byte_vec saltAndHashedPassword; // SHA256(salt + password)
    byte_vec iv;                    // IV to encrypt private key
    byte_vec salt;                  // Salt for hashing of password
    byte_vec publicKey;             // pub_key
    byte_vec privateKey;            // private key encrypted
    bool isFirstLogin;
    bool keysDeleted;               // field to track key deletion status
};

class UserDatabase {
private:
    std::unordered_map<std::string, User> users;
    std::string filename;
    byte_vec db_encryption_key;     // Chiave per cifrare l'intero database attualmente non usata

    byte_vec hashPassword(const std::string& password, const byte_vec& salt) {
        byte_vec hash(SHA256_DIGEST_LENGTH);
        byte_vec salted_password(password.begin(), password.end());
        salted_password.insert(salted_password.end(), salt.begin(), salt.end());
        
        SHA256(salted_password.data(), salted_password.size(), hash.data());
        return hash;
    }

public:
    UserDatabase(const std::string& db_file);
    size_t userCount() const;
    void printAll() const;
    void printLimited() const;

    bool userExists(const std::string& username) const;
    const User& getUser(const std::string& username) const;

    // User management
    bool addUser(const std::string& username, const std::string& password);
    bool authoriseUser(const std::string& username, const std::string& password);
    bool changePassword(const std::string& username, const std::string& old_password, const std::string& new_password);
    bool createKeys(const std::string& username, const std::string& password);
    bool deleteKeys(const std::string& username, const std::string& password);
    bool decryptPrivateKey(const std::string &username, byte_vec& file_content, const std::string& password, byte_vec& error_msg, EVP_PKEY** priv_key);
    bool getUserPublicKey(const std::string& username, byte_vec& public_key, byte_vec& msg);
    
    // Database persistence
    bool saveToFile();
    bool loadFromFile();
    
    // Initialization
    void initializeDefaultUsers();
};