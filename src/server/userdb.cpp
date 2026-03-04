#include "userdb.h"
#include "utility.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <openssl/x509.h>  // For d2i_PUBKEY
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/pem.h>  // PEM_write_bio_PUBKEY
#include <openssl/err.h>  // ERR_print_errors_fp
#include <openssl/evp.h>  // EVP_PKEY


UserDatabase::UserDatabase(const std::string& db_file) : filename(db_file) {
    
}

size_t UserDatabase::userCount() const {
    return users.size();
}

void UserDatabase::printLimited() const {
    std::cout << "\n=== DATABASE INFO ===" << std::endl;
    std::cout << "Number of users: " << users.size() << "\n" << std::endl;

    for (const auto& [username, user] : users) {
        if (users.empty()) {
            std::cout << "Database empty - no registered user" << std::endl;
            return;
        }   

        std::cout << "Username: " << username << std::endl;
        std::cout << "  First login: " << (user.isFirstLogin ? "Yes" : "No") << std::endl;
        std::cout << "  Keys deleted: " << (user.keysDeleted ? "Yes" : "No") << std::endl;
        std::cout << "  Public Key: ";
        if (user.publicKey.empty()) {
            std::cout << "Empty" << std::endl;
        } else {
            std::cout << "Present (" << user.publicKey.size() << " bytes)" << std::endl;
        }
        std::cout << "  Private Key Encrypted: ";
        if (user.privateKey.empty()) {
            std::cout << "Empty" << std::endl;
        } else {
            std::cout << "Present (" << user.privateKey.size() << " bytes)" << std::endl;
        }
        std::cout << "--------------------------------" << std::endl;
    }
    std::cout << "=== DATABASE END ===" << std::endl;
}

void UserDatabase::printAll() const {

    std::cout << "\n=== DATABASE INFO ===" << std::endl;
    std::cout << "Number of users: " << users.size() << "\n" << std::endl;

    for (const auto& [username, user] : users) {
        if (users.empty()) {
            std::cout << "Database empty - no registered user" << std::endl;
            return;
        }   

        std::cout << "Username: " << username << std::endl;
        std::cout << "  Salt: ";
        for (auto b : user.salt) {
            printf("%02x", b);
        }
        std::cout << std::endl;
        std::cout << "  Password hash (SHA256): ";
        for (auto b : user.saltAndHashedPassword) {
            printf("%02x", b);
        }
        std::cout << std::endl;
        std::cout << "  First login: " << (user.isFirstLogin ? "Yes" : "No") << std::endl;
        std::cout << "  Keys deleted: " << (user.keysDeleted ? "Yes" : "No") << std::endl;
        std::cout << "  Public Key: ";
        if (user.publicKey.empty()) {
            std::cout << "Empty" << std::endl;
        } else {
            std::cout << "Present (" << user.publicKey.size() << " bytes)" << std::endl;
        }

        std::cout << "  Private Key Encrypted: ";
        if (user.privateKey.empty()) {
            std::cout << "Empty" << std::endl;
        } else {
            std::cout << "Present (" << user.privateKey.size() << " bytes)" << std::endl;
        }

        std::cout << "  IV: ";
        if (user.iv.empty()) {
            std::cout << "Empty" << std::endl;
        } else {
            for (auto b : user.iv) {
                printf("%02x", b);
            }
            std::cout << std::endl;
        }        
        std::cout << "--------------------------------" << std::endl;
    }
    std::cout << "=== DATABASE END ===" << std::endl;
}

bool UserDatabase::userExists(const std::string& username) const {
    return users.find(username) != users.end();
}

const User& UserDatabase::getUser(const std::string& username) const {
    auto it = users.find(username);
    if (it == users.end()) {
        throw std::runtime_error("User not found");
    }
    return it->second;
}

bool UserDatabase::getUserPublicKey(const std::string& username, byte_vec& public_key, byte_vec& msg){
    // Verify if username exists
    if(!userExists(username)){
        printf("Username %s does not exist\n", username.c_str()); // Usa c_str()
        const std::string error_msg = "Username does not exist";
        msg.assign(error_msg.begin(), error_msg.end());
        return false;
    }
    const User& user = getUser(username);
    if(user.publicKey.empty()){
        printf("This username does not have a public key\n");
        const std::string error_msg = "This username does not have a public key";
        msg.assign(error_msg.begin(), error_msg.end());
        return false;
    }
    public_key = user.publicKey;
    return true;
}

bool UserDatabase::authoriseUser(const std::string& username, const std::string& password) {
    //Verify if user exist
    if (!userExists(username)) {
        printf("AUTH: User %s not found\n", username.c_str());
        return false;
    }

    //get user
    const User& user = getUser(username);

    //Compute hash password from salt of user
    byte_vec input_hash = hashPassword(password, user.salt);

    //Compare hash
    if (input_hash != user.saltAndHashedPassword) {
        printf("AUTH: Invalid password for user %s\n", username.c_str());
        return false;
    }
    printf("AUTH: Correct hashed password\n");

    return true;
}

bool UserDatabase::addUser(const std::string& username, const std::string& password) {
    //verify user
    if (userExists(username)) {
        std::cerr << "ERROR: User " << username << " already exists\n";
        return false;
    }

    //Create new user
    User newUser;
    
    //Generate casua salt 
    newUser.salt.resize(SALT_SIZE);
    if (RAND_bytes(newUser.salt.data(), newUser.salt.size()) != 1) {
        std::cerr << "ERROR: Failed to generate salt for user " << username << "\n";
        return false;
    }
    //Generate casua IV per next encrpytion
    newUser.iv.resize(IV_SIZE);
    if (RAND_bytes(newUser.iv.data(), newUser.iv.size()) != 1) {
        std::cerr << "ERROR: Failed to generate IV for user " << username << "\n";
        return false;
    }

    //password hash with salt
    newUser.saltAndHashedPassword = hashPassword(password, newUser.salt);
    
    //flags
    newUser.isFirstLogin = true;
    newUser.keysDeleted = false;
    
    //Initialize keys empty
    newUser.publicKey.clear();
    newUser.privateKey.clear();
    
    // Add user to database
    users[username] = newUser;
    
    //Save in databse
    if (!saveToFile()) {
        std::cerr << "ERROR: Failed to save database after adding user " << username << "\n";
        users.erase(username); // Rollback
        return false;
    }
    
    std::cout << "INFO: User " << username << " added successfully\n";
    return true;
}


bool UserDatabase::changePassword(const std::string& username, const std::string& old_password, const std::string& new_password) {
    try {
        //veirfy if user exist
        if (!userExists(username)) {
            printf("ERROR: User %s not found\n", username.c_str());
            return false;
        }

        //get user
        User& user = users[username];

        //Verify correctness of old password
        byte_vec old_hash = hashPassword(old_password, user.salt);
        if (old_hash != user.saltAndHashedPassword) {
            printf("ERROR: Old password is incorrect for user %s\n", username.c_str());
            return false;
        }

        //Generate new salt for the new password
        user.salt.resize(SALT_SIZE);
        if (RAND_bytes(user.salt.data(), user.salt.size()) != 1) {
             printf("ERROR: Failed to generate new salt for user %s\n", username.c_str());
             return false;
        }

        //generate new hash with new salt
        user.saltAndHashedPassword = hashPassword(new_password, user.salt);

        //reset flag
        user.isFirstLogin = false;

        //save database
        if (!saveToFile()) {
            printf("ERROR: Failed to save database after password change for user %s\n", username.c_str());
            //(rollback) of old password
            user.saltAndHashedPassword = old_hash;
            return false;
        }

        printf("INFO: Password changed successfully for user %s\n", username.c_str());
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: changePassword failed for user %s: %s\n", username.c_str(), e.what());
        return false;
    }
}

/* debug to print publick key
void printPemPublicKey(const byte_vec& der_key) {
    BIO *bio = BIO_new_mem_buf(der_key.data(), der_key.size());
    EVP_PKEY *pkey = d2i_PUBKEY_bio(bio, nullptr);
    BIO_free(bio);
    
    if(pkey) {
        BIO *pem_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        PEM_write_bio_PUBKEY(pem_bio, pkey);
        BIO_free(pem_bio);
        EVP_PKEY_free(pkey);
    } else {
        printf("Failed to parse DER key\n");
        ERR_print_errors_fp(stderr);
    }
}*/

bool UserDatabase::createKeys(const std::string& username, const std::string& password) {
    try {
        
        if (!userExists(username)) {
            printf("ERROR: User %s not found\n", username.c_str());
            return false;
        }
        User& user = users[username];

        //verify if keys are empty
        if (!user.publicKey.empty() || !user.privateKey.empty()) {
            printf("ERROR: User %s already has keys\n", username.c_str());
            return false;
        }

        //Check if keys were previously deleted
        if (user.keysDeleted) {
            printf("ERROR: Keys for user %s were deleted and cannot be recreated\n", username.c_str());
            return false;
        }

        //Generate new keys
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
            printf("ERROR: Failed to initialize key generation\n");
            if (ctx) EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            printf("ERROR: Failed to set key length\n");
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            printf("ERROR: Key generation failed\n");
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        EVP_PKEY_CTX_free(ctx);

        //serialize public key (in chiaro)
        unsigned char* pubkey_der = nullptr;
        int pubkey_len = i2d_PUBKEY(pkey, &pubkey_der);
        if (pubkey_len <= 0) {
            printf("ERROR: Failed to serialize public key\n");
            EVP_PKEY_free(pkey);
            return false;
        }
        user.publicKey.assign(pubkey_der, pubkey_der + pubkey_len);
        
        /* DEBUG
        printf("Public key of %s (%zu bytes):\n", username.c_str(), user.publicKey.size());
        for(size_t i = 0; i < user.publicKey.size(); ++i) {
            printf("%02X ", static_cast<unsigned char>(user.publicKey[i]));
            if((i+1) % 16 == 0) printf("\n");  // Newline ogni 16 bytes
        }
        printf("\n");

        printPemPublicKey(user.publicKey);
*/
        OPENSSL_free(pubkey_der);

        //serialize private key (to encrpyt)
        unsigned char* privkey_der = nullptr;
        int privkey_len = i2d_PrivateKey(pkey, &privkey_der);
        if (privkey_len <= 0) {
            printf("ERROR: Failed to serialize private key\n");
            EVP_PKEY_free(pkey);
            return false;
        }
        byte_vec privkey_serialized(privkey_der, privkey_der + privkey_len);
        OPENSSL_free(privkey_der);
        EVP_PKEY_free(pkey);

        //use hash password
        byte_vec password_hash = hashPassword(password, user.salt);
        
        //Derive a key di cifratura più robusta usando PBKDF2
        byte_vec encryption_key(SESSION_KEY_SIZE);
        if (PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(password_hash.data()), password_hash.size(), // Use l'hash as input
            user.salt.data(), user.salt.size(), // Use same salt
            100000,  
            EVP_sha256(),
            SESSION_KEY_SIZE,
            encryption_key.data()) != 1) {
            printf("ERROR: Failed to derive encryption key\n");
            return false;
        }

        //encrypt key using AES-CBC with user iv
        byte_vec encrypted_privkey;
        if (!cbcEncrypt(encryption_key, user.iv, privkey_serialized, encrypted_privkey)) {
            printf("ERROR: Failed to encrypt private key\n");
            return false;
        }

        //mem key
        user.privateKey = encrypted_privkey;

        //secure clean of sensible data
        OPENSSL_cleanse(encryption_key.data(), encryption_key.size());
        OPENSSL_cleanse(privkey_serialized.data(), privkey_serialized.size());
        OPENSSL_cleanse(password_hash.data(), password_hash.size());

        //Save to databse
        if (!saveToFile()) {
            printf("ERROR: Failed to save database after key creation\n");
            // Rollback
            user.publicKey.clear();
            user.privateKey.clear();
            return false;
        }

        printf("INFO: Successfully created keys for user %s\n", username.c_str());
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: createKeys failed: %s\n", e.what());
        return false;
    }
}

bool UserDatabase::deleteKeys(const std::string& username, const std::string& password) {
    try {
        
        if (!userExists(username)) {
            printf("ERROR: User %s not found\n", username.c_str());
            return false;
        }

        User& user = users[username];

        //Verify password
        /*
        byte_vec input_hash = hashPassword(password, user.salt);
        if (input_hash != user.saltAndHashedPassword) {
            printf("ERROR: Invalid password for user %s\n", username.c_str());
            return false;
        }*/

        //Check if keys already exist
        if (user.publicKey.empty() && user.privateKey.empty()) {
            printf("ERROR: User %s has no keys to delete\n", username.c_str());
            return false;
        }

        //Securely wipe key data
        user.publicKey.clear();
        user.privateKey.clear();
        
        //Set deletion flag to prevent recreation
        user.keysDeleted = true;

        //Generate new IV (security best practice)
        user.iv.resize(IV_SIZE);
        if (RAND_bytes(user.iv.data(), user.iv.size()) != 1) {
            printf("WARNING: Failed to generate new IV for user %s\n", username.c_str());
            // Continue anyway since this isn't critical
        }

        //Save changes
        if (!saveToFile()) {
            printf("ERROR: Failed to save database after key deletion\n");
            // Rollback changes
            user.keysDeleted = false;
            return false;
        }

        printf("INFO: Successfully deleted keys for user %s\n", username.c_str());
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: deleteKeys failed: %s\n", e.what());
        return false;
    }
}

bool UserDatabase::decryptPrivateKey(const std::string &username, byte_vec& file_content, const std::string& password, byte_vec& error_msg, EVP_PKEY** priv_key){
    
        if (!userExists(username)) {
            printf("ERROR: User %s not found\n", username.c_str());
            return false;
        }

        User& user = users[username];
        
        if(user.privateKey.empty() || user.publicKey.empty()) {
            printf("ERROR: User %s has no keys\n", username.c_str());
            string err_msg = "User has no keys";
            error_msg.assign(err_msg.begin(), err_msg.end());
        }
        
        // decrypt private key
        byte_vec password_hash = hashPassword(password, user.salt);
        byte_vec encryption_key(SESSION_KEY_SIZE);
        
        if (PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(password_hash.data()), password_hash.size(),
            user.salt.data(), user.salt.size(),
            100000,
            EVP_sha256(),
            SESSION_KEY_SIZE,
            encryption_key.data()) != 1) {
            printf("ERROR: Failed to derive decryption key\n");
            return false;
        }
        
        byte_vec decrypted_privkey;
        if (!cbcDecrypt(encryption_key, user.iv, user.privateKey, decrypted_privkey)) {
            printf("ERROR: Failed to decrypt private key\n");
            string err_msg = "Failed to decrypt private key";
            error_msg.assign(err_msg.begin(), err_msg.end());
        }
        
        //store priv_key to send
        const unsigned char* p = decrypted_privkey.data();
        *priv_key = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, decrypted_privkey.size());
        if (!*priv_key) {
            printf("ERROR: Failed to load private key\n");
            string err_msg = "Failed to load private key";
            error_msg.assign(err_msg.begin(), err_msg.end());
            return false;
        }
        return true;
        
}

bool UserDatabase::saveToFile() {
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        printf("ERROR: Failed to open file %s for writing\n", filename.c_str());
        return false;
    }

    // write number of users
    size_t num_users = users.size();
    out.write(reinterpret_cast<const char*>(&num_users), sizeof(num_users));

    // write each user
    for (const auto& [username, user] : users) {
        // len usarname + usernmae
        size_t username_len = username.size();
        out.write(reinterpret_cast<const char*>(&username_len), sizeof(username_len));
        out.write(username.data(), username_len);

        // user data
        out.write(reinterpret_cast<const char*>(user.salt.data()), user.salt.size());
        out.write(reinterpret_cast<const char*>(user.saltAndHashedPassword.data()), user.saltAndHashedPassword.size());
        out.write(reinterpret_cast<const char*>(&user.isFirstLogin), sizeof(user.isFirstLogin));
        out.write(reinterpret_cast<const char*>(&user.keysDeleted), sizeof(user.keysDeleted));

        // pubkey if present
        size_t pubkey_len = user.publicKey.size();
        out.write(reinterpret_cast<const char*>(&pubkey_len), sizeof(pubkey_len));
        if (pubkey_len > 0) {
            out.write(reinterpret_cast<const char*>(user.publicKey.data()), pubkey_len);
        }

        // priv key if present
        size_t privkey_len = user.privateKey.size();
        out.write(reinterpret_cast<const char*>(&privkey_len), sizeof(privkey_len));
        if (privkey_len > 0) {
            out.write(reinterpret_cast<const char*>(user.privateKey.data()), privkey_len);
        }

        // iv
        size_t iv_len = user.iv.size();
        out.write(reinterpret_cast<const char*>(&iv_len), sizeof(iv_len));
        if (iv_len > 0) {
            out.write(reinterpret_cast<const char*>(user.iv.data()), iv_len);
        }
    }

    out.close();
    return true;
}

bool UserDatabase::loadFromFile() {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        printf("ERROR: Failed to open file %s for reading\n", filename.c_str());
        return false;
    }
    
    users.clear();
    
    size_t num_users;
    in.read(reinterpret_cast<char*>(&num_users), sizeof(num_users));
    if (!in) {
        printf("ERROR: Failed to read user count from file\n");
        return false;
    }
    
    for (size_t i = 0; i < num_users; ++i) {
        User user;
        
        // Read username
        size_t username_len;
        in.read(reinterpret_cast<char*>(&username_len), sizeof(username_len));
        if (!in || username_len > 1000) { // Sanity check
            printf("ERROR: Invalid username length in file\n");
            return false;
        }
        
        std::string username(username_len, '\0');
        in.read(&username[0], username_len);
        if (!in) {
            printf("ERROR: Failed to read username from file\n");
            return false;
        }

        // Read salt (must be present)
        user.salt.resize(SALT_SIZE);
        in.read(reinterpret_cast<char*>(user.salt.data()), user.salt.size());
        if (!in) {
            printf("ERROR: Failed to read salt for user %s\n", username.c_str());
            return false;
        }

        // Read password hash
        user.saltAndHashedPassword.resize(HASH_SIZE);
        in.read(reinterpret_cast<char*>(user.saltAndHashedPassword.data()), user.saltAndHashedPassword.size());
        if (!in) {
            printf("ERROR: Failed to read password hash for user %s\n", username.c_str());
            return false;
        }

        // Read isFirstLogin flag
        in.read(reinterpret_cast<char*>(&user.isFirstLogin), sizeof(user.isFirstLogin));
        if (!in) {
            printf("ERROR: Failed to read isFirstLogin flag for user %s\n", username.c_str());
            return false;
        }

        // read KeysDeleted
        in.read(reinterpret_cast<char*>(&user.keysDeleted), sizeof(user.keysDeleted));
        if (!in) {
            printf("ERROR: Failed to read keysDeleted flag for user %s\n", username.c_str());
            return false;
        }

        // Read public key 
        size_t pubkey_len;
        in.read(reinterpret_cast<char*>(&pubkey_len), sizeof(pubkey_len));
        if (!in) {
            printf("ERROR: Failed to read public key length for user %s\n", username.c_str());
            return false;
        }
        
        if (pubkey_len > 0) {
            user.publicKey.resize(pubkey_len);
            in.read(reinterpret_cast<char*>(user.publicKey.data()), pubkey_len);
            if (!in) {
                printf("ERROR: Failed to read public key for user %s\n", username.c_str());
                return false;
            }
        }

        // Read private key 
        size_t privkey_len;
        in.read(reinterpret_cast<char*>(&privkey_len), sizeof(privkey_len));
        if (!in) {
            printf("ERROR: Failed to read private key length for user %s\n", username.c_str());
            return false;
        }
        
        if (privkey_len > 0) {
            user.privateKey.resize(privkey_len);
            in.read(reinterpret_cast<char*>(user.privateKey.data()), privkey_len);
            if (!in) {
                printf("ERROR: Failed to read private key for user %s\n", username.c_str());
                return false;
            }
        }

        // Read IV 
        size_t iv_len;
        in.read(reinterpret_cast<char*>(&iv_len), sizeof(iv_len));
        if (!in) {
            printf("ERROR: Failed to read IV length for user %s\n", username.c_str());
            return false;
        }
        
        if (iv_len > 0) {
            user.iv.resize(iv_len);
            in.read(reinterpret_cast<char*>(user.iv.data()), iv_len);
            if (!in) {
                printf("ERROR: Failed to read IV for user %s\n", username.c_str());
                return false;
            }
        }

        users[username] = user;
    }
    
    return true;
}

void UserDatabase::initializeDefaultUsers() {
    addUser("alice", "alice");
    addUser("bob", "bob");
    addUser("carl", "carl");
    
    //control
    if (!saveToFile()) {
        std::cerr << "ERROR: Failed to save database to file after initialization\n";
    } else {
        std::cout << "INFO: Database successfully saved to " << filename << "\n";
    }
}