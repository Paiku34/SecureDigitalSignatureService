#include <cstring>

#include <arpa/inet.h>

#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "utility.h"
#include <iostream>
#include "types.h"

static bool readFull(int sock, void* buffer, ssize_t length){
    char* ptr = static_cast<char*>(buffer);
    while(length > 0){
        ssize_t received = recv(sock, ptr, length, 0);
        if(received <= 0) return false;
        ptr += received;
        length -= received;
    }
    return true;
}


bool read_msg(int sock, byte_vec& out){
    // Riceive the lenght msg
    uint32_t net_len;
    if (!readFull(sock, &net_len, sizeof(net_len))) return false;

    //converts
    uint32_t len = ntohl(net_len);
    if(len <= 0) return false;

    out.resize(len);  

    // Riceive the message
    return readFull(sock, out.data(), len);
}

static bool writeFull(int sock, const void* buffer, ssize_t length){
    const char* ptr = static_cast<const char*>(buffer);
    while (length > 0) {
        ssize_t sent = send(sock, ptr, length, 0);
        if (sent <= 0) return false;
        ptr += sent;
        length -= sent;
    }
    return true;
}

bool write_msg(int sock,const byte_vec& data){
    //converts
    uint32_t len_net = htonl(data.size());
    //send msg length
    if (!writeFull(sock, &len_net, sizeof(len_net))) return false;

    //send msg
    return writeFull(sock, data.data(), data.size());
}

bool sendSecure(int sock, byte_vec& c_nonce, byte_vec& s_nonce, const byte_vec& key, const byte_vec& mac, byte_vec& cmd, byte_vec& data){
    try {
        //printf("INFO: sendSecure: started\n");
        byte_vec msg;
        // generate nonce compilation flag(client or server) and add it
        #ifdef CLIENT
        ERR_CHECK(RAND_bytes(c_nonce.data(), c_nonce.size()) <= 0); 
        #endif
        #ifdef SERVER
        ERR_CHECK(RAND_bytes(s_nonce.data(), s_nonce.size()) <= 0);
        #endif
        
        // insert all information
        uint32_t len = data.size(); 
        len = htonl(len);  
        msg.insert(msg.end(), c_nonce.begin(), c_nonce.end());
        msg.insert(msg.end(), s_nonce.begin(), s_nonce.end()); 
        msg.insert(msg.end(), cmd.begin(), cmd.end());  
        msg.insert(msg.end(), (unsigned char*)&len, (unsigned char*)&len + U32_SIZE);  
        msg.insert(msg.end(), data.begin(), data.end());

        // generate iv and encrypt the message
        byte_vec encrypted_data;
        byte_vec iv(IV_SIZE);
        ERR_CHECK(RAND_bytes(iv.data(), iv.size()) <= 0);  
        if(!cbcEncrypt(key, iv, msg, encrypted_data)){
            printf("Error in cbcEncrypt");
            return false;
        }
        msg.clear();

        // add iv and encrypted_data
        msg.insert(msg.end(), iv.begin(), iv.end());
        msg.insert(msg.end(), encrypted_data.begin(), encrypted_data.end());
        
        // comput the hmac
        byte_vec hmac;
        if(!hmacCompute(mac, msg, hmac)){
            printf("Error in hmac\n");
            return false;
        }

        // add the hmac
        msg.insert(msg.end(), hmac.begin(), hmac.end());
        if(!write_msg(sock, msg)) return false;

        //printf("INFO: sendSecure: finished\n");
        return true;
    } catch(const std::exception& e) {
        printf("ERROR: sendSecure: %s\n", e.what());
        return false;
    }
}

bool recvSecure(int sock, byte_vec& c_nonce, byte_vec& s_nonce, const byte_vec& key, const byte_vec& mac, byte_vec& cmd, byte_vec& data){
    try {
        //printf("INFO: recvSecure: started\n");
        byte_vec msg;
        ERR_CHECK(!read_msg(sock, msg));
        if(msg.size() <= IV_SIZE + NONCE_SIZE*2 + U32_SIZE + HMAC_SIZE + CMD_SIZE) {
            printf("ERROR: recvSecure: message too short\n");
            return false;
        }
        // read iv
        byte_vec iv(msg.begin(), msg.begin() + IV_SIZE); 

        // read encrypted msg
        byte_vec encrypted_msg(msg.begin() + IV_SIZE, msg.end() - HMAC_SIZE);

        // read the hmac
        byte_vec hmac(msg.end() - HMAC_SIZE, msg.end());
        byte_vec computed_hmac;
        
        // concatenate iv and encrypted msg
        byte_vec iv_msg(msg.begin(), msg.end() - HMAC_SIZE); 
        
        // check the hmac
        ERR_CHECK(!hmacCompute(mac, iv_msg, computed_hmac));
        if(CRYPTO_memcmp(hmac.data(), computed_hmac.data(), hmac.size()) != 0) {
            printf("ERROR: recvSecure: HMAC verification failed\n");
            return false;
        } else {
            //printf("INFO: recvSecure: HMAC verification finished\n");
        }
        
        // decrypt the msg
        byte_vec decrypted_msg;
        ERR_CHECK(!cbcDecrypt(key, iv, encrypted_msg, decrypted_msg));
        // check the compilation flag(client or server) nonce and store the other 
        #ifdef CLIENT
        if(CRYPTO_memcmp(c_nonce.data(), decrypted_msg.data(), NONCE_SIZE) != 0) {
            printf("ERROR: recvSecure: nonce mismatch\n");
            return false;
        } else {
            //printf("INFO: recvSecure: nonce verification finished\n");
        }
        s_nonce.clear();
        s_nonce.insert(s_nonce.end(), decrypted_msg.begin() + NONCE_SIZE, decrypted_msg.begin() + NONCE_SIZE*2);
        #endif
        #ifdef SERVER
        if(CRYPTO_memcmp(s_nonce.data(), decrypted_msg.data() + NONCE_SIZE, NONCE_SIZE) != 0) {
            printf("ERROR: recvSecure: nonce mismatch\n");
            return false;
        } else {
            //printf("INFO: recvSecure: nonce verification finished\n");
        }
        c_nonce.clear();
        c_nonce.insert(c_nonce.end(), decrypted_msg.begin(), decrypted_msg.begin() + NONCE_SIZE);
        #endif

        // read the command
        cmd.clear();
        cmd.insert(cmd.end(), decrypted_msg.begin() + NONCE_SIZE*2, decrypted_msg.begin() + NONCE_SIZE*2 + CMD_SIZE);
        
        // read the data len
        uint32_t len;
        std::memcpy(&len, decrypted_msg.data() + NONCE_SIZE*2 + CMD_SIZE, sizeof(len));
        len = ntohl(len);
        
        // read the data
        data.clear();
        data.insert(data.end(), decrypted_msg.begin() + NONCE_SIZE*2 + CMD_SIZE + U32_SIZE, decrypted_msg.begin() + NONCE_SIZE*2 + CMD_SIZE + U32_SIZE + len);
    } catch(const std::exception& e) {
        printf("ERROR: recvSecure: %s\n", e.what());
        return false;
    }

    return true;
}

bool generateDhPair(EVP_PKEY** dh_key) {
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY_CTX *kctx = nullptr;
    EVP_PKEY *dh_params = nullptr;
    OSSL_PARAM_BLD *param_bld = nullptr;
    OSSL_PARAM *params_array = nullptr;
    *dh_key = nullptr;

    //Build DH parameters using OSSL_PARAM_BLD
    param_bld = OSSL_PARAM_BLD_new();
    ERR_CHECK_MSG(!param_bld, "Failed to create OSSL_PARAM_BLD");
    ERR_CHECK_MSG(!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0), "Failed to set DH group");
    params_array = OSSL_PARAM_BLD_to_param(param_bld);
    ERR_CHECK_MSG(!params_array, "Failed to build OSSL_PARAM array");

    //Generate DH key pair
    pctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    ERR_CHECK_MSG(!pctx, "Failed to create DH context");
    ERR_CHECK_MSG(EVP_PKEY_fromdata_init(pctx) <= 0, "EVP_PKEY_fromdata_init failed");
    ERR_CHECK_MSG(EVP_PKEY_fromdata(pctx, &dh_params, EVP_PKEY_KEY_PARAMETERS, params_array) <= 0, "Failed to create DH parameters");
    kctx = EVP_PKEY_CTX_new_from_pkey(nullptr, dh_params, nullptr);
    ERR_CHECK_MSG(!kctx, "Failed to create keygen context");
    ERR_CHECK_MSG(EVP_PKEY_keygen_init(kctx) <= 0, "DH keygen initialization failed");
    ERR_CHECK_MSG(EVP_PKEY_generate(kctx, dh_key) <= 0, "DH keypair generation failed");

    //Cleanup and return
    OSSL_PARAM_free(params_array);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(dh_params);
    return true;

error:
    if (params_array) OSSL_PARAM_free(params_array);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (dh_params) EVP_PKEY_free(dh_params);
    if (*dh_key) EVP_PKEY_free(*dh_key);
    return false;
}

bool extractDhPubKeyDer(EVP_PKEY* dh_keypair, byte_vec& pubkey_der) {
    OSSL_ENCODER_CTX* ctx = nullptr;
    unsigned char* der = nullptr;
    size_t der_len = 0;
    
    ctx = OSSL_ENCODER_CTX_new_for_pkey(dh_keypair, EVP_PKEY_PUBLIC_KEY, "DER", nullptr, nullptr);
    ERR_CHECK_MSG(!ctx, "Failed to create encoder context");

    ERR_CHECK_MSG(!OSSL_ENCODER_to_data(ctx, &der, &der_len), "Failed to encode public key");

    //printf("DEBUG: Extracted DH public key length: %zu bytes\n", der_len); // Debug aggiuntivo
    
    pubkey_der.assign(der, der + der_len);
    OPENSSL_free(der);
    OSSL_ENCODER_CTX_free(ctx);
    return true;

error:
    if (der) OPENSSL_free(der);
    if (ctx) OSSL_ENCODER_CTX_free(ctx);
    return false;
}

bool getDhSharedKey(EVP_PKEY* our_keypair, const byte_vec& peer_pubkey_der, byte_vec& shared_key) {
    EVP_PKEY* peer_pubkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    size_t secret_len = 0;

    //Convert peer public key from DER to EVP_PKEY
    const unsigned char* p = peer_pubkey_der.data();
    peer_pubkey = d2i_PUBKEY(nullptr, &p, peer_pubkey_der.size());
    ERR_CHECK_MSG(!peer_pubkey, "Failed to decode peer public key");

    //derive
    ctx = EVP_PKEY_CTX_new(our_keypair, nullptr);
    ERR_CHECK_MSG(!ctx, "Failed to create EVP_PKEY_CTX");

    ERR_CHECK_MSG(EVP_PKEY_derive_init(ctx) <= 0, "EVP_PKEY_derive_init failed");
    ERR_CHECK_MSG(EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0, "EVP_PKEY_derive_set_peer failed");

    //determine length
    ERR_CHECK_MSG(EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0, "Failed to get shared key length");
    shared_key.resize(secret_len);

    //derive shared key
    ERR_CHECK_MSG(EVP_PKEY_derive(ctx, shared_key.data(), &secret_len) <= 0, "Failed to derive shared key");

    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_CTX_free(ctx);
    return true;

error:
    if (peer_pubkey) EVP_PKEY_free(peer_pubkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return false;
}

bool deriveKeys(const byte_vec& shared_key, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, const byte_vec& salt) {
    c_key.resize(SESSION_KEY_SIZE);
    s_key.resize(SESSION_KEY_SIZE);
    c_mac.resize(HMAC_SIZE);  // 32 bytes for SHA-256
    s_mac.resize(HMAC_SIZE);

    
    size_t key_len = SESSION_KEY_SIZE; // AES-256
    size_t mac_len = SESSION_KEY_SIZE; // SHA256
    size_t shared_key_len = shared_key.size();
    size_t derived_key_len = 2*key_len + 2*mac_len;
    byte_vec derived_key(derived_key_len);
    
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return false;

    if (1 != EVP_PKEY_derive_init(pctx)) return false;
    if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) return false;
    if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), SALT_SIZE)) return false;
    if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_key.data(), shared_key_len)) return false;
    if (1 != EVP_PKEY_derive(pctx, derived_key.data(), &derived_key_len)) return false;

    EVP_PKEY_CTX_free(pctx);

    // Split derived key
    try{
        c_key.assign(derived_key.data(), derived_key.data() + key_len);
        s_key.assign(derived_key.data() + key_len, derived_key.data() + 2 * key_len);
        c_mac.assign(derived_key.data() + 2 * key_len, derived_key.data() + 2 * key_len + mac_len);
        s_mac.assign(derived_key.data() + 2 * key_len + mac_len, derived_key.data() + 2 * key_len + 2 * mac_len);
    } catch(const std::exception& e) {
        ("ERROR: derive_keys failed: %s\n", e.what());
        return false;
    }

    return true;
}

bool serverSignature(EVP_PKEY* priv_key, const byte_vec& data, byte_vec& signature) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("Failed to create EVP_MD_CTX\n");
        return false;
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, priv_key) <= 0) {
        printf("EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    size_t sig_len;
    if (EVP_DigestSign(md_ctx, nullptr, &sig_len, data.data(), data.size()) <= 0) {
        printf("Failed to get signature length\n");
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    signature.resize(sig_len);
    if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0) {
        printf("EVP_DigestSign failed\n");
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    EVP_MD_CTX_free(md_ctx);
    return true;
}

bool cbcEncrypt(const byte_vec& key, const byte_vec& iv, const byte_vec& plaintext, byte_vec& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create cipher context\n");
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) <= 0) {
        printf("Encrypt init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size()) <= 0) {
        printf("Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) <= 0) {
        printf("Encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(out_len + final_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool hmacCompute(const byte_vec& key, const byte_vec& data, byte_vec& hmac) {
    EVP_MAC* mac = nullptr;
    EVP_MAC_CTX* ctx = nullptr;
    OSSL_PARAM params[2];
    size_t out_len = 0;

    mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        printf("ERROR: EVP_MAC_fetch failed\n");
        return false;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        printf("ERROR: EVP_MAC_CTX_new failed\n");
        EVP_MAC_free(mac);
        return false;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1) {
        printf("ERROR: EVP_MAC_init failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    if (EVP_MAC_update(ctx, data.data(), data.size()) != 1) {
        printf("ERROR: EVP_MAC_update failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    size_t mac_len = 0;
    if (EVP_MAC_final(ctx, nullptr, &mac_len, 0) != 1) {
        printf("ERROR: EVP_MAC_final (size query) failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    hmac.resize(mac_len);
    if (EVP_MAC_final(ctx, hmac.data(), &out_len, mac_len) != 1) {
        printf("ERROR: EVP_MAC_final failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    hmac.resize(out_len);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return true;
}

// Helper function for constant-time comparison
static int crypto_memcmp(const void* a, const void* b, size_t len) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    unsigned char res = 0;
    
    for (size_t i = 0; i < len; i++) {
        res |= x[i] ^ y[i];
    }
    return res;
}

bool serverVerify(const byte_vec& data, const byte_vec& signature, EVP_PKEY* s_pub_key) {
    if (!s_pub_key || data.empty() || signature.empty()) {
        printf("Invalid parameters for signature verification\n");
        return false;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("Failed to create EVP_MD_CTX\n");
        return false;
    }

    bool result = false;
    do {
        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, s_pub_key) <= 0) {
            printf("EVP_DigestVerifyInit failed\n");
            break;
        }

        if (EVP_DigestVerify(md_ctx, signature.data(), signature.size(), data.data(), data.size()) <= 0) {
            printf("Signature verification failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        result = true;
    } while (0);

    EVP_MD_CTX_free(md_ctx);
    return result;
}

bool cbcDecrypt(const byte_vec& key, const byte_vec& iv, const byte_vec& ciphertext, byte_vec& plaintext) {
    if (key.size() != SESSION_KEY_SIZE || iv.size() != IV_SIZE || ciphertext.empty()) {
        printf("Invalid parameters for decryption\n");
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create cipher context\n");
        return false;
    }

    bool result = false;
    plaintext.clear();

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) <= 0) {
            printf("Decrypt init failed\n");
            break;
        }

        plaintext.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), ciphertext.size()) <= 0) {
            printf("Decryption failed\n");
            break;
        }

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) <= 0) {
            printf("Decryption final failed (padding or corruption)\n");
            break;
        }

        plaintext.resize(out_len + final_len);
        result = true;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return result;
}
