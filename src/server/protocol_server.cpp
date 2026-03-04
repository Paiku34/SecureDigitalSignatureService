#include <csignal>
#include <cstring>
#include <thread>

#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/rand.h>


#include "types.h"
#include "utility.h"
#include "protocol_server.h"
#include <iostream>
#include "userdb.h"

extern UserDatabase db;
bool recvDhPublickey(int client_fd, byte_vec& pubkey_bin) {
    try{
        printf("\nINFO: recvDhPublickey: started\n");
        byte_vec msg;
        ERR_CHECK(!read_msg(client_fd, msg));

        uint32_t key_len;
        // read key len
        std::memcpy(&key_len, msg.data(), U32_SIZE);
        key_len = ntohl(key_len);
        // read client public dh key
        pubkey_bin.insert(pubkey_bin.end(), msg.begin() + U32_SIZE, msg.begin() + U32_SIZE + key_len);
        printf("INFO: recvDhPublickey: finished\n");
    } catch (std::exception& e) {
        printf("ERROR: recvDhPublickey: %s\n", e.what());
        return false;
    }
    return true;
}

bool sendServerKey(int sock, EVP_PKEY* s_sign_key, const byte_vec& s_nonce,
                  const byte_vec& c_pubkey_bin, const byte_vec& s_pubkey_bin,
                  const byte_vec& s_key, const byte_vec& s_mac) {
    try {
        printf("\nINFO: sendServerKey: started\n");
        byte_vec msg;
        
        //Generate server IV
        byte_vec s_iv(IV_SIZE);
        ERR_CHECK(RAND_bytes(s_iv.data(), s_iv.size()) != 1);
        msg.insert(msg.end(), s_iv.begin(), s_iv.end());
        
        //Add nonce
        msg.insert(msg.end(), s_nonce.begin(), s_nonce.end());
        
        //Add DH public key length and key
        uint32_t s_pubkey_len = htonl(static_cast<uint32_t>(s_pubkey_bin.size()));
        msg.insert(msg.end(), reinterpret_cast<unsigned char*>(&s_pubkey_len), 
              reinterpret_cast<unsigned char*>(&s_pubkey_len) + U32_SIZE);
        msg.insert(msg.end(), s_pubkey_bin.begin(), s_pubkey_bin.end());
        
        //Prepare data for signing (IV + nonce + key length + key)
        byte_vec data_to_sign = msg;
        printf("INFO: sendServerKey: preparing (IV + nonce + key length + key)\n");
        
        //Generate signature
        byte_vec signature;
        byte_vec keys_to_sign;
        keys_to_sign.insert(keys_to_sign.end(), c_pubkey_bin.begin(), c_pubkey_bin.end());
        keys_to_sign.insert(keys_to_sign.end(), s_pubkey_bin.begin(), s_pubkey_bin.end());
        //printf("INFO: sendServerKey: signing keys\n");
        ERR_CHECK(!serverSignature(s_sign_key, keys_to_sign, signature));
        printf("INFO: sendServerKey: keys signed\n");

        //Encrypt signature
        byte_vec encrypted_sig;
        ERR_CHECK(!cbcEncrypt(s_key, s_iv, signature, encrypted_sig));
        
        //Add encrypted signature length and data
        uint32_t enc_sig_len = htonl(static_cast<uint32_t>(encrypted_sig.size()));
        msg.insert(msg.end(), reinterpret_cast<unsigned char*>(&enc_sig_len), 
              reinterpret_cast<unsigned char*>(&enc_sig_len) + U32_SIZE);
        msg.insert(msg.end(), encrypted_sig.begin(), encrypted_sig.end());
        
        //Calculate HMAC on all data so far
        byte_vec hmac;
        ERR_CHECK(!hmacCompute(s_mac, msg, hmac));
        
        //Add HMAC to message
        msg.insert(msg.end(), hmac.begin(), hmac.end());
        printf("INFO: sendServerKey: adding (encrypted signature + HMAC)\n");
        
        //printf("DEBUG: Final message size: %zu bytes\n", msg.size());
        //printf("DEBUG: Encrypted signature size: %zu bytes\n", encrypted_sig.size());
        
        ERR_CHECK(!write_msg(sock, msg));
        printf("INFO: sendServerKey: successfull\n");
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: sendServerKey: %s\n", e.what());
        return false;
    }
}

bool verifyClientAuthentication(int client_fd, byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, string& username, string& password) {
    try {
        printf("\nINFO: verifyClientAuthentication: started\n");
        
        //Receive authentication message
        byte_vec cmd;
        byte_vec auth_data;
        ERR_CHECK(!recvSecure(client_fd, c_nonce, s_nonce, c_key, c_mac, cmd, auth_data));

        //Verify command is LOG
        string command(cmd.begin(), cmd.end());
        if (command != "LOG") {
            printf("ERROR: Expected LOG command, got %s\n", command.c_str());
            return false;
        }

        //Parse username:password
        string auth_str(auth_data.begin(), auth_data.end());
        size_t sep_pos = auth_str.find(':');
        if (sep_pos == string::npos) {
            printf("ERROR: Invalid authentication format\n");
            return false;
        }

        username = auth_str.substr(0, sep_pos);
        password = auth_str.substr(sep_pos + 1);

        printf("AUTH: Authentication of: %s\n", username.c_str());
        //printf("password: %s\n", password.c_str());

        //Verify credentials 
        if (!db.authoriseUser(username, password)) {
            byte_vec err_cmd(ERR, ERR + CMD_SIZE);
            byte_vec err_data;
            const char* err_msg = "Authentication failed:";
            err_data.assign(err_msg, err_msg + strlen(err_msg));
            
            if (!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, err_cmd, err_data)) {
                printf("ERROR: Failed to send error message\n");
            }
            return false;
        }

        //send ack, if is first login send change command
        const char* ack_msg;
        byte_vec ack_cmd;
        User user = db.getUser(username);
        if (user.isFirstLogin){
            printf("\nCHANGE: First Login: Sending CHG command\n");
            ack_cmd.assign(CHG, CHG + CMD_SIZE);
            ack_msg = "Change Password";
        }
        else{
            ack_cmd.assign(ACK, ACK + CMD_SIZE);
            ack_msg = "Authentication successful";
            printf("\nAUTH: Authentication successfull\n");
        }

        byte_vec ack_data;
        ack_data.assign(ack_msg, ack_msg + strlen(ack_msg));
        
        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, ack_cmd, ack_data));

        //recv new password and change it on database
        if(user.isFirstLogin){
            byte_vec change_password;
            ERR_CHECK(!recvSecure(client_fd, c_nonce, s_nonce, c_key, c_mac, cmd, change_password));
            string new_password(change_password.begin(), change_password.end());
            //printf("CHANGE: New password: %s\n", new_password.c_str());

            //modify in databse and save
            if(!db.changePassword(username, password, new_password)){
                password = new_password; //update variable 
                printf("ERROR: Change password error\n");
                return false;
            }
            printf("UPDATE DB: Updating new password successfull\n");
        }
        
        printf("\nINFO: verifyClientAuthentication: completed successfully\n");
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: verifyClientAuthentication failed: %s\n", e.what());
        return false;
    }
}

bool handshake(int client_fd, EVP_PKEY* s_priv_key, byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, string& username, string& password){
    byte_vec c_pubkey_bin;
    ERR_CHECK(!recvDhPublickey(client_fd, c_pubkey_bin));

    //Convert in EVP_PKEY
    const unsigned char* p = c_pubkey_bin.data();
    EVP_PKEY* client_pubkey = d2i_PUBKEY(nullptr, &p, c_pubkey_bin.size());
    ERR_CHECK_MSG(!client_pubkey, "Invalid DH public key format");

    byte_vec s_pubkey_bin(DH_KEY_SIZE);
    EVP_PKEY* dh_keypair;
    ERR_CHECK(!generateDhPair(&dh_keypair));
    ERR_CHECK(!extractDhPubKeyDer(dh_keypair,s_pubkey_bin));

    byte_vec shared_key;
    printf("\nINFO: generating dh sharedkey\n");
    ERR_CHECK(!getDhSharedKey(dh_keypair, c_pubkey_bin, shared_key));
    //printf("INFO: dh key sharedgenerated\n");

    ERR_CHECK(RAND_bytes(s_nonce.data(), s_nonce.size()) <= 0);
    ERR_CHECK(!deriveKeys(shared_key, c_key, s_key, c_mac, s_mac, s_nonce));
     
    printf("INFO: keys derived\n");

    ERR_CHECK(!sendServerKey(client_fd, s_priv_key, s_nonce, c_pubkey_bin, s_pubkey_bin, s_key, s_mac));
    s_pubkey_bin.clear();
    EVP_PKEY_free(dh_keypair);
    
    shared_key.clear();

    // Fase 3: Autenticazione client + isFirstLogin
    ERR_CHECK(!verifyClientAuthentication(client_fd, c_nonce, s_nonce, c_key, s_key, c_mac, s_mac, username, password));

    return true;
}