#include <csignal>
#include <cstring>
#include <thread>

#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>  
#include <iostream>

#include "types.h"
#include "utility.h"
#include "protocol_client.h"

bool sendDhPublicKey(int sock, const byte_vec& c_pubkey_dh){
    try{
        printf("INFO: sendDhPublickey: sending pub_key to server\n");
        byte_vec msg;
        uint32_t pubkey_len = htonl(c_pubkey_dh.size());
        // add pubkey size
        msg.insert(msg.end(), (unsigned char*)&pubkey_len, (unsigned char*)&pubkey_len + U32_SIZE); 
        // add pubkey data
        msg.insert(msg.end(), c_pubkey_dh.begin(), c_pubkey_dh.end());
        ERR_CHECK(!write_msg(sock, msg));
    } catch (const std::exception& e) {
        printf("ERROR: sendDhPublickey: %s\n", e.what());
        return false;
    }
    return true;
}

bool recvServerKeys(int sock, EVP_PKEY* s_pub_key, EVP_PKEY* dh_keypair,
                   const byte_vec& c_pubkey_bin, byte_vec& s_nonce,
                   byte_vec& c_key, byte_vec& s_key,
                   byte_vec& c_mac, byte_vec& s_mac) {
    try {
        
        printf("\nINFO: recvServerKeys: started\n");
        byte_vec msg;
        //Receive full message
        ERR_CHECK(!read_msg(sock, msg));

        // read iv
        byte_vec iv(msg.begin(), msg.begin() + IV_SIZE);
        s_nonce.clear();

        // read server nonce
        s_nonce.insert(s_nonce.end(), msg.begin() + IV_SIZE, msg.begin() + IV_SIZE + NONCE_SIZE);
        
        //read key length
        uint32_t key_len;
        std::memcpy(&key_len, msg.data() + 32, sizeof(key_len));
        key_len = ntohl(key_len);

        // read server public key
        byte_vec s_pubkey_dh;
        s_pubkey_dh.insert(s_pubkey_dh.end(), msg.begin() + IV_SIZE + NONCE_SIZE + U32_SIZE, msg.begin() + IV_SIZE + NONCE_SIZE + U32_SIZE + key_len);
        
        // read signature len
        uint32_t sig_len;
        std::memcpy(&sig_len, msg.data() + IV_SIZE*2 + U32_SIZE + key_len, U32_SIZE);
        sig_len = ntohl(sig_len); 
        // read ecnypted signature +hmac
        byte_vec recv_encrypted_signature(msg.begin() + IV_SIZE + NONCE_SIZE + U32_SIZE*2 + key_len, msg.begin() + IV_SIZE + NONCE_SIZE + U32_SIZE*2 + key_len + sig_len);
        byte_vec recv_hmac(msg.begin() + IV_SIZE + NONCE_SIZE + U32_SIZE*2 + key_len + sig_len, msg.end());

       
        // compose the keypair to verify signature
        byte_vec keys;
        keys.insert(keys.end(), c_pubkey_bin.begin(), c_pubkey_bin.end());
        keys.insert(keys.end(), s_pubkey_dh.begin(), s_pubkey_dh.end());
        byte_vec shared_secret;

        printf("INFO: recvServerKeys: read (iv + s_nonce + key len + s_pub_key + enc_signature + hmac)\n");

        // generate shared secret
        ERR_CHECK(!getDhSharedKey(dh_keypair, s_pubkey_dh, shared_secret));
        printf("INFO: recvServerKeys: shared key generated\n");

        // derive session keys
        ERR_CHECK(!deriveKeys(shared_secret, c_key, s_key, c_mac, s_mac, s_nonce));
        printf("INFO: recvServerKeys: keys derived\n");
        
        // check the hmac
        byte_vec computed_hmac;
        byte_vec msg_to_check(msg.begin(), msg.begin() + IV_SIZE + NONCE_SIZE + U32_SIZE*2 + key_len + sig_len);
        ERR_CHECK(!hmacCompute(s_mac, msg_to_check, computed_hmac));
        if(CRYPTO_memcmp(recv_hmac.data(), computed_hmac.data(), recv_hmac.size()) != 0) {
            printf("ERROR: recvServerKeys: HMAC verification failed\n");
            return false;
        } else {
            printf("INFO: recvServerKeys: HMAC verification successfull\n");
        }
        
        // decrypt the signature
        byte_vec decrypted_signature;
        ERR_CHECK(!cbcDecrypt(s_key, iv, recv_encrypted_signature, decrypted_signature));

        // verify the signature
        bool ok = serverVerify(keys, decrypted_signature, s_pub_key);
        if(!ok) {
            printf("ERROR: recvServerKeys: sign verification failed\n");
            return false;
        } else {
            printf("INFO: recvServerKeys: sign verification successfull\n");
        }
        
        printf("INFO: recvServerKeys completed successfully\n");
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: recvServerKeys: %s\n", e.what());
        return false;
    }
}

bool clientAuthenticate(int sock, byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, byte_vec& c_mac, byte_vec& s_key, byte_vec& s_mac, string& username, string& password) { 
    try {
        printf("\nINFO: clientAuthenticate started\n");

        printf("INFO: clientAuthenticate: Insert username: ");
        std::string temp_username;
        std::cin >> temp_username;
        
        printf("INFO: clientAuthenticate: Insert password: ");
        std::string temp_password;
        std::cin >> temp_password;

        // Convert strings to byte_vec
        byte_vec username_vec(temp_username.begin(), temp_username.end());
        byte_vec password_vec(temp_password.begin(), temp_password.end());

        // Prepare authentication data
        byte_vec cmd(LOG, LOG + CMD_SIZE);
        byte_vec auth_data;
        auth_data.insert(auth_data.end(), username_vec.begin(), username_vec.end());
        auth_data.push_back(':');
        auth_data.insert(auth_data.end(), password_vec.begin(), password_vec.end());

        // Send authentication data
        printf("INFO: clientAuthenticate: sending LOG command + username + password\n");
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, auth_data));

        // Receive ACK from server
        byte_vec ack_cmd;
        byte_vec ack_data;
        if (!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, ack_cmd, ack_data)) {
            printf("ERROR: Failed to receive ACK from server\n");
            return false;
        }

        // Verify ACK command
        string ack_command(ack_cmd.begin(), ack_cmd.end());
        if(ack_command == "ACK"){
            printf("ACK: Received authentication ack from server\n");
        }
        //change password since is first login
        else if(ack_command == "CHG"){
            // Verify ACK data (optional)
            string ack_message(ack_data.begin(), ack_data.end());
            printf("\nServer response: %s\n", ack_message.c_str());
            printf("CHANGE: You need to change password\n");
            byte_vec cmd_change(CHG, CHG + CMD_SIZE);
            byte_vec change_data;

            printf("Insert new password: ");
            std::string change_password;
            std::cin >> change_password;
            byte_vec new_password(change_password.begin(), change_password.end());
            change_data.insert(change_data.end(), new_password.begin(), new_password.end());

            // Send new_password
            ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, change_data));

        }
        else{
            printf("ERROR: Expected ACK from server, got %s\n", ack_command.c_str());
            string ack_message(ack_data.begin(), ack_data.end());
            printf("Server response: %s\n", ack_message.c_str());
            return false;
        }
        //store 
        username = temp_username;
        password = temp_password;
        
        printf("AUTH: Autentication successfull\n");
        return true;
    } catch (const std::exception& e) {
        printf("ERROR: clientAuthenticate: %s\n", e.what());
        return false;
    }
}

bool handshake(int sock, EVP_PKEY* s_pub_key, string& username, string& password,byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key,byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac){
    EVP_PKEY* dh_keypair;
    byte_vec c_pubkey_bin;
    printf("\nINFO: generating DH keypair\n");
    ERR_CHECK(!generateDhPair(&dh_keypair));

    // extract pubkey as DER
    ERR_CHECK(!extractDhPubKeyDer(dh_keypair, c_pubkey_bin));

    //send client pubkey to server
    ERR_CHECK(!sendDhPublicKey(sock, c_pubkey_bin));

    //Generate client nonce
    ERR_CHECK(RAND_bytes(c_nonce.data(), c_nonce.size()) <= 0);

    //Receive and verify server response
    byte_vec s_pubkey_bin;
    ERR_CHECK(!recvServerKeys(sock, s_pub_key, dh_keypair, c_pubkey_bin, s_nonce, c_key, s_key, c_mac, s_mac));

    EVP_PKEY_free(dh_keypair);

    //Verify client authentication
    ERR_CHECK(!clientAuthenticate(sock, c_nonce, s_nonce, c_key, c_mac, s_key, s_mac, username, password));
    
    return true;
}