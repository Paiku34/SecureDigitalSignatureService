#include <csignal>
#include <cstring>
#include <thread>

#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <iostream>
#include <openssl/pem.h>  // Per PEM_write_bio_PUBKEY
#include <openssl/err.h>  // Per ERR_print_errors_fp
#include <openssl/evp.h>  // Per EVP_PKEY
#include <vector>
#include <string>

#include "types.h"
#include "utility.h"
#include "protocol_server.h"
#include "userdb.h"

UserDatabase db("users.db");
int server_fd;

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
}

bool handleClient(int client_fd, string& username, byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, string& password){
    printf("\nINFO: handleClient started\n");
    
    byte_vec cmd;
    byte_vec data;
    ERR_CHECK(!recvSecure(client_fd, c_nonce, s_nonce, c_key, c_mac, cmd, data));

    byte_vec cmd_send;
    byte_vec send_data;

    //Verify command
    string command(cmd.begin(), cmd.end());
    
    if(command == CHG){
        printf("CHANGE: Triyng to change password for user %s\n", username.c_str());
        //Parse old_password:new_password
        string data_str(data.begin(), data.end());
        size_t sep_pos = data_str.find(':');
        if (sep_pos == string::npos) {
            printf("ERROR: Invalid authentication format\n");
            return false;
        }

        string old_password = data_str.substr(0, sep_pos);
        string new_password = data_str.substr(sep_pos + 1);

        if(!db.changePassword(username, old_password, new_password)){
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            const char* err_msg = "Change password failed";
            send_data.assign(err_msg, err_msg + strlen(err_msg));
        }
        else{ //error
            cmd_send.assign(ACK, ACK + CMD_SIZE);
            const char* msg = "Change password successfull";
            send_data.assign(msg, msg + strlen(msg));
            password = new_password;
        }
        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data));
    }
    else if(command == CRT){
        printf("CREATE: Trying to create new pair of keys for user %s\n", username.c_str());
        
        User user;
        user = db.getUser(username);
        //check if user doesnt already have pair of keys or flag keysdeleted = true
        if(user.privateKey.empty() && user.publicKey.empty() && (!user.keysDeleted)){
            //create keys
            if(!db.createKeys(username, password)){
                return false;
            }
            cmd_send.assign(ACK, ACK + CMD_SIZE);
            const char* msg = "Creation of keys successfull";
            send_data.assign(msg, msg + strlen(msg));
            printf("ACK: Creation of keys successfull\n");
        }
        else{ //error
            const char* err_msg;
            if(user.keysDeleted){
                printf("ERROR: Keys for user %s were deleted and cannot be recreated \n", username.c_str());
                err_msg = "User keys were deleted";
            }
            else{
                printf("ERROR: User %s has already a pair of keys\n", username.c_str());
                err_msg = "User already has a pair of keys";
            }
            
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            send_data.assign(err_msg, err_msg + strlen(err_msg));
        }
        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data));

    }
    else if(command == DEL){
        printf("DELETE: Trying to delete pair of keys for user %s\n", username.c_str());
        
        User user = db.getUser(username);
        if(!(user.privateKey.empty()) && !(user.publicKey.empty())){ //we can delete them
            if(!db.deleteKeys(username, password)){
                return false;
            }
            cmd_send.assign(ACK, ACK + CMD_SIZE);
            const char* msg = "Deletion of keys successfull";
            send_data.assign(msg, msg + strlen(msg));
            printf("ACK: Deletion of keys successfull\n");
        }
        else{ //error
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            const char* msg = "Deletion of keys failed, user doesn't have keys";
            send_data.assign(msg, msg + strlen(msg));
            printf("ERR: Deletion of keys failed\n");
        }

        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data));
    }
    else if(command == PRT){
        printf("PRINT: Received command PRT from client\n");
        db.printAll();
    }
    else if(command == GET){
        string user(data.begin(), data.end());
        printf("GETPUBKEY: Received GET request for user %s\n", user.c_str()); 

        byte_vec public_key, error_msg;
        if(db.getUserPublicKey(user, public_key, error_msg)) {
            // Success: sned ack + pubkey
            cmd_send.assign(ACK, ACK + CMD_SIZE);
            send_data = public_key;
            printf("Sending public key (%zu bytes): \n", public_key.size());
            printPemPublicKey(public_key);
            
        } else {
            // Error
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            send_data = error_msg;
        }
        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data));
        
    }
    else if(command == SGN) {
        printf("SIGN: Signing request received\n");

        //parsing data: filename and file_content
        auto extractWithLength = [](const byte_vec& vec, size_t& offset) -> byte_vec {
            if (offset + 4 > vec.size()) throw std::runtime_error("Invalid format");
            uint32_t len;
            memcpy(&len, &vec[offset], 4);
            len = ntohl(len);
            offset += 4;
            if (offset + len > vec.size()) throw std::runtime_error("Invalid length");
            byte_vec result(vec.begin() + offset, vec.begin() + offset + len);
            offset += len;
            return result;
        };

        std::string filename;
        byte_vec file_content;

        try {
            size_t offset = 0;
            byte_vec filename_vec = extractWithLength(data, offset);
            file_content = extractWithLength(data, offset);
            filename = std::string(filename_vec.begin(), filename_vec.end());
        } catch (const std::exception& e) {
            printf("ERROR: Malformed SGN payload: %s\n", e.what());
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            std::string msg = "Invalid SGN format";
            send_data.assign(msg.begin(), msg.end());
            sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data);
            return true;
        }

        // Load and decrpyt private key 
        byte_vec error_msg;
        EVP_PKEY* priv_key = nullptr;
        if (!db.decryptPrivateKey(username, file_content, password, error_msg, &priv_key)) {
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            send_data = error_msg;
            sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data);
            return true;
        }

        //sign file
        byte_vec signature;
        if (!serverSignature(priv_key, file_content, signature)) {
            printf("ERROR: Failed to sign file\n");
            EVP_PKEY_free(priv_key);
            cmd_send.assign(ERR, ERR + CMD_SIZE);
            std::string msg = "Failed to sign file";
            send_data.assign(msg.begin(), msg.end()); //error msg
        } else {
            printf("SIGN: Successfully signed %s (%zu bytes)\n", filename.c_str(), signature.size());
            cmd_send.assign(ACK, ACK + CMD_SIZE);
            send_data = signature; //insert signature on send_data
        }

        //free key
        EVP_PKEY_free(priv_key);
        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, cmd_send, send_data));

    }
    else if(command == VRF){
        printf("VERIFY: Verifying document signature\n");

        //same as sign handling
        auto extractWithLength = [](const byte_vec& vec, size_t& offset) -> byte_vec {
            if (offset + 4 > vec.size()) throw std::runtime_error("Invalid format");
            uint32_t len;
            memcpy(&len, &vec[offset], 4);
            len = ntohl(len);
            offset += 4;
            if (offset + len > vec.size()) throw std::runtime_error("Invalid length");
            byte_vec result(vec.begin() + offset, vec.begin() + offset + len);
            offset += len;
            return result;
        };

        std::string signing_user, filename;
        byte_vec file_content, signature;

        try {
            size_t offset = 0;
            byte_vec user_vec     = extractWithLength(data, offset);
            byte_vec filename_vec = extractWithLength(data, offset);
            file_content          = extractWithLength(data, offset);
            signature             = extractWithLength(data, offset);

            signing_user = std::string(user_vec.begin(), user_vec.end());
            filename     = std::string(filename_vec.begin(), filename_vec.end());
        } catch (const std::exception& e) {
            printf("ERROR: Malformed VRF payload: %s\n", e.what());
            byte_vec err_cmd(ERR, ERR + CMD_SIZE);
            std::string msg = "Invalid VRF data format";
            byte_vec err_data(msg.begin(), msg.end());
            ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, err_cmd, err_data));
            return true;
        }

        // Get user public key
        byte_vec pubkey, error_msg;
        if(!db.getUserPublicKey(signing_user, pubkey, error_msg)) {
            byte_vec err_cmd(ERR, ERR + CMD_SIZE);
            ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, err_cmd, error_msg));
            return true;
        }

        // Deserialize key
        const unsigned char* p = pubkey.data();
        EVP_PKEY* pub_key = d2i_PUBKEY(nullptr, &p, pubkey.size());
        if(!pub_key) {
            printf("ERROR: Failed to parse public key\n");
            byte_vec err_cmd(ERR, ERR + CMD_SIZE);
            std::string msg = "Failed to parse public key";
            byte_vec err_data(msg.begin(), msg.end());
            ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, err_cmd, err_data));
            return true;
        }

        // Verify signature
        bool verified = serverVerify(file_content, signature, pub_key);
        EVP_PKEY_free(pub_key);

        byte_vec resp_cmd, resp_data;
        if(verified) {
            resp_cmd.assign(ACK, ACK + CMD_SIZE);
            std::string msg = "Signature is valid";
            resp_data.assign(msg.begin(), msg.end());
            printf("VERIFY: Signature OK for %s\n", filename.c_str());
        } else {
            resp_cmd.assign(ERR, ERR + CMD_SIZE);
            std::string msg = "Signature verification failed";
            resp_data.assign(msg.begin(), msg.end());
            printf("VERIFY: Signature failed for %s\n", filename.c_str());
        }

        ERR_CHECK(!sendSecure(client_fd, c_nonce, s_nonce, s_key, s_mac, resp_cmd, resp_data));
    }

    return true;
}

void handleClientThread(int client_fd,EVP_PKEY* s_priv_key){
    printf("INFO: Client connected.\n");

    byte_vec s_nonce(NONCE_SIZE), c_nonce(NONCE_SIZE);
    byte_vec c_key(SESSION_KEY_SIZE), s_key(SESSION_KEY_SIZE);
    byte_vec c_mac(SESSION_KEY_SIZE), s_mac(SESSION_KEY_SIZE);
    string username, password;

    if(handshake(client_fd, s_priv_key, c_nonce, s_nonce, c_key, s_key, c_mac, s_mac, username, password)) {
        printf("INFO: handshake: finished\n");
        while(handleClient(client_fd, username, c_nonce, s_nonce, c_key, s_key, c_mac, s_mac, password));
    } else {
        printf("INFO: handshake: failed\n");
    }

    printf("INFO: Client disconnected.\n");
    close(client_fd);
}

void sigintHandler(int sig) {
    close(server_fd);
    printf("INFO: Server shutting down...\n");
    printf("END: Server shutdown\n");
    db.saveToFile();
    exit(0);
}

EVP_PKEY* loadServerPrivKey(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen failed");
        return nullptr;
    }

    EVP_PKEY* priv_key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    return priv_key;
}

int main(int argc, char** argv){
    signal(SIGINT, sigintHandler);

    EVP_PKEY* s_priv_key = loadServerPrivKey("server_priv.pem");
    if (!s_priv_key) {
        printf("ERROR: Failed to load server private key\n");
        return 1;
    }
    else{
        printf("LOAD: server_priv.pem loaded successfully\n");
    }

    bool reset_requested = false;
    //bool info_requested = false;
    
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "reset")) {
            reset_requested = true;
        }
    }

    if (reset_requested) {
        printf("RESET: reset of file users.db...\n");
        db.initializeDefaultUsers();
        db.printLimited();
    }
    else{
        db.loadFromFile();
    }
    // no reset command and database is empty
    if (!reset_requested && db.userCount() == 0) {
        printf("WARNING: Database is empty. Use './server reset' to initialize default users\n");
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 5) < 0) { perror("listen"); return 1; }
    
    printf("\nINFO: Server listening on port %d...\n", PORT);
    printf("START: Server started, (Ctrl+C to exit)\n");

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        std::thread(handleClientThread, client_fd, s_priv_key).detach();
    }

    close(server_fd);
    return 0;
}