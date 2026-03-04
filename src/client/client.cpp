#include <csignal>
#include <cstring>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <sstream>  // Per std::stringstream
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>  // Per PEM_write_bio_PUBKEY
#include <openssl/err.h>  // Per ERR_print_errors_fp
#include <openssl/evp.h>  // Per EVP_PKEY
#include <fstream>


#include "types.h"
#include "utility.h"
#include "protocol_client.h"

byte_vec pub_key;  //here is stored the pubkey of the user (done with command GET)
string username_pub_key; //here is stored the username associated to that pub_key

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

bool doRequest(int sock, string& username, byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, byte_vec& c_mac, byte_vec& s_key, byte_vec& s_mac){
    printf("\nINFO: ClientRequest started\n");

    printf("INFO: Insert command: ");
    std::string command; command.clear();
    std::cin >> command;

    byte_vec cmd(command.begin(), command.end());
    byte_vec cmd_recv; cmd_recv.clear();
    byte_vec recv_data; recv_data.clear();

    if(command == CHG){
        printf("CHANGE: Insert old password you want to change for %s\n", username.c_str());
        std::string oldPassword;
        std::cin >> oldPassword;

        printf("CHANGE: Insert new password\n");
        std::string newPassword;
        std::cin >> newPassword;

        byte_vec old_password(oldPassword.begin(), oldPassword.end());
        byte_vec new_password(newPassword.begin(), newPassword.end());

        byte_vec chg_data;
        chg_data.insert(chg_data.end(), old_password.begin(), old_password.end());
        chg_data.push_back(':');
        chg_data.insert(chg_data.end(), new_password.begin(), new_password.end());

        printf("INFO: sending CHG command + old_password + new_password\n");
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, chg_data));

        ERR_CHECK(!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, cmd_recv, recv_data));
        
        // Verify ACK command
        string ack_command(cmd_recv.begin(), cmd_recv.end());
        if(ack_command == "ACK"){
            printf("ACK: Received change password ack from server\n");
        }
        else if(ack_command == "ERR"){
            printf("ERR: Received change password err from server\n");
        }
        string data_received(recv_data.begin(), recv_data.end());
        printf("SERVER MSG: %s\n", data_received.c_str());

    }
    else if(command == CRT){
        printf("INFO: sending CRT command\n");
        byte_vec no_data; no_data.clear();
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, no_data));

        ERR_CHECK(!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, cmd_recv, recv_data));
        
        // Verify ACK command
        string ack_command(cmd_recv.begin(), cmd_recv.end());
        if(ack_command == "ACK"){
            printf("ACK: Received Create keys ack from server\n");
        }
        else if(ack_command == "ERR"){
            printf("ERR: Received Create keys err from server\n");
        }
        string data_received(recv_data.begin(), recv_data.end());
        printf("SERVER MSG: %s\n", data_received.c_str());

    }
    else if(command == DEL){
        printf("INFO: sending DEL command\n");
        byte_vec no_data; no_data.clear();
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, no_data));
        
        ERR_CHECK(!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, cmd_recv, recv_data));
    
        // Verify ACK command
        string ack_command(cmd_recv.begin(), cmd_recv.end());
        if(ack_command == "ACK"){
            printf("ACK: Received Delete keys ack from server\n");
        }
        else if(ack_command == "ERR"){
            printf("ERR: Received Delete keys err from server\n");
        }
        string data_received(recv_data.begin(), recv_data.end());
        printf("SERVER MSG: %s\n", data_received.c_str());
    }
    else if(command == GET){
        printf("INFO: sending GET command\n");
        string pubkeyuser;
        printf("Insert the user name whose public key you want\n");
        std::cin >> pubkeyuser;
        byte_vec data(pubkeyuser.begin(), pubkeyuser.end());
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, data));
        
        ERR_CHECK(!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, cmd_recv, recv_data));
        
        // Verify ACK command
        string ack_command(cmd_recv.begin(), cmd_recv.end());
        if(ack_command == ACK){
            printf("ACK: Received getPublicKey ack from server\n");
            pub_key = recv_data;
            username_pub_key = pubkeyuser;
            printf("PUBKEY: Stored pubkey of %s (only for the duration of the session)\n", username_pub_key.c_str());
            printPemPublicKey(recv_data);
        }
        else if(ack_command == ERR){
            printf("ERR: Received getPublicKey err from server\n");
            string data_received(recv_data.begin(), recv_data.end());
            printf("SERVER MSG: %s\n", data_received.c_str());
        }
        
    }
    else if(command == PBK){
        printf("PUBKEY: Trying to print the pubkey stored\n");
        if(pub_key.empty() || username_pub_key.empty()){
            printf("ERR: No pubkey requested. Use command GET before\n");
        }
        else{
            printf("USER_PUBKEY: You have requested the %s pubkey\n", username_pub_key.c_str());
            printPemPublicKey(pub_key);
        }
    }
    else if(command == SGN) {
        printf("SIGN: Requesting to sign a file\n");

        std::string filename;
        printf("SIGN: Enter the file name to sign: ");
        std::cin >> filename;

        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            printf("ERR: Failed to open file %s\n", filename.c_str());
            return true;
        }

        byte_vec file_content((std::istreambuf_iterator<char>(file)), {});
        file.close();

        // Serialize: [len][filename][len][file_content]
        byte_vec sgn_data;

        auto appendWithLength = [](byte_vec& vec, const byte_vec& data) {
            uint32_t len = htonl(static_cast<uint32_t>(data.size()));
            vec.insert(vec.end(), reinterpret_cast<unsigned char*>(&len), reinterpret_cast<unsigned char*>(&len) + sizeof(len));
            vec.insert(vec.end(), data.begin(), data.end());
        };

        appendWithLength(sgn_data, byte_vec(filename.begin(), filename.end()));
        appendWithLength(sgn_data, file_content);

        // Send command
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, sgn_data));

        // Receive signature
        ERR_CHECK(!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, cmd_recv, recv_data));

        std::string ack_command(cmd_recv.begin(), cmd_recv.end());
        if (ack_command == "ACK") {
            printf("ACK: File signed successfully\n");
            std::string sig_filename = filename + ".sig";
            std::ofstream sig_file(sig_filename, std::ios::binary);
            if (!sig_file) {
                printf("ERR: Failed to create signature file %s\n", sig_filename.c_str());
                return true;
            }
            sig_file.write(reinterpret_cast<const char*>(recv_data.data()), recv_data.size());
            sig_file.close();
            printf("SIGN: Signature saved to %s\n", sig_filename.c_str());
        } else {
            std::string error_msg(recv_data.begin(), recv_data.end());
            printf("ERR: Signing failed: %s\n", error_msg.c_str());
        }
    }

    else if(command == VRF){
        printf("VERIFY: Trying to verify signed document\n");

        std::string filename, sig_filename, signing_user;

        printf("VERIFY: Enter the file name to verify: ");
        std::cin >> filename;

        printf("VERIFY: Enter the signature file name: ");
        std::cin >> sig_filename;

        printf("VERIFY: Enter the username who signed the document (leave empty to use the stored pubkey cmd PBK): ");
        std::cin.ignore();
        std::getline(std::cin, signing_user);
        if(signing_user.empty()) signing_user = username_pub_key;

        // Read file content
        std::ifstream file(filename, std::ios::binary);
        if(!file) {
            printf("ERR: Failed to open file %s\n", filename.c_str());
            return true;
        }
        byte_vec file_content((std::istreambuf_iterator<char>(file)), {});
        file.close();

        // Read signature
        std::ifstream sig_file(sig_filename, std::ios::binary);
        if(!sig_file) {
            printf("ERR: Failed to open signature file %s\n", sig_filename.c_str());
            return true;
        }
        byte_vec signature((std::istreambuf_iterator<char>(sig_file)), {});
        sig_file.close();

        // Serialize data: [len][signing_user][len][filename][len][file_content][len][signature]
        auto appendWithLength = [](byte_vec& vec, const byte_vec& data) {
            uint32_t len = htonl(static_cast<uint32_t>(data.size()));
            vec.insert(vec.end(), reinterpret_cast<unsigned char*>(&len), reinterpret_cast<unsigned char*>(&len) + sizeof(len));
            vec.insert(vec.end(), data.begin(), data.end());
        };

        byte_vec vrf_data;
        appendWithLength(vrf_data, byte_vec(signing_user.begin(), signing_user.end()));
        appendWithLength(vrf_data, byte_vec(filename.begin(), filename.end()));
        appendWithLength(vrf_data, file_content);
        appendWithLength(vrf_data, signature);

        // Send command
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, vrf_data));

        // Receive response
        byte_vec ack_cmd, ack_data;
        ERR_CHECK(!recvSecure(sock, c_nonce, s_nonce, s_key, s_mac, ack_cmd, ack_data));

        std::string ack_command(ack_cmd.begin(), ack_cmd.end());
        if(ack_command == "ACK") {
            std::string msg(ack_data.begin(), ack_data.end());
            printf("VERIFY: Document verification successful: %s\n", msg.c_str());
        } else {
            std::string msg(ack_data.begin(), ack_data.end());
            printf("ERR: Verification failed: %s\n", msg.c_str());
        }
    }
    else if(command == PRT){
        byte_vec no_data; no_data.clear();
        ERR_CHECK(!sendSecure(sock, c_nonce, s_nonce, c_key, c_mac, cmd, no_data));
    }
    else{
        printf("COMMAND ERROR: --------------------------------------\n");
        printf("CHG to change password\n");
        printf("CRT to create new pair of keys\n");
        printf("DEL to delete pair of keys\n");
        printf("GET to retrieve public key of a user\n");
        printf("PBK to print the pubkey requested before\n");
        printf("SGN to sign a specific document\n");
        printf("VRF to verify a specific document\n");
        printf("PRT to print all info (//debug on server)\n"); //debug
        printf("-----------------------------------------------------\n");
    }
    
    return true;
}

EVP_PKEY* loadServerPubKey(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if(!fp) return nullptr;
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

int main(int argc, char** argv) {
    string username;
    string password;

    byte_vec c_nonce(NONCE_SIZE);
    byte_vec s_nonce(NONCE_SIZE);
    byte_vec c_key(SESSION_KEY_SIZE);
    byte_vec s_key(SESSION_KEY_SIZE);
    byte_vec c_mac(SESSION_KEY_SIZE);
    byte_vec s_mac(SESSION_KEY_SIZE);

    EVP_PKEY* s_pub_key = loadServerPubKey("server_pub.pem");
    if (!s_pub_key) {
        printf("ERROR: Failed to load server public key\n");
        return 1;
    }
    else{
        printf("LOAD: server_pub.pem loaded successfully\n");
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(IP);

    printf("INFO: Connecting to server at %s:%d...\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    if(!handshake(sock, s_pub_key, username, password, c_nonce, s_nonce, c_key, s_key, c_mac, s_mac)) {
        printf("handshake errorr...\n Closing connection\n");
        close(sock);
        return 0;
    }

    printf("INFO: handshake finished\n");
    while(doRequest(sock, username, c_nonce, s_nonce, c_key, c_mac, s_key, s_mac));
    
    printf("server shutted down...\n Closing connection\n");
    close(sock);
    return 0;
}
