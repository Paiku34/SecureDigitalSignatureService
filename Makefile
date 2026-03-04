CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I./src/common
LDFLAGS = -lssl -lcrypto -lpthread

# Directory
SRC_DIR = src
BIN_DIR = bin
OBJ_DIR = obj

# Files
COMMON_SRC = $(SRC_DIR)/common/utility.cpp
SERVER_SRC = $(SRC_DIR)/server/server.cpp $(SRC_DIR)/server/protocol_server.cpp $(SRC_DIR)/server/userdb.cpp
CLIENT_SRC = $(SRC_DIR)/client/client.cpp $(SRC_DIR)/client/protocol_client.cpp

# Object files
COMMON_OBJ = $(OBJ_DIR)/utility.o
SERVER_OBJ = $(OBJ_DIR)/server.o $(OBJ_DIR)/protocol_server.o $(OBJ_DIR)/userdb.o
CLIENT_OBJ = $(OBJ_DIR)/client.o $(OBJ_DIR)/protocol_client.o

# Targets
SERVER = $(BIN_DIR)/server
CLIENT = $(BIN_DIR)/client

all: $(SERVER) $(CLIENT)

# Create directories
$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

# Server
$(SERVER): $(BIN_DIR) $(OBJ_DIR) $(SERVER_OBJ) $(COMMON_OBJ)
	$(CXX) $(SERVER_OBJ) $(COMMON_OBJ) $(LDFLAGS) -o $@
	@echo "✓ Server compilato: $(SERVER)"

# Client
$(CLIENT): $(BIN_DIR) $(OBJ_DIR) $(CLIENT_OBJ) $(COMMON_OBJ)
	$(CXX) $(CLIENT_OBJ) $(COMMON_OBJ) $(LDFLAGS) -o $@
	@echo "✓ Client compilato: $(CLIENT)"

# Object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/server/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/client/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/utility.o: $(SRC_DIR)/common/utility.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Run targets
run-server: $(SERVER)
	@echo "🚀 Avvio server..."
	./$(SERVER)

run-client: $(CLIENT)
	@echo "🚀 Avvio client..."
	./$(CLIENT)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "✓ Pulizia completata"

.PHONY: all run-server run-client clean
