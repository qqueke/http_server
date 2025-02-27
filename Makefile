MAKEFLAGS += -j$(nproc)

# Compiler
CXX = g++

SRCDIR = src
INCDIR = include
BUILDDIR = build
LIBDIR = lib
TESTDIR = tests

# Dependencies
OPENSSL_DIR = /usr/include/openssl
LS_QPACK_REPO = https://github.com/litespeedtech/ls-qpack.git
LS_HPACK_REPO = https://github.com/litespeedtech/ls-hpack.git
MSQUIC_REPO = https://github.com/microsoft/msquic.git


LS_QPACK_DIR = $(LIBDIR)/ls-qpack
LS_HPACK_DIR = $(LIBDIR)/ls-hpack
MSQUIC_DIR = $(LIBDIR)/msquic

# Lib build directories
LS_QPACK_BUILD = $(LS_QPACK_DIR)/build
LS_HPACK_BUILD = $(LS_HPACK_DIR)/build
MSQUIC_BUILD = $(MSQUIC_DIR)/build

# Compiler flags
CXXFLAGS += -O0 -g -std=c++20 
# -fsanitize=address  

# Include directories
CXXFLAGS += -I$(INCDIR)          
CXXFLAGS += -I$(OPENSSL_DIR)
CXXFLAGS += -I$(LS_QPACK_DIR)
CXXFLAGS += -I$(LS_HPACK_DIR)
CXXFLAGS += -I$(MSQUIC_DIR)/src/inc  

# Library paths 
LDFLAGS += -L$(LS_QPACK_BUILD)
LDFLAGS += -L$(LS_HPACK_BUILD)
LDFLAGS += -L$(MSQUIC_BUILD)/bin/Release  

# Linked libraries
# LDFLAGS += -lasan
# LDFLAGS += -static-libasan
# LDFLAGS += -ltcmalloc

# LDFLAGS += -lprofiler -ltcmalloc
LDFLAGS += -lssl -lcrypto -lz
LDFLAGS += -lmsquic
LDFLAGS += -lls-qpack
LDFLAGS += -lls-hpack

# Source files for server
MAIN_SRC = $(SRCDIR)/main.cpp
SERVER_SRC = $(SRCDIR)/server.cpp
ROUTER_SRC = $(SRCDIR)/router.cpp
ROUTES_SRC = $(SRCDIR)/routes.cpp
LOG_SRC = $(SRCDIR)/log.cpp
S_CALLBACKS_SRC = $(SRCDIR)/sCallbacks.cpp

# Source files for client
CLIENT_SRC = $(SRCDIR)/client.cpp
C_CALLBACKS_SRC = $(SRCDIR)/cCallbacks.cpp

# Common source files
COMMON_SRC = $(SRCDIR)/common.cpp
UTILS_SRC = $(SRCDIR)/utils.cpp

# Object files for server
MAIN_OBJ = $(BUILDDIR)/main.o
SERVER_OBJ = $(BUILDDIR)/server.o
ROUTER_OBJ = $(BUILDDIR)/router.o
ROUTES_OBJ = $(BUILDDIR)/routes.o
LOG_OBJ = $(BUILDDIR)/log.o
S_CALLBACKS_OBJ = $(BUILDDIR)/sCallbacks.o

# Object files for client
CLIENT_OBJ = $(BUILDDIR)/client.o
C_CALLBACKS_OBJ = $(BUILDDIR)/cCallbacks.o

# Common object files
COMMON_OBJ = $(BUILDDIR)/common.o
UTILS_OBJ = $(BUILDDIR)/utils.o

# Targets
all: server 

# all: dependencies server  

.PHONY: dependencies clean
dependencies:
	# Create the LIBDIR directory
	mkdir -p lib

	# Clone or update ls-qpack repository
	# @if [ ! -d "lib/ls-qpack" ]; then \
	# 	git clone --depth 1 $(LS_QPACK_REPO) lib/ls-qpack; \
	# 	mkdir -p $(LS_QPACK_BUILD); \
	# 	cd $(LS_QPACK_BUILD) && cmake .. && make; \
	# else \
	# 	cd lib/ls-qpack && git pull; \
	# 	if ! git diff --quiet; then \
	# 		mkdir -p $(LS_QPACK_BUILD); \
	# 		cd $(LS_QPACK_BUILD) && cmake .. && make; \
	# 	fi; \
	# fi

	# Clone or update ls-hpack repository
	# @if [ ! -d "lib/ls-hpack" ]; then \
	# 	git clone --depth 1 $(LS_HPACK_REPO) lib/ls-hpack; \
	# 	mkdir -p $(LS_HPACK_BUILD); \
	# 	cd $(LS_HPACK_BUILD) && cmake .. && make; \
	# else \
	# 	cd lib/ls-hpack && git pull; \
	# 	if ! git diff --quiet; then \
	# 		mkdir -p $(LS_HPACK_BUILD); \
	# 		cd $(LS_HPACK_BUILD) && cmake .. && make; \
	# 	fi; \
	# fi

	# Clone or update msquic repository
	# @if [ ! -d "lib/msquic" ]; then \
	# 	git clone --depth 1 $(MSQUIC_REPO) lib/msquic; \
	# 	cd lib/msquic && git submodule update --init --recursive; \
	# 	mkdir -p $(MSQUIC_BUILD); \
	# 	cd $(MSQUIC_BUILD) && cmake .. && make; \
	# else \
	# 	cd lib/msquic && git pull; \
	# 	if ! git diff --quiet; then \
	# 		mkdir -p $(MSQUIC_BUILD); \
	# 		cd $(MSQUIC_BUILD) && cmake .. && make; \
	# 	fi; \
	# fi

# Build the main executable
server: $(MAIN_OBJ) $(SERVER_OBJ) $(ROUTER_OBJ) $(ROUTES_OBJ) $(S_CALLBACKS_OBJ) $(LOG_OBJ) $(UTILS_OBJ) $(COMMON_OBJ) $(CLIENT_OBJ) $(C_CALLBACKS_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Rules for building object files
$(BUILDDIR)/main.o: $(MAIN_SRC) $(SERVER_SRC) $(ROUTES_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/server.o: $(SERVER_SRC) $(ROUTER_SRC) $(INCDIR)/server.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/router.o: $(ROUTER_SRC) $(INCDIR)/router.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/routes.o: $(ROUTES_SRC) $(ROUTER_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/log.o: $(LOG_SRC) $(INCDIR)/log.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/client.o: $(CLIENT_SRC) $(INCDIR)/utils.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/sCallbacks.o: $(S_CALLBACKS_SRC) 
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/cCallbacks.o: $(C_CALLBACKS_SRC) 
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/common.o: $(COMMON_SRC) $(INCDIR)/common.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/utils.o: $(UTILS_SRC) $(INCDIR)/utils.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(BUILDDIR)/*.o server client

# Testing target 
test:
	$(CXX) $(CXXFLAGS) $(TESTDIR)/*.cpp -o $(BUILDDIR)/tests && ./$(BUILDDIR)/tests

