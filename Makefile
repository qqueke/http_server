MAKEFLAGS += -j$(nproc)

# Compiler
CXX = g++

INCLUDE_PATH = /home/QQueke/Documents/Repositories/msquic/src/inc
LIB_PATH = /home/QQueke/Documents/Repositories/msquic/build/bin/Release
# Compiler flags
CXXFLAGS = -O0 -g -std=c++20 -Iinclude -I/usr/include/openssl -I$(INCLUDE_PATH) -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lz  -L$(LIB_PATH) -lmsquic

# Directories
SRCDIR = src
INCDIR = include
BUILDDIR = build
TESTDIR = tests

# Source files for server
MAIN_SRC = $(SRCDIR)/main.cpp
SERVER_SRC = $(SRCDIR)/server.cpp
ROUTER_SRC = $(SRCDIR)/router.cpp
ROUTES_SRC = $(SRCDIR)/routes.cpp
LOG_SRC = $(SRCDIR)/log.cpp
S_CALLBACKS_SRC = $(SRCDIR)/sCallbacks.cpp

# Source files for client
CLIENT_SRC = $(SRCDIR)/client.cpp

# Common source files
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

# Common object files
UTILS_OBJ = $(BUILDDIR)/utils.o

# Targets
all: server client

# Build the main executable
server: $(MAIN_OBJ) $(SERVER_OBJ) $(ROUTER_OBJ) $(ROUTES_OBJ) $(LOG_OBJ) $(UTILS_OBJ) $(S_CALLBACKS_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Build the client executable
client: $(CLIENT_OBJ) $(UTILS_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

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

$(BUILDDIR)/utils.o: $(UTILS_SRC) $(INCDIR)/utils.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(BUILDDIR)/*.o server client

# Testing target (example, customize as needed)
test:
	$(CXX) $(CXXFLAGS) $(TESTDIR)/*.cpp -o $(BUILDDIR)/tests && ./$(BUILDDIR)/tests

