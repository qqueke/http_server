
MAKEFLAGS += -j$(nproc)

# Compiler
CXX = g++

SRCDIR = src
INCDIR = include
BUILDDIR = build
TESTDIR = tests

CXXFLAGS += -O0 -g -std=c++20

# Include directories
CXXFLAGS += -I$(INCDIR)          
CXXFLAGS += -I/usr/include/openssl       
CXXFLAGS += -I/home/QQueke/Documents/Repositories/ls-qpack 
CXXFLAGS += -I/home/QQueke/Documents/Repositories/msquic/src/inc  

# Library paths 
LDFLAGS += -L/home/QQueke/Documents/Repositories/ls-qpack/build 
LDFLAGS += -L/home/QQueke/Documents/Repositories/msquic/build/bin/Release  

# Linked libraries 
LDFLAGS += -lssl -lcrypto -lz
LDFLAGS += -lmsquic
LDFLAGS += -lls-qpack

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
UTILS_OBJ = $(BUILDDIR)/utils.o

# Targets
all: server client

# Build the main executable
server: $(MAIN_OBJ) $(SERVER_OBJ) $(ROUTER_OBJ) $(ROUTES_OBJ) $(LOG_OBJ) $(UTILS_OBJ) $(S_CALLBACKS_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Build the client executable
client: $(CLIENT_OBJ) $(UTILS_OBJ) $(C_CALLBACKS_OBJ) $(LOG_OBJ)
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

$(BUILDDIR)/utils.o: $(UTILS_SRC) $(INCDIR)/utils.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(BUILDDIR)/*.o server client

# Testing target (example, customize as needed)
test:
	$(CXX) $(CXXFLAGS) $(TESTDIR)/*.cpp -o $(BUILDDIR)/tests && ./$(BUILDDIR)/tests

