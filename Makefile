MAKEFLAGS += -j$(nproc)

# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -O0 -g -std=c++20 -Iinclude -I/usr/include/openssl -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lz

# Directories
SRCDIR = src
INCDIR = include
BUILDDIR = build
TESTDIR = tests

# Source files
MAIN_SRC = $(SRCDIR)/main.cpp
SERVER_SRC = $(SRCDIR)/server.cpp
ROUTER_SRC = $(SRCDIR)/router.cpp
ROUTES_SRC = $(SRCDIR)/routes.cpp
LOG_SRC = $(SRCDIR)/log.cpp
# UTILS_SRC = $(SRCDIR)/utils.cpp

# Object files
MAIN_OBJ = $(BUILDDIR)/main.o
SERVER_OBJ = $(BUILDDIR)/server.o
ROUTER_OBJ = $(BUILDDIR)/router.o
ROUTES_OBJ = $(BUILDDIR)/routes.o
LOG_OBJ = $(BUILDDIR)/log.o
# UTILS_OBJ = $(BUILDDIR)/utils.o

# Targets
all: http_server

# Build the main executable
http_server: $(MAIN_OBJ) $(SERVER_OBJ) $(ROUTER_OBJ) $(ROUTES_OBJ) $(LOG_OBJ)
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

# $(BUILDDIR)/utils.o: $(UTILS_SRC)
# 	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(BUILDDIR)/*.o http_server

# Testing target (example, customize as needed)
test:
	$(CXX) $(CXXFLAGS) $(TESTDIR)/*.cpp -o $(BUILDDIR)/tests && ./$(BUILDDIR)/tests

