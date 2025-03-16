MAKEFLAGS += -j$(nproc)

# Compiler
CXX = g++

SRCDIR = src
INCDIR = include
BUILDDIR = build
LIBDIR = lib
TESTDIR = tests

# Dependencies
LS_QPACK_REPO = https://github.com/litespeedtech/ls-qpack.git
LS_HPACK_REPO = https://github.com/litespeedtech/ls-hpack.git
MSQUIC_REPO = https://github.com/microsoft/msquic.git


TEST_SRCS = $(filter-out src/main.cc, $(wildcard src/*.cc))

LS_QPACK_DIR = $(LIBDIR)/ls-qpack
LS_HPACK_DIR = $(LIBDIR)/ls-hpack
MSQUIC_DIR = $(LIBDIR)/msquic

# Lib build directories
LS_QPACK_BUILD = $(LS_QPACK_DIR)/build
LS_HPACK_BUILD = $(LS_HPACK_DIR)/build
MSQUIC_BUILD = $(MSQUIC_DIR)/build

# Compiler flags
CXXFLAGS += -O3 -g -Wall -std=c++20 
#-fsanitize=address  

# Include directories
CXXFLAGS += -I$(INCDIR)          
CXXFLAGS += -I$(LS_QPACK_DIR)
CXXFLAGS += -I$(LS_HPACK_DIR)
CXXFLAGS += -I$(MSQUIC_DIR)/src/inc  


# Library paths 
LDFLAGS += -L$(LS_QPACK_BUILD)
LDFLAGS += -L$(LS_HPACK_BUILD)
LDFLAGS += -L$(MSQUIC_BUILD)/bin/Release  

# Linked libraries
# LDFLAGS += -lasan
# LDFLAGS += -lprofiler -ltcmalloc

LDFLAGS += -lgtest -lgtest_main -pthread
LDFLAGS += -lssl -lcrypto -lz
LDFLAGS += -lmsquic
LDFLAGS += -lls-qpack
LDFLAGS += -lls-hpack

# Source files for server
MAIN_SRC = $(SRCDIR)/main.cc
SERVER_SRC = $(SRCDIR)/server.cc
ROUTER_SRC = $(SRCDIR)/router.cc
ROUTES_SRC = $(SRCDIR)/routes.cc
LOG_SRC = $(SRCDIR)/log.cc

CODEC_SRC = $(SRCDIR)/codec.cc
HTTP2_FRAME_BUILDER_SRC = $(SRCDIR)/http2_frame_builder.cc

HTTP3_FRAME_BUILDER_SRC = $(SRCDIR)/http3_frame_builder.cc
HTTP2_FRAME_HANDLER_SRC = $(SRCDIR)/http2_frame_handler.cc


HEADER_PARSER_SRC = $(SRCDIR)/header_parser.cc
HEADER_VALIDATOR_SRC = $(SRCDIR)/header_validator.cc


STATIC_CONTENT_HANDLER_SRC = $(SRCDIR)/static_content_handler.cc

DATABASE_SRC = $(SRCDIR)/database.cc
HTTP3_FRAME_HANDLER_SRC = $(SRCDIR)/http3_frame_handler.cc

TRANSPORT_SRC = $(SRCDIR)/transport.cc

TLS_MANAGER_SRC = $(SRCDIR)/tls_manager.cc

CLIENT_SRC = $(SRCDIR)/client.cc

UTILS_SRC = $(SRCDIR)/utils.cc

TCP_SERVER_SRC = $(SRCDIR)/tcp_server.cc

TCP_CLIENT_SRC = $(SRCDIR)/tcp_client.cc

QUIC_SERVER_SRC = $(SRCDIR)/quic_server.cc

QUIC_CLIENT_SRC = $(SRCDIR)/quic_client.cc


# Object files for server
MAIN_OBJ = $(BUILDDIR)/main.o
SERVER_OBJ = $(BUILDDIR)/server.o
ROUTER_OBJ = $(BUILDDIR)/router.o
ROUTES_OBJ = $(BUILDDIR)/routes.o
LOG_OBJ = $(BUILDDIR)/log.o

CODEC_OBJ = $(BUILDDIR)/codec.o
HTTP2_FRAME_BUILDER_OBJ = $(BUILDDIR)/http2_frame_builder.o

HTTP3_FRAME_BUILDER_OBJ = $(BUILDDIR)/http3_frame_builder.o
TRANSPORT_OBJ = $(BUILDDIR)/transport.o

TLS_MANAGER_OBJ = $(BUILDDIR)/tls_manager.o

HTTP2_FRAME_HANDLER_OBJ = $(BUILDDIR)/http2_frame_handler.o
HEADER_PARSER_OBJ = $(BUILDDIR)/header_parser.o
HEADER_VALIDATOR_OBJ = $(BUILDDIR)/header_validator.o

STATIC_CONTENT_HANDLER_OBJ = $(BUILDDIR)/static_content_handler.o

DATABASE_OBJ = $(BUILDDIR)/database.o

HTTP3_FRAME_HANDLER_OBJ = $(BUILDDIR)/http3_frame_handler.o

TCP_SERVER_OBJ = $(BUILDDIR)/tcp_server.o

TCP_CLIENT_OBJ = $(BUILDDIR)/tcp_client.o


QUIC_SERVER_OBJ = $(BUILDDIR)/quicserver.o

QUIC_CLIENT_OBJ = $(BUILDDIR)/quicclient.o

# Object files for client
CLIENT_OBJ = $(BUILDDIR)/client.o

UTILS_OBJ = $(BUILDDIR)/utils.o

# Targets
all: server 

# all: dependencies server  

.PHONY: dependencies clean
dependencies:
	# Create the LIBDIR directory
	mkdir -p lib

	# Clone or update ls-qpack repository
	@if [ ! -d "lib/ls-qpack" ]; then \
		git clone --depth 1 $(LS_QPACK_REPO) lib/ls-qpack; \
		mkdir -p $(LS_QPACK_BUILD); \
		cd $(LS_QPACK_BUILD) && cmake .. && make; \
	else \
		cd lib/ls-qpack && git pull; \
		if ! git diff --quiet; then \
			mkdir -p $(LS_QPACK_BUILD); \
			cd $(LS_QPACK_BUILD) && cmake .. && make; \
		fi; \
	fi

	# Clone or update ls-hpack repository
	@if [ ! -d "lib/ls-hpack" ]; then \
		git clone --depth 1 $(LS_HPACK_REPO) lib/ls-hpack; \
		mkdir -p $(LS_HPACK_BUILD); \
		cd $(LS_HPACK_BUILD) && cmake .. && make; \
	else \
		cd lib/ls-hpack && git pull; \
		if ! git diff --quiet; then \
			mkdir -p $(LS_HPACK_BUILD); \
			cd $(LS_HPACK_BUILD) && cmake .. && make; \
		fi; \
	fi

	# Clone or update msquic repository
	@if [ ! -d "lib/msquic" ]; then \
		git clone --depth 1 $(MSQUIC_REPO) lib/msquic; \
		cd lib/msquic && git submodule update --init --recursive; \
		mkdir -p $(MSQUIC_BUILD); \
		cd $(MSQUIC_BUILD) && cmake .. && make; \
	else \
		cd lib/msquic && git pull; \
		if ! git diff --quiet; then \
			mkdir -p $(MSQUIC_BUILD); \
			cd $(MSQUIC_BUILD) && cmake .. && make; \
		fi; \
	fi

# Build the main executable
server: $(MAIN_OBJ) $(SERVER_OBJ) $(ROUTER_OBJ) $(ROUTES_OBJ) $(LOG_OBJ) $(UTILS_OBJ) $(CLIENT_OBJ) $(CODEC_OBJ) $(HTTP2_FRAME_BUILDER_OBJ) $(HTTP2_FRAME_HANDLER_OBJ) $(TRANSPORT_OBJ) $(HEADER_PARSER_OBJ) $(HEADER_VALIDATOR_OBJ) $(HTTP3_FRAME_BUILDER_OBJ) $(HTTP3_FRAME_HANDLER_OBJ) $(TLS_MANAGER_OBJ) $(TCP_SERVER_OBJ) $(TCP_CLIENT_OBJ) $(QUIC_SERVER_OBJ) $(QUIC_CLIENT_OBJ) $(DATABASE_OBJ) $(STATIC_CONTENT_HANDLER_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Rules for building object files
$(MAIN_OBJ): $(MAIN_SRC) $(SERVER_SRC) $(ROUTES_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SERVER_OBJ): $(SERVER_SRC) $(ROUTER_SRC) $(INCDIR)/server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(ROUTER_OBJ): $(ROUTER_SRC) $(INCDIR)/router.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(ROUTES_OBJ): $(ROUTES_SRC) $(ROUTER_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/log.o: $(LOG_SRC) $(INCDIR)/log.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(CLIENT_OBJ): $(CLIENT_SRC) $(INCDIR)/utils.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(UTILS_OBJ): $(UTILS_SRC) $(INCDIR)/utils.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(CODEC_OBJ): $(CODEC_SRC) $(INCDIR)/codec.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HTTP2_FRAME_BUILDER_OBJ): $(HTTP2_FRAME_BUILDER_SRC) $(INCDIR)/http2_frame_builder.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HTTP3_FRAME_BUILDER_OBJ): $(HTTP3_FRAME_BUILDER_SRC) $(INCDIR)/http3_frame_builder.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HTTP2_FRAME_HANDLER_OBJ): $(HTTP2_FRAME_HANDLER_SRC) $(INCDIR)/http2_frame_handler.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HEADER_PARSER_OBJ): $(HEADER_PARSER_SRC) $(INCDIR)/header_parser.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HEADER_VALIDATOR_OBJ): $(HEADER_VALIDATOR_SRC) $(INCDIR)/header_validator.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(STATIC_CONTENT_HANDLER_OBJ): $(STATIC_CONTENT_HANDLER_SRC) $(INCDIR)/static_content_handler.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(DATABASE_OBJ): $(DATABASE_SRC) $(INCDIR)/database.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(HTTP3_FRAME_HANDLER_OBJ): $(HTTP3_FRAME_HANDLER_SRC) $(INCDIR)/http3_frame_handler.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TRANSPORT_OBJ): $(TRANSPORT_SRC) $(INCDIR)/transport.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TCP_SERVER_OBJ): $(TCP_SERVER_SRC) $(INCDIR)/tcp_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TCP_CLIENT_OBJ): $(TCP_CLIENT_SRC) $(INCDIR)/tcp_client.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(QUIC_SERVER_OBJ): $(QUIC_SERVER_SRC) $(INCDIR)/quic_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(QUIC_CLIENT_OBJ): $(QUIC_CLIENT_SRC) $(INCDIR)/quic_client.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TLS_MANAGER_OBJ): $(TLS_MANAGER_SRC) $(INCDIR)/tls_manager.h
	$(CXX) $(CXXFLAGS) -c $< -o $@
# Clean target
clean:
	rm -f $(BUILDDIR)/*.o server client

# Testing target 
test: $(TESTDIR)/*.cc $(TEST_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $(BUILDDIR)/tests $(LDFLAGS)
	./$(BUILDDIR)/tests

