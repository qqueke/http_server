// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

#include "../include/quic_server.h"

#include <cstdio>
#include <cstdlib>
#include <format>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <vector>

#include "../include/http3_frame_handler.h"
#include "../include/log.h"

const QUIC_API_TABLE *QuicServer::ms_quic_ = nullptr;
HQUIC QuicServer::config_ = nullptr;

QuicServer::QuicServer(
    const std::shared_ptr<Router> &router,
    const std::shared_ptr<StaticContentHandler> &content_handler, int argc,
    char *argv[])
    : router_(router),
      static_content_handler_(content_handler),
      status_(0),
      listener_(nullptr) {
  // Open a handle to the library and get the API function table.
  if (QUIC_FAILED(status_ = MsQuicOpen2(&ms_quic_))) {
    printf("MsQuicOpen2 failed, 0x%x!\n", status_);
    if (ms_quic_ != nullptr) {
      if (config_ != nullptr) {
        ms_quic_->ConfigurationClose(config_);
      }
      if (registration_ != nullptr) {
        // This will block until all outstanding child objects have been
        // closed.
        ms_quic_->RegistrationClose(registration_);
      }
      MsQuicClose(ms_quic_);
    }

    exit(EXIT_FAILURE);
  }

  // Create a registration for the app's connections.
  if (QUIC_FAILED(
          status_ = ms_quic_->RegistrationOpen(&kRegConfig, &registration_))) {
    printf("RegistrationOpen failed, 0x%x!\n", status_);
    if (ms_quic_ != nullptr) {
      if (config_ != nullptr) {
        ms_quic_->ConfigurationClose(config_);
      }
      if (registration_ != nullptr) {
        // This will block until all outstanding child objects have been
        // closed.
        ms_quic_->RegistrationClose(registration_);
      }
      MsQuicClose(ms_quic_);
    }
    exit(EXIT_FAILURE);
  }

  codec_ = std::make_shared<QpackCodec>(ms_quic_);

  transport_ = std::make_shared<QuicTransport>(ms_quic_);

  frame_builder_ = std::make_shared<Http3FrameBuilder>();

  listen_addr_ = {0};
  QuicAddrSetFamily(&listen_addr_, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&listen_addr_, UDP_PORT);

  // Load the server configuration based on the command line.
  if (!LoadConfiguration(argc, argv)) {
    LogError("Server failed to load configuration.");
    if (listener_ != nullptr) {
      ms_quic_->ListenerClose(listener_);
    }
    return;
  }

  // Create/allocate a new listener object.
  if (QUIC_FAILED(status_ = ms_quic_->ListenerOpen(
                      registration_, ListenerCallback,
                      reinterpret_cast<void *>(this), &listener_))) {
    LogError(std::format("ListenerStart failed, 0x{:x}!", status_));
    LogError("Server failed to load configuration.");
    if (listener_ != nullptr) {
      ms_quic_->ListenerClose(listener_);
    }
    return;
  }
}

QuicServer::~QuicServer() {}

void QuicServer::Run() {
  if (QUIC_FAILED(status_ = ms_quic_->ListenerStart(listener_, &Alpn, 1,
                                                    &listen_addr_))) {
    // printf("ListenerStart failed, 0x%x!\n", Status);
    std::ostringstream oss;
    oss << "ListenerStart failed, 0x" << std::hex << status_ << "!";
    LogError(oss.str());

    LogError("Server failed to load configuration.");
    if (listener_ != nullptr) {
      ms_quic_->ListenerClose(listener_);
    }
    return;
  }
}

int QuicServer::LoadConfiguration(_In_ int argc,
                                  _In_reads_(argc)
                                      _Null_terminated_ char *argv[]) {
  QUIC_SETTINGS Settings = {0};

  // Configures the server's idle timeout.
  Settings.IdleTimeoutMs = 1000;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;

  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  Settings.PeerBidiStreamCount = 100;
  Settings.IsSet.PeerBidiStreamCount = TRUE;
  Settings.PeerUnidiStreamCount = 2;
  Settings.IsSet.PeerUnidiStreamCount = TRUE;

  // Settings.StreamMultiReceiveEnabled = TRUE;

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char *Cert;
  const char *KeyFile;
  if ((Cert = GetValue(argc, argv, "cert_hash")) != nullptr) {
    // Load the server's certificate from the default certificate store,
    // using the provided certificate hash.

    uint32_t CertHashLen = DecodeHexBuffer(
        Cert, sizeof(Config.CertHash.ShaHash), Config.CertHash.ShaHash);
    if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
      return FALSE;
    }
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
    Config.CredConfig.CertificateHash = &Config.CertHash;

  } else if ((Cert = GetValue(argc, argv, "cert_file")) != nullptr &&
             (KeyFile = GetValue(argc, argv, "key_file")) != nullptr) {
    // Loads the server's certificate from the file.
    const char *Password = GetValue(argc, argv, "password");
    if (Password != nullptr) {
      Config.CertFileProtected.CertificateFile = const_cast<char *>(Cert);
      Config.CertFileProtected.PrivateKeyFile = const_cast<char *>(KeyFile);
      Config.CertFileProtected.PrivateKeyPassword =
          const_cast<char *>(Password);
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
      Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
    } else {
      Config.CertFile.CertificateFile = const_cast<char *>(Cert);
      Config.CertFile.PrivateKeyFile = const_cast<char *>(KeyFile);
      Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
      Config.CredConfig.CertificateFile = &Config.CertFile;
    }

  } else {
    printf(
        "Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and "
        "optionally 'password')]!\n");
    return FALSE;
  }

  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(status = ms_quic_->ConfigurationOpen(
                      registration_, &Alpn, 1, &Settings, sizeof(Settings),
                      nullptr, &config_))) {
    std::ostringstream oss;
    oss << "ConfigurationOpen failed, 0x" << std::hex << status;
    LogError(oss.str());

    return FALSE;
  }

  // Leaks here
  // Loads the TLS credential part of the configuration.
  if (QUIC_FAILED(status = ms_quic_->ConfigurationLoadCredential(
                      config_, &Config.CredConfig))) {
    std::ostringstream oss;
    oss << "ConfigurationLoadCredential failed, 0x" << std::hex << status;
    LogError(oss.str());
    return FALSE;
  }

  return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    QuicServer::StreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                               _Inout_ QUIC_STREAM_EVENT *Event) {
  // UNREFERENCED_PARAMETER(Context);
  QuicServer *server = reinterpret_cast<QuicServer *>(Context);

  switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:

      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.

      free(Event->SEND_COMPLETE.ClientContext);
#ifdef QUIC_DEBUG
      printf("[strm][%p] Data sent\n", Stream);
#endif
      break;
    case QUIC_STREAM_EVENT_RECEIVE:

#ifdef QUIC_DEBUG

      printf("[strm][%p] Data received\n", Stream);
#endif

      // If no previous allocated Buffer let's allocate one for this Stream

      // Created here
      // Tried to use after free here
      if (server->quic_buffer_map_.find(Stream) ==
          server->quic_buffer_map_.end()) {
        server->quic_buffer_map_[Stream].reserve(256);
      }

      // Data was received from the peer on Stream.
      for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
        const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];

        uint8_t *bufferPointer = buffer->Buffer;
        uint8_t *bufferEnd = buffer->Buffer + buffer->Length;

        if (buffer->Length > 0) {
          auto &strm_buf = server->quic_buffer_map_[Stream];
          strm_buf.insert(strm_buf.end(), bufferPointer, bufferEnd);
        }
      }

      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:

    {
      if (!server->quic_buffer_map_mutex_[Stream].try_lock()) {
        std::cout << "Seems like someone is using stream: " << Stream
                  << std::endl;
        break;
      }

      // auto startTime = std::chrono::high_resolution_clock::now();
#ifdef QUIC_DEBUG

      printf("[strm][%p] Peer shut down\n", Stream);
#endif
      // The peer gracefully shut down its send direction of the stream.

      if (server->quic_buffer_map_.find(Stream) ==
          server->quic_buffer_map_.end()) {
        std::ostringstream oss;
        oss << " No BufferMap found for Stream: " << Stream << "!";
        LogError(oss.str());
        break;
      }

      {
        std::unique_ptr<Http3FrameHandler> frame_handler =
            std::make_unique<Http3FrameHandler>(
                server->transport_, server->frame_builder_, server->codec_,
                server->router_.lock(), server->static_content_handler_.lock());

        // Should buffer per connection and eventually stream not just stream in
        // case it gets reused no?
        frame_handler->ProcessFrames(Stream, server->quic_buffer_map_[Stream]);
      }

      // Freed here
      server->quic_buffer_map_[Stream].clear();
      server->quic_buffer_map_mutex_[Stream].unlock();
    }

    break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

      // The peer aborted its send direction of the stream.
#ifdef QUIC_DEBUG

      printf("[strm][%p] Peer aborted\n", Stream);
#endif
      ms_quic_->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
// Both directions of the stream have been shut down and MsQuic is done
// with the stream. It can now be safely cleaned up.
#ifdef QUIC_DEBUG
      printf("[strm][%p] Stream officialy closed\n", Stream);
#endif

      ms_quic_->StreamClose(Stream);
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The server's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    QuicServer::ConnectionCallback(_In_ HQUIC Connection,
                                   _In_opt_ void *Context,
                                   _Inout_ QUIC_CONNECTION_EVENT *Event) {
  UNREFERENCED_PARAMETER(Context);

  // HTTPServer *server = (HTTPServer *)Context;

  switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
#ifdef QUIC_DEBUG
      printf("[conn][%p] Connected\n", Connection);
#endif
      // The handshake has completed for the connection.

      // Send  resumption ticket for future interactions
      ms_quic_->ConnectionSendResumptionTicket(
          Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, nullptr);

      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:

      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.

#ifdef QUIC_DEBUG
      if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
          QUIC_STATUS_CONNECTION_IDLE) {
        printf("[conn][%p] Successfully shut down on idle.\n", Connection);
      } else {
        printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
               Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
      }
#endif

      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:

      // The connection was explicitly shut down by the peer.
#ifdef QUIC_DEBUG
      printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
             reinterpret_cast<int64_t>(
                 Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode));
#endif

      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:

      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
#ifdef QUIC_DEBUG

      printf("[conn][%p] Connection officialy closed\n", Connection);
#endif
      ms_quic_->ConnectionClose(Connection);
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:

      // The peer has started/created a new stream. The app MUST set the
      // callback handler before returning.
#ifdef QUIC_DEBUG

      printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
#endif
      ms_quic_->SetCallbackHandler(
          Event->PEER_STREAM_STARTED.Stream,
          reinterpret_cast<void *>(QuicServer::StreamCallback), Context);

      break;
    case QUIC_CONNECTION_EVENT_RESUMED:

      // The connection succeeded in doing a TLS resumption of a previous
      // connection's session.
#ifdef QUIC_DEBUG

      printf("[conn][%p] Connection resumed!\n", Connection);
#endif
      break;
    default:
      break;
  }
  return QUIC_STATUS_SUCCESS;
}

// The server's callback for listener events from MsQuic.
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API
    QuicServer::ListenerCallback(_In_ HQUIC Listener, _In_opt_ void *Context,
                                 _Inout_ QUIC_LISTENER_EVENT *Event) {
  UNREFERENCED_PARAMETER(Listener);
  UNREFERENCED_PARAMETER(Context);
  QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
  switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:

      // A new connection is being attempted by a client. For the handshake to
      // proceed, the server must provide a configuration for QUIC to use. The
      // app MUST set the callback handler before returning.

      ms_quic_->SetCallbackHandler(
          Event->NEW_CONNECTION.Connection,
          reinterpret_cast<void *>(QuicServer::ConnectionCallback), Context);
      Status = ms_quic_->ConnectionSetConfiguration(
          Event->NEW_CONNECTION.Connection, config_);
      break;
    default:
      break;
  }
  return Status;
}
