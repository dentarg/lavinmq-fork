require "socket"
require "openssl"
require "../config"
require "../proxy_protocol"
require "../../stdlib/socket_shutdown"

module LavinMQ
  module HTTP
    # A client address from a PROXY protocol header. It isn't a `Socket::IPAddress`,
    # so it never counts as loopback, e.g. for the default user: it describes
    # the client as seen by the proxy, not a connection on this host.
    struct ProxiedAddress < ::Socket::Address
      getter address : ::Socket::IPAddress

      def initialize(@address : ::Socket::IPAddress)
        super(@address.family, @address.size)
      end

      def to_unsafe : LibC::Sockaddr*
        @address.to_unsafe
      end

      def to_s(io : IO) : Nil
        @address.to_s(io)
      end
    end

    # Accepts connections for the HTTP server's own listeners, see
    # `Server#bind_tcp` and `#bind_tls`. With tcp_proxy_protocol enabled,
    # connections may start with a PROXY header, see `ProxiedConnection`.
    class ProxyProtocolListener
      include ::Socket::Server

      def initialize(@server : TCPServer, @tls_context : OpenSSL::SSL::Context::Server?,
                     @follower : String -> Bool)
      end

      def accept? : IO?
        client = @server.accept? || return
        if Config.instance.tcp_proxy_protocol?
          ProxiedConnection.new(client, @tls_context, @follower)
        elsif ctx = @tls_context
          # The handshake is done by HTTP::Server, in the connection's fiber
          OpenSSL::SSL::Socket::Server.new(client, ctx, sync_close: true, accept: false)
        else
          client
        end
      end

      def accept : IO
        accept? || raise IO::Error.new("Closed listener")
      end

      def local_address : ::Socket::IPAddress
        @server.local_address
      end

      def close : Nil
        @server.close
      end

      def closed? : Bool
        @server.closed?
      end
    end

    # A connection that may start with a PROXY header, from a trusted source
    # or a follower that forwards one (see *follower*). The header is read,
    # and the TLS handshake done, on first use, so in the connection's fiber.
    # It wraps the TLS socket, rather than the TLS socket wrapping it, so that
    # the TLS socket is on the TCP socket and kTLS works.
    class ProxiedConnection < IO
      Log = LavinMQ::Log.for "http.server"

      @io : IO?
      @remote_address : ::Socket::Address?
      @closed = false

      def initialize(@socket : TCPSocket, @tls_context : OpenSSL::SSL::Context::Server?,
                     @follower : String -> Bool)
      end

      def read(slice : Bytes) : Int32
        io.read(slice).to_i32
      end

      def peek : Bytes?
        io.peek
      end

      def write(slice : Bytes) : Nil
        io.write(slice)
      end

      def flush : Nil
        @io.try &.flush
      end

      def close : Nil
        return if @closed
        @closed = true
        (@io || @socket).close
      end

      def closed? : Bool
        @closed
      end

      # The client's address from a PROXY header from a trusted source, else the peer's
      def remote_address : ::Socket::Address?
        io
        @remote_address
      end

      def local_address : ::Socket::Address
        @socket.local_address
      end

      def read_timeout=(timeout : Time::Span?)
        @socket.read_timeout = timeout
      end

      def write_timeout=(timeout : Time::Span?)
        @socket.write_timeout = timeout
      end

      def shutdown_read_write : Nil
        @socket.shutdown_read_write
      end

      private def io : IO
        @io ||= establish
      end

      # Errors are raised as IO::Error, which HTTP::Server treats as a lost connection
      private def establish : IO
        @remote_address = proxied_address || @socket.remote_address
        if ctx = @tls_context
          # A client that never completes the handshake mustn't hold the fiber
          @socket.read_timeout = ProxyProtocol::HANDSHAKE_TIMEOUT
          ssl = OpenSSL::SSL::Socket::Server.new(@socket, ctx, sync_close: true)
          @socket.read_timeout = nil
          ssl.tap(&.sync=(false))
        else
          @socket.tap(&.sync=(false))
        end
      rescue ex : ProxyProtocol::Error | ArgumentError
        Log.warn { "Invalid PROXY header from #{@socket.remote_address}: #{ex.message}" }
        raise IO::Error.new(ex.message, cause: ex)
      rescue ex : OpenSSL::SSL::Error
        Log.debug(exception: ex) { "Error during SSL handshake" }
        raise IO::Error.new(ex.message, cause: ex)
      end

      # Untrusted and LOCAL headers are read and dropped, see ProxyProtocol.read_trusted
      private def proxied_address : ProxiedAddress?
        remote = @socket.remote_address
        header = ProxyProtocol.read_trusted(@socket, remote, Config.instance, Log,
          trusted: @follower.call(remote.address)) || return
        addr = header.to_conn_info.try(&.remote_address) || return
        ProxiedAddress.new(::Socket::IPAddress.new(addr.address, addr.port.to_i32))
      end
    end
  end
end
