require "log/spec"
require "http/web_socket"
require "./spec_helper"
require "../src/lavinmq/proxy_protocol"

# Counts the writes it gets, to check that a header isn't written in pieces
private class WriteCountingIO < IO
  getter writes = 0
  getter bytes_written = 0

  def read(slice : Bytes)
    0
  end

  def write(slice : Bytes) : Nil
    @writes += 1
    @bytes_written += slice.size
  end
end

# 127.0.0.1:37424 -> 127.0.0.1:5671
private PROXY_V2_TCPV4_ADDRESS = Bytes[0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x92, 0x30, 0x16, 0x27]

private def proxy_v2_header(address : Bytes = PROXY_V2_TCPV4_ADDRESS) : Bytes
  io = IO::Memory.new
  io.write LavinMQ::ProxyProtocol::V2::Signature.to_slice
  io.write_byte 0x21u8 # v2, PROXY
  io.write_byte 0x11u8 # TCP over IPv4
  io.write_bytes address.size.to_u16, IO::ByteFormat::NetworkEndian
  io.write address
  io.to_slice
end

# PROXY v2 header from 10.1.2.3:54321 to the given port
private def proxy_v2_header_from_client(port : Int32) : Bytes
  io = IO::Memory.new
  io.write Bytes[10, 1, 2, 3, 127, 0, 0, 1]
  io.write_bytes 54321u16, IO::ByteFormat::NetworkEndian
  io.write_bytes port.to_u16, IO::ByteFormat::NetworkEndian
  proxy_v2_header(io.to_slice)
end

# GET /api/whoami as the default user over *io*, returns the status code
private def whoami_status(io : IO) : Int32
  io << "GET /api/whoami HTTP/1.1\r\nHost: localhost\r\n" \
        "Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\nConnection: close\r\n\r\n"
  io.flush
  HTTP::Client::Response.from_io(io, ignore_body: true).status_code
end

# GET /api/whoami as the default user on the HTTP listener, with *proxy_header* sent first
private def http_whoami_status(addr : Socket::IPAddress, proxy_header : Bytes?) : Int32
  socket = TCPSocket.new(addr.address, addr.port)
  socket.read_timeout = 5.seconds
  socket.write proxy_header if proxy_header
  whoami_status(socket)
ensure
  socket.try &.close
end

private def connection_addresses(s : LavinMQ::Server) : Array(String)
  s.connections.compact_map(&.as?(LavinMQ::AMQP::Client)).map(&.connection_info.remote_address.to_s)
end

# Answers the leader's challenge as a follower on replication protocol version 3 or later
private def answer_replication_challenge(follower : IO, password : String, start_header : Bytes) : Nil
  header = Bytes.new(start_header.size)
  follower.read_fully(header)
  header.should eq start_header
  leader_nonce = Bytes.new(LavinMQ::Clustering::CHALLENGE_SIZE)
  follower.read_fully(leader_nonce)
  nonce = Random::Secure.random_bytes(LavinMQ::Clustering::CHALLENGE_SIZE)
  follower.write nonce
  follower.write LavinMQ::Clustering.challenge_response(password, :follower, leader_nonce, nonce, start_header)
end

private def whoami_from_follower_host(start_header : Bytes) : Int32
  config = LavinMQ::Config.instance
  config.clustering = true
  replicator = LavinMQ::Clustering::Server.new(config, NullCoordinator.new, 0)
  status = 0
  with_http_server(replicator: replicator) do |http, _|
    with_proxy_protocol([LavinMQ::IPMatcher.parse("10.0.0.1")]) do
      repli_server = TCPServer.new("127.0.0.1", 0)
      spawn(replicator.listen(repli_server), name: "repli server spec")
      follower = TCPSocket.new("127.0.0.1", repli_server.local_address.port)
      follower.write start_header
      if start_header.in?(LavinMQ::Clustering::StartV3, LavinMQ::Clustering::StartV4)
        answer_replication_challenge(follower, replicator.password, start_header)
      else
        follower.write_byte replicator.password.bytesize.to_u8
        follower.write replicator.password.to_slice
      end
      follower.write_bytes 1i32, IO::ByteFormat::LittleEndian
      follower.read_byte.should eq 0 # authenticated
      wait_for { replicator.all_followers.size == 1 }
      status = http_whoami_status(http.addr, proxy_v2_header)
      follower.close
    ensure
      replicator.close
    end
  end
  status
end

describe "ProxyProtocol" do
  describe "v1" do
    it "can parse valid data" do
      r, w = IO.pipe
      w.write "PROXY TCP4 1.2.3.4 127.0.0.2 34567 1234\r\n".to_slice

      conn_info = LavinMQ::ProxyProtocol::V1.from_io(r).to_conn_info
      conn_info.remote_address.to_s.should eq "1.2.3.4:34567"
      conn_info.local_address.to_s.should eq "127.0.0.2:1234"
      conn_info.ssl?.should be_false
      conn_info.proxied?.should be_true
    end

    it "raises for the UNKNOWN family so the connection is closed" do
      r, w = IO.pipe
      w.write "PROXY UNKNOWN\r\n".to_slice

      expect_raises(LavinMQ::ProxyProtocol::InvalidFamily) do
        LavinMQ::ProxyProtocol::V1.from_io(r)
      end
    end

    it "raises for a family that is not TCP4 or TCP6" do
      r, w = IO.pipe
      w.write "PROXY TCP 1.2.3.4 127.0.0.2 34567 1234\r\n".to_slice

      expect_raises(LavinMQ::ProxyProtocol::InvalidFamily, "TCP") do
        LavinMQ::ProxyProtocol::V1.from_io(r)
      end
    end

    it "can handle invalid data" do
      r, w = IO.pipe
      w.write "GET / HTTP/1.1\r\n".to_slice
      expect_raises(LavinMQ::ProxyProtocol::InvalidSignature) do
        LavinMQ::ProxyProtocol::V1.from_io(r)
      end
    end

    it "can write a header for TCP4 addresses" do
      io = IO::Memory.new
      src = Socket::IPAddress.new("1.1.1.1", 80)
      dst = Socket::IPAddress.new("2.2.2.2", 8080)
      io.write_bytes LavinMQ::ProxyProtocol::V1.new(src, dst)
      io.to_s.should eq "PROXY TCP4 1.1.1.1 2.2.2.2 80 8080\r\n"
    end

    it "can write a header for TCPv6 addresses" do
      io = IO::Memory.new
      src = Socket::IPAddress.new("::1", 80)
      dst = Socket::IPAddress.new("::2", 8080)
      io.write_bytes LavinMQ::ProxyProtocol::V1.new(src, dst)
      io.to_s.should eq "PROXY TCP6 ::1 ::2 80 8080\r\n"
    end
  end

  describe "v2" do
    it "can parse valid data" do
      r, w = IO.pipe
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x4e,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27, 0x20, 0x00, 0x3f, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x07, 0x54,
        0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33, 0x25, 0x00,
        0x07, 0x52, 0x53, 0x41, 0x32, 0x30, 0x34, 0x38,
        0x24, 0x00, 0x0a, 0x52, 0x53, 0x41, 0x2d, 0x53,
        0x48, 0x41, 0x32, 0x35, 0x36, 0x23, 0x00, 0x16,
        0x54, 0x4c, 0x53, 0x5f, 0x41, 0x45, 0x53, 0x5f,
        0x32, 0x35, 0x36, 0x5f, 0x47, 0x43, 0x4d, 0x5f,
        0x53, 0x48, 0x41, 0x33, 0x38, 0x34, 0x41, 0x4d,
        0x51, 0x50, 0x00, 0x00, 0x09, 0x01
      )
      w.write pp_bytes.to_slice

      conn_info = LavinMQ::ProxyProtocol::V2.from_io(r).to_conn_info.should_not be_nil
      conn_info.remote_address.to_s.should eq "127.0.0.1:37424"
      conn_info.local_address.to_s.should eq "127.0.0.1:5671"
      conn_info.ssl?.should be_true
      conn_info.ssl_version.should eq "TLSv1.3"
      conn_info.ssl_cipher.should eq "TLS_AES_256_GCM_SHA384"
      conn_info.proxied?.should be_true
    end

    it "can handle invalid data" do
      r, w = IO.pipe
      w.write "GET / HTTP/1.1\r\n".to_slice
      expect_raises(LavinMQ::ProxyProtocol::InvalidSignature) do
        LavinMQ::ProxyProtocol::V2.from_io(r)
      end
    end

    it "can write header for TCPv4 addresses" do
      io = IO::Memory.new
      src = Socket::IPAddress.new("127.0.0.1", 37424)
      dst = Socket::IPAddress.new("127.0.0.1", 5671)
      io.write_bytes LavinMQ::ProxyProtocol::V2.new(src, dst), IO::ByteFormat::NetworkEndian
      io.to_slice.should eq UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27
      ).to_slice
    end

    it "writes a parsed header back unchanged, TLVs included" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x1e,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27, 0x20, 0x00, 0x0f, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x07, 0x54,
        0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33,
      ).to_slice
      header = LavinMQ::ProxyProtocol::V2.from_io(IO::Memory.new(pp_bytes))
      header.tlvs.size.should eq 1
      header.to_conn_info.should_not(be_nil).ssl_version.should eq "TLSv1.3"
      io = IO::Memory.new
      io.write_bytes header, IO::ByteFormat::NetworkEndian
      io.to_slice.should eq pp_bytes
    end

    it "writes a header in a single write" do
      io = WriteCountingIO.new
      src = Socket::IPAddress.new("2001:db8::1", 37424)
      dst = Socket::IPAddress.new("2001:db8::2", 5671)
      tlvs = [LavinMQ::ProxyProtocol::V2::TLV.new(0x04u8, Bytes.new(8))]
      io.write_bytes LavinMQ::ProxyProtocol::V2.new(src, dst, tlvs), IO::ByteFormat::NetworkEndian
      io.writes.should eq 1
      io.bytes_written.should eq 16 + 36 + 3 + 8
    end

    it "writes and parses TCPv6 addresses" do
      src = Socket::IPAddress.new("2001:db8::1", 37424)
      dst = Socket::IPAddress.new("fe80::a:b", 5671)
      io = IO::Memory.new
      io.write_bytes LavinMQ::ProxyProtocol::V2.new(src, dst), IO::ByteFormat::NetworkEndian
      io.to_slice[12, 4].should eq Bytes[0x21, 0x21, 0x00, 0x24]
      io.rewind
      conn_info = LavinMQ::ProxyProtocol::V2.from_io(io).to_conn_info.should_not be_nil
      conn_info.remote_address.address.should eq "2001:db8::1"
      conn_info.remote_address.port.should eq 37424
      conn_info.local_address.address.should eq "fe80::a:b"
      conn_info.local_address.port.should eq 5671
    end

    it "writes and parses a LOCAL header without addresses" do
      io = IO::Memory.new
      local = LavinMQ::ProxyProtocol::V2.new(nil, nil, command: LavinMQ::ProxyProtocol::V2::Command::Local)
      io.write_bytes local, IO::ByteFormat::NetworkEndian
      io.to_slice[12, 4].should eq Bytes[0x20, 0x00, 0x00, 0x00]
      io.rewind
      header = LavinMQ::ProxyProtocol::V2.from_io(io)
      header.command.should eq LavinMQ::ProxyProtocol::V2::Command::Local
      header.src.should be_nil
      header.to_conn_info.should be_nil
    end

    it "uses no addresses from a LOCAL header" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x20, 0x11, 0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
      ).to_slice
      r, w = IO.pipe
      w.write pp_bytes
      LavinMQ::ProxyProtocol.parse(r).should be_nil
    end

    it "discards the protocol block of a LOCAL header, whatever its family" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x20, 0x31, 0x00, 0x05, # LOCAL, UNIX stream, 5 bytes
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x41, 0x4d, 0x51, 0x50, # payload after the header
      ).to_slice
      io = IO::Memory.new(pp_bytes)
      header = LavinMQ::ProxyProtocol::V2.from_io(io)
      header.local?.should be_true
      header.to_conn_info.should be_nil
      io.gets_to_end.should eq "AMQP"
    end

    it "skips TLVs it doesn't understand" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x16,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27,
        0x04, 0x00, 0x02, 0x00, 0x00, # NOOP
        0xea, 0x00, 0x02, 0x41, 0x42, # vendor specific (AWS)
      ).to_slice
      conn_info = LavinMQ::ProxyProtocol::V2.from_io(IO::Memory.new(pp_bytes)).to_conn_info.should_not be_nil
      conn_info.remote_address.to_s.should eq "127.0.0.1:37424"
    end

    it "doesn't mark a connection as TLS when the SSL TLV says the client didn't use it" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x14,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27,
        0x20, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, # SSL, client: 0, verify: 0
      ).to_slice
      conn_info = LavinMQ::ProxyProtocol::V2.from_io(IO::Memory.new(pp_bytes)).to_conn_info.should_not be_nil
      conn_info.ssl?.should be_false
      conn_info.ssl_verify?.should be_false
    end

    it "refuses a TLV that is longer than the header" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x10,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27, 0x20, 0x00, 0x0e, 0x01,
      ).to_slice
      expect_raises(LavinMQ::ProxyProtocol::Error, "Truncated TLV") do
        LavinMQ::ProxyProtocol::V2.from_io(IO::Memory.new(pp_bytes))
      end
    end
  end

  describe "auto-detection" do
    it "doesn't take an HTTP request split after its first byte for a PROXY header" do
      r, w = IO.pipe
      ch = Channel(Bool).new
      spawn { ch.send LavinMQ::ProxyProtocol.header?(r) }

      w.write "P".to_slice # as in both "PROXY" and "POST"
      Fiber.yield
      w.write "OST / HTTP/1.1\r\n".to_slice

      ch.receive.should be_false
      LavinMQ::ProxyProtocol.read(r).should be_nil
      r.gets.should eq "POST / HTTP/1.1"
    end

    it "auto-detects V1 protocol" do
      r, w = IO.pipe
      w.write "PROXY TCP4 1.2.3.4 127.0.0.2 34567 1234\r\n".to_slice

      conn_info = LavinMQ::ProxyProtocol.parse(r).should_not be_nil
      conn_info.remote_address.to_s.should eq "1.2.3.4:34567"
      conn_info.local_address.to_s.should eq "127.0.0.2:1234"
    end

    it "auto-detects V2 protocol" do
      r, w = IO.pipe
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x4e,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27, 0x20, 0x00, 0x3f, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x07, 0x54,
        0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33, 0x25, 0x00,
        0x07, 0x52, 0x53, 0x41, 0x32, 0x30, 0x34, 0x38,
        0x24, 0x00, 0x0a, 0x52, 0x53, 0x41, 0x2d, 0x53,
        0x48, 0x41, 0x32, 0x35, 0x36, 0x23, 0x00, 0x16,
        0x54, 0x4c, 0x53, 0x5f, 0x41, 0x45, 0x53, 0x5f,
        0x32, 0x35, 0x36, 0x5f, 0x47, 0x43, 0x4d, 0x5f,
        0x53, 0x48, 0x41, 0x33, 0x38, 0x34, 0x41, 0x4d,
        0x51, 0x50, 0x00, 0x00, 0x09, 0x01
      )
      w.write pp_bytes.to_slice

      conn_info = LavinMQ::ProxyProtocol.parse(r).should_not be_nil
      conn_info.remote_address.to_s.should eq "127.0.0.1:37424"
      conn_info.ssl?.should be_true
      conn_info.proxied?.should be_true
    end

    it "returns nil for AMQP protocol header" do
      r, w = IO.pipe
      w.write "AMQP\x00\x00\x09\x01".to_slice

      conn_info = LavinMQ::ProxyProtocol.parse(r)
      conn_info.should be_nil
    end

    it "returns nil for MQTT protocol header" do
      r, w = IO.pipe
      w.write Bytes[0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54]

      conn_info = LavinMQ::ProxyProtocol.parse(r)
      conn_info.should be_nil
    end

    it "returns nil for HTTP request" do
      r, w = IO.pipe
      w.write "GET / HTTP/1.1\r\n".to_slice

      conn_info = LavinMQ::ProxyProtocol.parse(r)
      conn_info.should be_nil
    end

    it "times out on the initial peek when the peer sends nothing" do
      r, _w = IO.pipe
      expect_raises(IO::TimeoutError) do
        LavinMQ::ProxyProtocol.parse(r, timeout: 100.milliseconds)
      end
      # read_timeout must be reset so it doesn't leak into the connection handler
      r.read_timeout.should be_nil
    end

    it "detects a V2 header split across TCP segments" do
      pp_bytes = UInt8.static_array(
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
        0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00, 0x0c,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x92, 0x30, 0x16, 0x27
      )
      r, w = IO.pipe
      ch = Channel(LavinMQ::ConnectionInfo?).new
      spawn { ch.send LavinMQ::ProxyProtocol.parse(r) }

      # First segment carries fewer than the 12 signature bytes
      w.write pp_bytes.to_slice[0, 6]
      Fiber.yield
      w.write pp_bytes.to_slice[6..]

      conn_info = ch.receive.should_not be_nil
      conn_info.remote_address.to_s.should eq "127.0.0.1:37424"
    end

    it "detects a V1 header split across TCP segments" do
      header = "PROXY TCP4 1.2.3.4 127.0.0.2 34567 1234\r\n".to_slice
      r, w = IO.pipe
      ch = Channel(LavinMQ::ConnectionInfo?).new
      spawn { ch.send LavinMQ::ProxyProtocol.parse(r) }

      w.write header[0, 3] # "PRO"
      Fiber.yield
      w.write header[3..]

      conn_info = ch.receive.should_not be_nil
      conn_info.remote_address.to_s.should eq "1.2.3.4:34567"
    end
  end

  describe "on HTTP" do
    it "reads a PROXY header, and the address never counts as loopback" do
      with_http_server do |http, _|
        with_proxy_protocol do
          # The header claims the client is 127.0.0.1, but the default user is limited to loopback
          http_whoami_status(http.addr, proxy_v2_header).should eq 401
          http_whoami_status(http.addr, nil).should eq 200
        end
      end
    end

    it "doesn't read PROXY headers with tcp_proxy_protocol disabled" do
      with_http_server do |http, _|
        header = "PROXY TCP4 10.1.2.3 127.0.0.1 54321 #{http.addr.port}\r\n".to_slice
        http_whoami_status(http.addr, header).should eq 400
      end
    end

    it "trusts PROXY headers from followers on replication protocol version 4" do
      # The address in the header never counts as loopback, so the default user is refused
      whoami_from_follower_host(LavinMQ::Clustering::StartV4).should eq 401
    end

    it "doesn't trust PROXY headers from older followers, which forward a client's" do
      # The header is ignored, so the default user is on a real loopback connection
      whoami_from_follower_host(LavinMQ::Clustering::StartV3).should eq 200
      whoami_from_follower_host(LavinMQ::Clustering::StartV2).should eq 200
    end

    it "ignores a PROXY header from an untrusted source" do
      with_http_server do |http, _|
        with_proxy_protocol([LavinMQ::IPMatcher.parse("10.0.0.1")]) do
          Log.capture("lmq.http.server", :warn) do |logs|
            # The header is dropped, so the default user is on a real loopback connection
            http_whoami_status(http.addr, proxy_v2_header).should eq 200
            logs.check(:warn, /^PROXY protocol from untrusted source /)
          end
        end
      end
    end

    it "reads a PROXY header on HTTPS in front of TLS" do
      with_amqp_server do |s|
        with_proxy_protocol do
          ctx = OpenSSL::SSL::Context::Server.new
          ctx.certificate_chain = "spec/resources/server_certificate.pem"
          ctx.private_key = "spec/resources/server_key.pem"
          addr = s.http_server.bind_tls("127.0.0.1", 0, ctx)
          spawn(name: "https listen") { s.http_server.listen }
          Fiber.yield
          socket = TCPSocket.new(addr.address, addr.port)
          socket.write proxy_v2_header
          client_ctx = OpenSSL::SSL::Context::Client.new
          client_ctx.verify_mode = OpenSSL::SSL::VerifyMode::NONE
          tls = OpenSSL::SSL::Socket::Client.new(socket, client_ctx, sync_close: true)
          begin
            tls.read_timeout = 5.seconds
            whoami_status(tls).should eq 401
          ensure
            tls.close
          end
        end
      end
    end

    it "gives WebSocket connections the client's address from a PROXY header" do
      with_http_server do |http, s|
        with_proxy_protocol do
          s.users.create("foo", "bar")
          s.users.add_permission "foo", "/", /.*/, /.*/, /.*/
          socket = TCPSocket.new(http.addr.address, http.addr.port)
          socket.read_timeout = 5.seconds
          socket.write proxy_v2_header_from_client(http.addr.port)
          socket << "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" \
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" \
                    "Sec-WebSocket-Protocol: amqp\r\n\r\n"
          socket.flush
          HTTP::Client::Response.from_io(socket, ignore_body: true).status_code.should eq 101
          ws = HTTP::WebSocket.new(HTTP::WebSocket::Protocol.new(socket, masked: true))
          conn = AMQP::Client::Connection.start(AMQP::Client::WebSocketIO.new(ws),
            "foo", "bar", "/", 10u16, 4096u32, 0u16, AMQP::Client::ConnectionInformation.new)
          begin
            wait_for { s.connections.present? }
            connection_addresses(s).should eq ["10.1.2.3:54321"]
            s.connections.first.as(LavinMQ::AMQP::Client).connection_info.proxied?.should be_true
          ensure
            conn.close
          end
        end
      end
    end
  end

  describe "trusted sources" do
    it "parses individual IPv4 addresses" do
      config = LavinMQ::Config.new
      config.proxy_protocol_trusted_sources = LavinMQ::IPMatcher.parse_list("192.168.1.1, 10.0.0.1")

      config.proxy_protocol_trusted_sources.size.should eq 2
      config.proxy_protocol_trusted_sources[0].matches?("192.168.1.1").should be_true
      config.proxy_protocol_trusted_sources[0].matches?("192.168.1.2").should be_false
    end

    it "parses IPv4 CIDR notation" do
      config = LavinMQ::Config.new
      config.proxy_protocol_trusted_sources = LavinMQ::IPMatcher.parse_list("192.168.0.0/24")

      config.proxy_protocol_trusted_sources.size.should eq 1
      config.proxy_protocol_trusted_sources[0].matches?("192.168.0.1").should be_true
      config.proxy_protocol_trusted_sources[0].matches?("192.168.0.255").should be_true
      config.proxy_protocol_trusted_sources[0].matches?("192.168.1.1").should be_false
    end

    it "parses IPv6 CIDR notation" do
      config = LavinMQ::Config.new
      config.proxy_protocol_trusted_sources = LavinMQ::IPMatcher.parse_list("2001:db8::/32")

      config.proxy_protocol_trusted_sources.size.should eq 1
      config.proxy_protocol_trusted_sources[0].matches?("2001:db8::1").should be_true
      config.proxy_protocol_trusted_sources[0].matches?("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").should be_true
      config.proxy_protocol_trusted_sources[0].matches?("2001:db9::1").should be_false
    end

    it "parses mixed IPs and CIDR notation" do
      config = LavinMQ::Config.new
      config.proxy_protocol_trusted_sources = LavinMQ::IPMatcher.parse_list(
        "10.0.0.1, 192.168.0.0/24, 2001:db8::/32, ::1")

      config.proxy_protocol_trusted_sources.size.should eq 4

      # Exact IPv4
      config.proxy_protocol_trusted_sources[0].matches?("10.0.0.1").should be_true
      config.proxy_protocol_trusted_sources[0].matches?("10.0.0.2").should be_false

      # IPv4 CIDR
      config.proxy_protocol_trusted_sources[1].matches?("192.168.0.50").should be_true
      config.proxy_protocol_trusted_sources[1].matches?("192.168.1.50").should be_false

      # IPv6 CIDR
      config.proxy_protocol_trusted_sources[2].matches?("2001:db8::100").should be_true
      config.proxy_protocol_trusted_sources[2].matches?("2001:db9::1").should be_false

      # Exact IPv6
      config.proxy_protocol_trusted_sources[3].matches?("::1").should be_true
      config.proxy_protocol_trusted_sources[3].matches?("::2").should be_false
    end

    it "raises on an invalid entry mixed with valid ones" do
      # A typo must fail loudly rather than silently dropping the entry and
      # degrading the allow-list (potentially to trust-all).
      expect_raises(ArgumentError, /Invalid IP\/CIDR 'invalid-ip'/) do
        LavinMQ::IPMatcher.parse_list("10.0.0.1, invalid-ip, 192.168.0.0/24")
      end
    end

    it "raises when every entry is invalid instead of collapsing to trust-all" do
      # Regression for #2083: an all-invalid list must not parse to an empty
      # array (which trusted_proxy_source? treats as trust-all).
      expect_raises(ArgumentError, /Invalid IP\/CIDR/) do
        LavinMQ::IPMatcher.parse_list("10.0.0.0/33, 300.0.0.1")
      end
    end

    it "handles whitespace correctly" do
      config = LavinMQ::Config.new
      config.proxy_protocol_trusted_sources = LavinMQ::IPMatcher.parse_list(
        "  10.0.0.1  ,  192.168.0.0/24  ")

      config.proxy_protocol_trusted_sources.size.should eq 2
      config.proxy_protocol_trusted_sources[0].matches?("10.0.0.1").should be_true
      config.proxy_protocol_trusted_sources[1].matches?("192.168.0.50").should be_true
    end

    it "returns empty array for empty config" do
      config = LavinMQ::Config.new
      config.proxy_protocol_trusted_sources = LavinMQ::IPMatcher.parse_list("")

      config.proxy_protocol_trusted_sources.size.should eq 0
    end

    it "fails loudly on an invalid entry (does not collapse to trust-all)" do
      expect_raises(ArgumentError, /Invalid IP\/CIDR/) do
        LavinMQ::IPMatcher.parse_list("10.0.0.0/33, not-an-ip")
      end
    end

    it "matches an IPv4 trusted source for an IPv4-mapped IPv6 peer (dual-stack)" do
      sources = LavinMQ::IPMatcher.parse_list("10.0.0.0/24")
      # An IPv4 load balancer behind a `bind = ::` listener arrives mapped
      sources.any?(&.matches?("::ffff:10.0.0.5")).should be_true
      sources.any?(&.matches?("::ffff:10.0.1.5")).should be_false
    end
  end

  it "reads a load balancer's header in front of a TLS handshake" do
    with_amqp_server(tls: true) do |s|
      s.@config.tcp_proxy_protocol = true
      tcp_client = TCPSocket.new("localhost", amqp_tls_port(s))
      tcp_client.read_timeout = 5.seconds
      tcp_client.write "PROXY TCP4 203.0.113.7 127.0.0.1 40000 5671\r\n".to_slice
      client_ctx = OpenSSL::SSL::Context::Client.new
      client_ctx.verify_mode = OpenSSL::SSL::VerifyMode::NONE
      ssl_client = OpenSSL::SSL::Socket::Client.new(tcp_client, client_ctx, sync_close: true)
      ssl_client.write AMQ::Protocol::PROTOCOL_START_0_9_1.to_slice
      ssl_client.flush
      AMQ::Protocol::Stream.new(ssl_client).next_frame.should be_a(AMQ::Protocol::Frame::Connection::Start)
    ensure
      ssl_client.try &.close rescue nil
      tcp_client.try &.close rescue nil
    end
  end

  # Invalid addresses, a truncated v2 header or nothing at all before the
  # timeout each raise something else than a ProxyProtocol::Error
  {"PROXY TCP4 a b 1 2\r\n", "PROXY TCP4 1.2.3.4 127.0.0.1 99999 5671\r\n"}.each do |header|
    it "logs an invalid PROXY header in front of TLS as a warning: #{header.inspect}" do
      with_amqp_server(tls: true) do |s|
        s.@config.tcp_proxy_protocol = true
        Log.capture("lmq.server", :warn) do |logs|
          socket = TCPSocket.new("localhost", amqp_tls_port(s))
          socket.write header.to_slice
          socket.read_timeout = 5.seconds
          socket.read(Bytes.new(1)).should eq 0 # closed by the server
          socket.close
          logs.check(:warn, /^Error accepting TLS connection from /)
        end
      end
    end
  end
end
