require "./spec_helper"
require "../src/lavinmq/client_listeners"

# The leader runs on the same host in these specs, so it can't use the same
# ports: forwards to *leader_ports*, by this node's port
private class SpecListeners < LavinMQ::ClientListeners
  def initialize(config, leader_host, @leader_ports : Hash(Int32, Int32))
    super(config, leader_host)
  end

  private def leader_port(l) : Int32?
    l.target_port.try { |port| @leader_ports[port] }
  end
end

# Reports whether what it accepts has TCP_NODELAY set
private class NodelayListeners < LavinMQ::ClientListeners
  getter nodelay = Channel(Bool).new(1)

  private def dispatch(l, io) : Nil
    nodelay.send io.as(TCPSocket).tcp_nodelay?
    io.close
  end
end

private def tls_context : OpenSSL::SSL::Context::Server
  ctx = OpenSSL::SSL::Context::Server.new
  ctx.certificate_chain = "spec/resources/server_certificate.pem"
  ctx.private_key = "spec/resources/server_key.pem"
  ctx
end

private def tls_client : OpenSSL::SSL::Context::Client
  ctx = OpenSSL::SSL::Context::Client.new
  ctx.verify_mode = OpenSSL::SSL::VerifyMode::NONE
  ctx
end

# Only AMQP and AMQPS, on ports of their own
private def listener_config : LavinMQ::Config
  config = LavinMQ::Config.new
  config.amqp_bind = "127.0.0.1"
  config.amqp_port = free_port
  config.amqps_port = free_port
  config.mqtt_port = config.mqtts_port = config.http_port = config.https_port = -1
  config.unix_path = config.mqtt_unix_path = config.http_unix_path = ""
  config
end

private def proxied_connections(s : LavinMQ::Server) : Array(Bool)
  s.connections.map { |c| c.as(LavinMQ::AMQP::Client).connection_info.proxied? }
end

describe LavinMQ::ClientListeners do
  it "forwards AMQP and AMQPS to the leader, with the client's address, until this node serves" do
    with_amqp_server(extra_tls_listener: true) do |s|
      with_proxy_protocol do # how the leader trusts a follower's PROXY header
        s.@config.default_user_only_loopback = false
        config = listener_config
        leader : String? = "localhost"
        listeners = SpecListeners.new(config, -> { leader.as(String?) },
          {config.amqp_port => amqp_port(s), config.amqps_port => amqp_tls_port(s)})
        listeners.bind(tls_context, nil, nil)
        listeners.listen
        begin
          plain = AMQP::Client.new(host: "127.0.0.1", port: config.amqp_port).connect
          tls = AMQP::Client.new(host: "127.0.0.1", port: config.amqps_port, tls: tls_client).connect
          plain.channel.queue("through-follower").publish_confirm("m").should be_true
          tls.channel.queue("through-follower").publish_confirm("m").should be_true
          s.vhosts["/"].queue("through-follower").message_count.should eq 2
          proxied_connections(s).should eq [true, true]

          # Now this node serves, on the same ports
          listeners.serve(LavinMQ::ClientListeners::Brokers.new(s.amqp_server, s.mqtt_server, s.http_server))
          wait_for { plain.closed? && tls.closed? } # were forwarded to the old leader
          local = AMQP::Client.new(host: "127.0.0.1", port: config.amqp_port).connect
          local.channel.queue("through-follower").publish_confirm("m").should be_true
          proxied_connections(s).should eq [false]
          local.close
        ensure
          listeners.close
        end
      end
    end
  end

  it "hands HTTP to the broker with the client's address" do
    with_amqp_server do |s|
      config = listener_config
      config.amqp_port = config.amqps_port = -1
      config.http_bind = "127.0.0.1"
      config.http_port = free_port
      listeners = LavinMQ::ClientListeners.new(config, -> { nil.as(String?) })
      listeners.bind(nil, nil, nil)
      listeners.listen
      listeners.serve(LavinMQ::ClientListeners::Brokers.new(s.amqp_server, s.mqtt_server, s.http_server))
      # The default user may only log in from loopback
      response = HTTP::Client.new("127.0.0.1", config.http_port).get("/api/whoami",
        headers: HTTP::Headers{"Authorization" => "Basic #{Base64.strict_encode("guest:guest")}"})
      response.status_code.should eq 200
    ensure
      listeners.try &.close
    end
  end

  it "accepts with TCP_NODELAY set, as configured" do
    config = listener_config
    config.amqp_port = config.amqps_port = -1
    config.http_bind = "127.0.0.1"
    config.http_port = free_port
    # Knows a leader, so that it accepts
    listeners = NodelayListeners.new(config, -> { "127.0.0.1".as(String?) })
    listeners.bind(nil, nil, nil)
    listeners.listen
    TCPSocket.new("127.0.0.1", config.http_port).close
    listeners.nodelay.receive.should be_true
  ensure
    listeners.try &.close
  end

  it "lets connections wait until it serves, without listening before" do
    with_amqp_server do |s|
      config = listener_config
      config.amqps_port = -1
      listeners = LavinMQ::ClientListeners.new(config, -> { nil.as(String?) })
      listeners.bind(nil, nil, nil)
      connected = Channel(AMQP::Client::Connection).new(1)
      spawn { connected.send AMQP::Client.new(host: "127.0.0.1", port: config.amqp_port).connect }
      sleep 50.milliseconds # in the listen backlog, not closed
      listeners.serve(LavinMQ::ClientListeners::Brokers.new(s.amqp_server, s.mqtt_server, s.http_server))
      select
      when conn = connected.receive
        conn.channel.queue("waited").publish_confirm("m").should be_true
        conn.close
      when timeout(5.seconds)
        fail "the waiting connection wasn't served"
      end
    ensure
      listeners.try &.close
    end
  end

  it "closes the connection of a forwarded client that stops reading for tcp_send_timeout" do
    config = listener_config
    config.amqps_port = -1
    config.tcp_send_timeout = 1
    leader = TCPServer.new("127.0.0.1", 0)
    listeners = SpecListeners.new(config, -> { "127.0.0.1".as(String?) },
      {config.amqp_port => leader.local_address.port})
    listeners.bind(nil, nil, nil)
    listeners.listen
    client = TCPSocket.new("127.0.0.1", config.amqp_port)
    upstream = leader.accept
    # The leader keeps sending to a client that never reads, until the
    # follower gives up on the client and closes the connection to the
    # leader too
    closed = Channel(Exception).new(1)
    spawn(name: "leader writing to a stalled client") do
      chunk = Bytes.new(64 * 1024)
      loop { upstream.write chunk }
    rescue ex
      closed.send ex
    end
    select
    when ex = closed.receive
      ex.should be_a(IO::Error)
    when timeout(10.seconds)
      fail "The follower kept the connection of a client that doesn't read"
    end
  ensure
    client.try &.close rescue nil
    upstream.try &.close rescue nil
    listeners.try &.close
    leader.try &.close
  end

  it "lets connections wait while neither serving nor knowing of a leader" do
    with_amqp_server do |s|
      config = listener_config
      config.amqps_port = -1
      leader = TCPServer.new("127.0.0.1", 0)
      leader_host : String? = nil
      listeners = SpecListeners.new(config, -> { leader_host.as(String?) }, {config.amqp_port => leader.local_address.port})
      listeners.bind(nil, nil, nil)
      listeners.listen
      early = TCPSocket.new("127.0.0.1", config.amqp_port)
      early.read_timeout = 100.milliseconds
      expect_raises(IO::TimeoutError) { early.read_byte } # not closed

      leader_host = "127.0.0.1"
      listeners.leader_host_changed
      leader.accept.close # forwarded once there's a leader

      # The leader is gone, e.g. this node won the election and loads its data
      leader_host = nil
      listeners.leader_host_changed
      promoted = TCPSocket.new("127.0.0.1", config.amqp_port)
      promoted.read_timeout = 100.milliseconds
      expect_raises(IO::TimeoutError) { promoted.read_byte }

      listeners.serve(LavinMQ::ClientListeners::Brokers.new(s.amqp_server, s.mqtt_server, s.http_server))
      promoted.read_timeout = 5.seconds
      promoted.write "AMQP\u0000\u0000\u0009\u0001".to_slice
      promoted.read_byte.should eq 1 # a method frame, Connection.Start
    ensure
      early.try &.close
      promoted.try &.close
      listeners.try &.close
      leader.try &.close
    end
  end
end

# A follower forwarding its AMQP port, or its HTTP port with *http*, to the
# leader at *target*, and a client connected to it, on the port's Unix socket
# with *unix*
private def with_forwarding(http = false, unix = false, tcp_proxy_protocol = false,
                            trusted = Array(LavinMQ::IPMatcher).new, & : IO, TCPServer ->) : Nil
  target = TCPServer.new("127.0.0.1", 0)
  config = listener_config
  config.amqps_port = -1
  config.tcp_proxy_protocol = tcp_proxy_protocol
  config.proxy_protocol_trusted_sources = trusted
  path = File.tempname("lavinmq-forward", ".sock")
  if http
    config.amqp_port = -1
    config.http_bind = "127.0.0.1"
    config.http_port = free_port
    config.http_unix_path = path if unix
    port = config.http_port
  else
    config.unix_path = path if unix
    port = config.amqp_port
  end
  listeners = SpecListeners.new(config, -> { "127.0.0.1".as(String?) }, {port => target.local_address.port})
  listeners.bind(nil, nil, nil)
  listeners.listen
  client = unix ? UNIXSocket.new(path) : TCPSocket.new("127.0.0.1", port)
  client.read_timeout = 5.seconds
  yield client, target
ensure
  client.try &.close
  listeners.try &.close
  target.try &.close
  path.try { |p| File.delete?(p) }
end

# What reaches the leader at *target*, up to the first line that isn't a PROXY header
private def leader_lines(target : TCPServer) : Array(String)
  upstream = target.accept
  upstream.read_timeout = 5.seconds
  lines = [] of String
  loop do
    lines << (line = upstream.gets.to_s)
    break unless line.starts_with?("PROXY")
  end
  lines
ensure
  upstream.try &.close
end

# Connects to *port* over TLS, sending *proxy_header* first, and reads Connection.Start
private def amqps_start(port, proxy_header : Bytes) : Nil
  socket = TCPSocket.new("127.0.0.1", port)
  socket.write proxy_header
  tls = OpenSSL::SSL::Socket::Client.new(socket, tls_client, sync_close: true)
  tls.write LavinMQ::AMQP::PROTOCOL_START_0_9_1.to_slice
  tls.flush
  tls.read_timeout = 5.seconds
  frame = Bytes.new(7)
  tls.read_fully(frame)
  frame[0].should eq 1u8 # Connection.Start method frame
ensure
  tls.try &.close rescue nil
  socket.try &.close rescue nil
end

# The status of GET /api/whoami as the default user, sending *proxy_header* first
private def whoami_status(port, proxy_header : String?) : Int32
  socket = TCPSocket.new("127.0.0.1", port)
  socket.read_timeout = 5.seconds
  socket << proxy_header if proxy_header
  socket << "GET /api/whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" \
            "Authorization: Basic #{Base64.strict_encode("guest:guest")}\r\n\r\n"
  socket.flush
  HTTP::Client::Response.from_io(socket, ignore_body: true).status_code
ensure
  socket.try &.close
end

describe LavinMQ::ClientListeners do
  describe "forwarding PROXY headers to the leader" do
    header = "PROXY TCP4 10.1.2.3 127.0.0.1 54321 5672\r\n"
    only_10_0_0_1 = [LavinMQ::IPMatcher.parse("10.0.0.1")]

    it "drops an untrusted one on AMQP and sends its own" do
      with_forwarding(tcp_proxy_protocol: true, trusted: only_10_0_0_1) do |client, target|
        client << header << "data\r\n"
        client.flush
        lines = leader_lines(target)
        lines.size.should eq 2
        lines[0].should match /^PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 \d+ \d+$/
        lines[1].should eq "data"
      end
    end

    it "forwards a trusted load balancer's on AMQP instead of its own" do
      with_forwarding(tcp_proxy_protocol: true) do |client, target|
        client << header << "data\r\n"
        client.flush
        leader_lines(target).should eq [header.chomp, "data"]
      end
    end

    it "forwards a trusted load balancer's on HTTP" do
      with_forwarding(http: true, tcp_proxy_protocol: true) do |client, target|
        client << header << "data\r\n"
        client.flush
        leader_lines(target).should eq [header.chomp, "data"]
      end
    end

    it "drops an untrusted one on HTTP" do
      with_forwarding(http: true, tcp_proxy_protocol: true, trusted: only_10_0_0_1) do |client, target|
        client << header << "data\r\n"
        client.flush
        leader_lines(target).should eq ["data"]
      end
    end

    # tcp_proxy_protocol is set per node, the leader may read them from followers
    it "drops a client's on HTTP with tcp_proxy_protocol disabled" do
      with_forwarding(http: true) do |client, target|
        client << header << "data\r\n"
        client.flush
        leader_lines(target).should eq ["data"]
      end
    end

    it "drops a client's on the HTTP Unix socket" do
      with_forwarding(http: true, unix: true, tcp_proxy_protocol: true) do |client, target|
        client << header << "data\r\n"
        client.flush
        leader_lines(target).should eq ["data"]
      end
    end

    # The leader's AMQP Unix socket reads them too
    it "forwards a client's on the AMQP Unix socket" do
      with_forwarding(unix: true, tcp_proxy_protocol: true) do |client, target|
        client << header << "data\r\n"
        client.flush
        leader_lines(target).should eq [header.chomp, "data"]
      end
    end

    it "closes the connection when another follows a dropped one" do
      with_forwarding(http: true, tcp_proxy_protocol: true, trusted: only_10_0_0_1) do |client, _target|
        client << header << header << "data\r\n"
        client.flush
        client.read(Bytes.new(1)).should eq 0
      end
    end

    it "lets the leader see a trusted load balancer's client in front of TLS" do
      with_amqp_server(extra_tls_listener: true) do |s|
        with_proxy_protocol do
          config = listener_config
          config.tcp_proxy_protocol = true
          listeners = SpecListeners.new(config, -> { "localhost".as(String?) },
            {config.amqps_port => amqp_tls_port(s)})
          listeners.bind(tls_context, nil, nil)
          listeners.listen
          Log.capture("lmq.server", :info) do |logs|
            # PROXY v2 from 10.1.2.3:54321 with an AUTHORITY TLV, as a load balancer passing TLS through sends it
            v2 = IO::Memory.new
            v2.write LavinMQ::ProxyProtocol::V2::Signature.to_slice
            v2.write Bytes[0x21, 0x11, 0x00, 0x13, 10, 1, 2, 3, 127, 0, 0, 1, 0xd4, 0x31, 0x16, 0x27]
            v2.write Bytes[0x02, 0x00, 0x04]
            v2.write "host".to_slice
            amqps_start(config.amqps_port, v2.to_slice)
            logs.check(:info, /^10\.1\.2\.3:54321 connected with /)
          end
        ensure
          listeners.try &.close
        end
      end
    end
  end

  it "hands HTTP to the broker with the client's address from a trusted PROXY header" do
    with_amqp_server do |s|
      with_proxy_protocol do
        config = listener_config
        config.amqp_port = config.amqps_port = -1
        config.http_bind = "127.0.0.1"
        config.http_port = free_port
        listeners = LavinMQ::ClientListeners.new(config, -> { nil.as(String?) })
        listeners.bind(nil, nil, nil)
        listeners.listen
        listeners.serve(LavinMQ::ClientListeners::Brokers.new(s.amqp_server, s.mqtt_server, s.http_server))
        # The default user may only log in from loopback, and an address from
        # a PROXY header never counts as loopback
        whoami_status(config.http_port, "PROXY TCP4 127.0.0.1 127.0.0.1 54321 15672\r\n").should eq 401
        whoami_status(config.http_port, nil).should eq 200
      ensure
        listeners.try &.close
      end
    end
  end
end
