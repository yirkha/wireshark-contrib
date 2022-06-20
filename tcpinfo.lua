--[[------------------------------------------------------------------------------------------------

    tcpinfo.lua

    Wireshark script for analyzing and summarizing TCP connections reliability


    This program has been created for analyzing customer-reported issues from the "netsh trace"
    packet captures processed by the etl2pcapng tool, with focus on connections to M365 services
    from the MS Teams apps. Its usefulness for other tasks in other environments is not guaranteed.


    Usage:
       extrac32 NetTrace.cab report.etl processes.txt
       etl2pcapng report.etl report.pcapng
       tshark -r report.pcapng -q -X lua_script:tcpinfo.lua >tcpinfo.txt


    Output row format:   [ 95] 10.11.11.112:54892 | 07:33:48 12732-13721 ( 31.9 s,  20 s idle)
                           |               |           |          |          |         |
        tcp.stream --------'               |           |          |          |         |
        Local/client address and port -----'           |          |          |         |
        Time of the first packet seen -----------------'          |          |         |
        Number of the first/last packet in the capture -----------'          |         |
        Time between the first and the last packet seen ---------------------'         |
        Time between the last packet with TCP data and the last packet overall --------'

    Traffic statistics:                21 out,   733 B (mss  187) |  44 in, 41009 B (mss 1362)
                                        |          |          |       |       |           |
                        Packets sent ---'          |          |       |       |           |
                          Bytes sent --------------'          |       |       |           |
            Largest TCP segment sent -------------------------'       |       |           |
          (beware of TCP offloading)                                  |       |           |
                    Packets received ---------------------------------'       |           |
                      Bytes received -----------------------------------------'           |
        Largest TCP segment received -----------------------------------------------------'
          (beware of TCP offloading)

    TCP/TLS connection progress observations:                          S/A cH/sH cD/sD c:-R/FR
                                                                       | |  |  |  |  | | || ||
                                                      SYN seen --------' |  |  |  |  | | || ||
                                                  SYN+ACK seen ----------'  |  |  |  | | || ||
                                         TLS Client Hello seen -------------'  |  |  | | || ||
                                         TLS Server Hello seen ----------------'  |  | | || ||
                           TLS Application Data by client seen -------------------'  | | || ||
                           TLS Application Data by server seen ----------------------' | || ||
         FIN/RST was sent first by (c)lient/(s)erver/noone yet ------------------------' || ||
                                            FIN by client seen --------------------------'| ||
                                            RST by client seen ---------------------------' ||
                                            FIN by server seen -----------------------------'|
                                            RST by server seen ------------------------------'

    Wireshark's TCP analysis observations:             31 seg.lost,  42 retrans.,  69 dup-acks
                                                             |            |             |
                       "Previous segment(s) not captured" ---'            |             |
             "This frame is a (suspected) retransmission" ----------------'             |
                                          "Duplicate ACK" ------------------------------'

    ICMP:    10.11.1.5 said Destination unreachable (Fragmentation needed: got 1500, can 1496)


    Beware that the attribution of connections to processes can be wrong and misleading.
    See the comment at the end of tap.packet() for more details.

    Also the "connection progress observations" can be wrong because Wireshark does not handle
    reassembling of TCP stream very well at the moment (June 2022; yes, even with the option
    tcp.reassemble_out_of_order:TRUE). Some "cH/sH" and "cD/sD" might be errorneously missing.

    There is no real IPv6 support for now. But the tool does at least not crash on it and
    lets you know it is in use in your capture, so that you can implement support. Good luck.


    Note: All of this code became GPL licensed as soon as it got released/published/distributed:
        https://wiki.wireshark.org/Lua#beware-the-gpl
    That said, if you do your own internal modifications, you do not need to bother much:
        https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html#GPLRequireSourcePostedPublic

----------------------------------------------------------------------------------------------------

    Copyright (C) 2022  Jiri Hruska <jirka@fud.cz>

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

------------------------------------------------------------------------------------------------]]--

do
    -- Predefine all used fields. These can be later dereferenced to value(s) from
    -- the current packet when called from within the tap.packet() callback.
    local f_dns                          = Field.new("dns")
    local f_dns_resp_type                = Field.new("dns.resp.type")
    local f_dns_resp_name                = Field.new("dns.resp.name")
    local f_dns_cname                    = Field.new("dns.cname")
    local f_dns_a                        = Field.new("dns.a")
    local f_dns_aaaa                     = Field.new("dns.aaaa")
    local f_frame_comment                = Field.new("frame.comment")
    local f_frame_packet_flags_direction = Field.new("frame.packet_flags_direction")
    local f_http_request_method          = Field.new("http.request.method")
    local f_http_request_uri             = Field.new("http.request.uri")
    local f_icmp                         = Field.new("icmp")
    local f_icmp_code                    = Field.new("icmp.code")
    local f_icmp_mtu                     = Field.new("icmp.mtu")
    local f_icmp_type                    = Field.new("icmp.type")
    local f_ip_dst                       = Field.new("ip.dst")
    local f_ip_len                       = Field.new("ip.len")
    local f_ip_src                       = Field.new("ip.src")
    local f_ipv6_dst                     = Field.new("ipv6.dst")
    local f_ipv6_plen                    = Field.new("ipv6.plen")
    local f_ipv6_src                     = Field.new("ipv6.src")
    local f_tcp                          = Field.new("tcp")
    local f_tcp_analysis_duplicate_ack   = Field.new("tcp.analysis.duplicate_ack")
    local f_tcp_analysis_lost_segment    = Field.new("tcp.analysis.lost_segment")
    local f_tcp_analysis_retransmission  = Field.new("tcp.analysis.retransmission")
    local f_tcp_flags                    = Field.new("tcp.flags")
    local f_tcp_len                      = Field.new("tcp.len")
    local f_tcp_stream                   = Field.new("tcp.stream")
    local f_tls_handshake_type           = Field.new("tls.handshake.type")
    local f_tls_record_content_type      = Field.new("tls.record.content_type")
    local f_tls_record_opaque_type       = Field.new("tls.record.opaque_type")


    -- A few utilities to hide awkward syntax or other ugliness behind reasonable names

    local function get_all_field_values(f)
        return { f() }
    end

    local function get_field_value(f)
        local all = get_all_field_values(f)
        if #all ~= 1 then
            error(string.format("Exactly 1 value of field %s was expected", f.name))
        end
        return all[1].value
    end

    local function get_field_numeric_ipv4(f)
        -- Must be parsed from the raw packet (TVB) because Wireshark otherwise returns
        -- everything as an Address object, which inherently does reverse name resolution.
        local b = (getmetatable(f).__typeof == "Field") and ({ f() })[1].range:bytes() or f.range:bytes()
        return string.format("%d.%d.%d.%d", b:get_index(0), b:get_index(1), b:get_index(2), b:get_index(3))
    end

    local function get_field_numeric_ipv6(f)
        -- Ditto
        local b = (getmetatable(f).__typeof == "Field") and ({ f() })[1].range:bytes() or f.range:bytes()
        local a = string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            b:get_index( 0), b:get_index( 1), b:get_index( 2), b:get_index( 3),
            b:get_index( 4), b:get_index( 5), b:get_index( 6), b:get_index( 7),
            b:get_index( 8), b:get_index( 9), b:get_index(10), b:get_index(11),
            b:get_index(12), b:get_index(13), b:get_index(14), b:get_index(15))
        a = "!" .. a
        a = string.gsub(a, "([!:])00?0?", "%1")
        a = string.gsub(a, "[!:]0:[0:]+", "::", 1)  -- Not the longest run per the RFC, but should do the job
        a = string.gsub(a, "^!", "")
        return a
    end

    local function is_field_present(f)
        return (#get_all_field_values(f) > 0)
    end

    local function is_lan_address(addr)
        -- Note there is no "or" in Lua's simplistic regex syntax
        return string.find(addr, "^10%.") or
               string.find(addr, "^172%.1[6789]%.") or string.find(addr, "^172%.2[0-9]%.") or string.find(addr, "^172%.3[01]%.") or
               string.find(addr, "^192%.168%.") or
               string.find(addr, "^169%.254%.")
    end

    local function bool_to_int(b)
        return (b and 1 or 0)
    end

    -- Useful for default-initializing tables of tables of numbers and similar structures
    local function deep_set_if_not_exists(root, ...)
        local args = {...}
        local arg = 1
        while true do
            local k = args[arg + 0]
            local v = args[arg + 1]
            arg = arg + 2

            if k == nil then
                break
            end

            if not root[k] then
                root[k] = v
            end
            root = root[k]
        end
    end

    local function sorted_keys(what)
        output = {}
        for k, v in pairs(what) do
            table.insert(output, k)
        end
        table.sort(output)
        return ipairs(output)
    end


    local dns_map = {}  -- Map of seen DNS resolutions, value=set of CNAMEs that got resolved to
                        -- the particular key (another CNAME or a leaf address) at some time

    local function find_all_dns_aliases(addr)
        local output = {}
        local recurse
        recurse = function(addr)
            for alias, _ in pairs(dns_map[addr] or {}) do
                if not output[alias] then
                    output[alias] = true
                    recurse(alias)
                end
            end
        end
        recurse(addr)
        return output
    end


    -- A few global statistics about the input file
    local input_first_ts = nil
    local input_last_ts  = nil

    local streams = {}  -- Info about seen TCP streams, key=Wireshark stream ID (tcp.stream)

    local icmp = {}     -- Seen ICMP messages about TCP streams, key=source-destination tuple


    -- Load process.txt from the `netsh trace` package and prepare mapping of PIDs to process name
    local function load_process_info(filename)
        local output = {}
        local line_no = 0
        local col1_pos, col2_pos, last_pid
        for line in io.lines(filename) do
            line_no = line_no + 1
            if line_no == 3 then  -- The line between header and data, showing column widths with '='
                col1_pos = string.find(line, " ")
                col2_pos = string.find(line, " ", col1_pos + 1)
            elseif line_no > 3 then
                local image    = string.gsub(string.sub(line, 1, col1_pos - 1), " +$", "")
                local pid      = tonumber(string.sub(line, col1_pos + 1, col2_pos - 1))
                local services = string.gsub(string.sub(line, col2_pos + 1), " +$", "")
                if image == "" and pid == nil then
                    -- Continuation of the previous line, append to the last item
                    output[last_pid] = string.sub(output[last_pid], 0, -2) .. services .. ")"
                else
                    output[pid] = (services ~= "N/A") and string.format("%s (%s)", image, services) or image
                    last_pid = pid
                end
            end
        end
        return output
    end
    local process_info_loaded, process_info = pcall(load_process_info, "processes.txt")
    if not process_info_loaded then
        io.stderr:write(string.format("Process information could not be loaded, only numeric PIDs will be shown:\n    %s\n", process_info))
    end


    local tap = Listener.new(nil, "dns or tcp")

    -- Called sequentially for each packet
    function tap.packet(pinfo, tvb, frame)
        if input_first_ts == nil then
            input_first_ts = pinfo.abs_ts
        end
        input_last_ts = pinfo.abs_ts

        -- DNS
        if is_field_present(f_dns) then
            local dns_resp_types = get_all_field_values(f_dns_resp_type)
            local dns_resp_names = get_all_field_values(f_dns_resp_name)
            local dns_cnames     = get_all_field_values(f_dns_cname)
            local dns_as         = get_all_field_values(f_dns_a)
            local dns_aaaas      = get_all_field_values(f_dns_aaaa)
            local cname_idx      = 1
            local a_idx          = 1
            local aaaa_idx       = 1
            -- io.stderr:write(string.format("%6d  %d types, %d names, %d CNAMEs, %d As, %d AAAAs\n",
            --     pinfo.number, #dns_resp_types, #dns_resp_names, #dns_cnames, #dns_as, #dns_aaaas))
            for i, resp_type in ipairs(dns_resp_types) do
                if resp_type.value == 0x01 then  -- A
                    local name = dns_resp_names[i].value
                    local target = get_field_numeric_ipv4(dns_as[a_idx])
                    a_idx = a_idx + 1
                    deep_set_if_not_exists(dns_map, target, {}, name, true)
                    -- io.stderr:write(string.format("        A      %s -> %s\n", name, target))
                elseif resp_type.value == 0x05 then  -- CNAME
                    local name = dns_resp_names[i].value
                    local target = dns_cnames[cname_idx].value
                    cname_idx = cname_idx + 1
                    deep_set_if_not_exists(dns_map, target, {}, name, true)
                    -- io.stderr:write(string.format("        CNAME  %s -> %s\n", name, target))
                elseif resp_type.value == 0x1C then  -- AAAA
                    local name = dns_resp_names[i].value
                    local target = get_field_numeric_ipv6(dns_aaaas[aaaa_idx])
                    aaaa_idx = aaaa_idx + 1
                    deep_set_if_not_exists(dns_map, target, {}, name, true)
                    -- io.stderr:write(string.format("        AAAA   %s -> %s\n", name, target))
                end
            end
        end

        -- TCP
        if is_field_present(f_tcp) then

            if is_field_present(f_icmp) then
                -- This is a TCP header reported inside an ICMP packet only, to be handled differently
                local icmp_type = get_field_value(f_icmp_type)
                if icmp_type == 0x03 then
                    icmp_type = "Destination unreachable"
                end
                local icmp_code = get_field_value(f_icmp_code)
                if icmp_code == 0x04 then
                    local ip_len = get_all_field_values(f_ip_len)[2].value
                    local icmp_mtu = get_field_value(f_icmp_mtu)
                    icmp_code = string.format("Fragmentation needed: got %d, can %d", ip_len, icmp_mtu)
                end
                local msg = string.format("%s said %s (%s)", tostring(pinfo.src), icmp_type, icmp_code)

                -- There is no tcp.stream available, store using a src-dst key and cross-match later
                local src_addr = get_field_numeric_ipv4(get_all_field_values(f_ip_src)[2])
                local dst_addr = get_field_numeric_ipv4(get_all_field_values(f_ip_dst)[2])
                local src_port = tonumber(pinfo.src_port)
                local dst_port = tonumber(pinfo.dst_port)
                local key = string.format("%s:%d-%s:%d", src_addr, src_port, dst_addr, dst_port)

                deep_set_if_not_exists(icmp, key, {}, msg, 0)
                icmp[key][msg] = icmp[key][msg] + 1
                return
            end

            local ipv6 = is_field_present(f_ipv6_plen)
            local tcp_stream = get_field_value(f_tcp_stream)
            local s = streams[tcp_stream]
            if not s then
                -- First time seeing this TCP stream, create its record
                s = {
                    id                        = tcp_stream,
                    first_packet              = pinfo.number,
                    last_packet               = -1,
                    first_timestamp           = pinfo.abs_ts,
                    last_data_timestamp       = pinfo.abs_ts,
                    last_timestamp            = -1,
                    seen_syn                  = 0,
                    seen_syn_ack              = 0,
                    client_num_packets        = 0,
                    client_addr               = ipv6 and get_field_numeric_ipv6(f_ipv6_src) or get_field_numeric_ipv4(f_ip_src),
                    client_host               = tostring(pinfo.src),
                    client_port               = tonumber(pinfo.src_port),
                    client_observed_mss       = 0,
                    client_sent_bytes         = 0,
                    client_sent_fin           = 0,
                    client_sent_rst           = 0,
                    server_num_packets        = 0,
                    server_addr               = ipv6 and get_field_numeric_ipv6(f_ipv6_dst) or get_field_numeric_ipv4(f_ip_dst),
                    server_host               = tostring(pinfo.dst),
                    server_port               = tonumber(pinfo.dst_port),
                    server_observed_mss       = 0,
                    server_sent_bytes         = 0,
                    server_sent_fin           = 0,
                    server_sent_rst           = 0,
                    first_closed_by           = " ",
                    num_lost_segments         = 0,
                    num_duplicate_acks        = 0,
                    num_retransmissions       = 0,
                    seen_tls_client_hello     = 0,
                    seen_tls_server_hello     = 0,
                    seen_tls_client_appdata   = 0,
                    seen_tls_server_appdata   = 0,
                    pids                      = {},
                    proxy_target              = nil
                }

                -- Handle cases where we got to see the server-to-client packet first
                -- by normalizing (swapping) the source and destination fields
                local pfd_success, pfd_value = pcall(get_field_value, f_frame_packet_flags_direction)
                if pfd_success and pfd_value == 0x1 then  -- Direction: Inbound
                    local addr, host, port = s.client_addr, s.client_host, s.client_port
                    s.client_addr, s.client_host, s.client_port = s.server_addr, s.server_host, s.server_port
                    s.server_addr, s.server_host, s.server_port = addr, host, port
                end

                -- Decide if the stream is interesting (HTTP/S or proxy client-to-server traffic)
                s.interesting = is_lan_address(s.client_addr) and
                    (s.server_port == 80 or s.server_port == 443 or s.server_port == 8080)
                if not s.interesting then
                    io.stderr:write(string.format("Ignoring uninteresting stream %d: %s:%d -> %s:%d\n",
                        s.id, s.client_host, s.client_port, s.server_host, s.server_port))
                end

                streams[tcp_stream] = s
            end

            if not s.interesting then
                -- No need to bother further with uninteresting streams
                return
            end

            local tcp_len = get_field_value(f_tcp_len)
            local tcp_flags = get_field_value(f_tcp_flags)
            local tcp_fin = (bit.band(tcp_flags, 0x01) ~= 0)
            local tcp_syn = (bit.band(tcp_flags, 0x02) ~= 0)
            local tcp_rst = (bit.band(tcp_flags, 0x04) ~= 0)
            local tcp_ack = (bit.band(tcp_flags, 0x10) ~= 0)
            if tcp_syn and tcp_ack then
                s.seen_syn_ack = s.seen_syn_ack + 1
            elseif tcp_syn then
                s.seen_syn = s.seen_syn + 1
            end

            local c2s = (tostring(pinfo.src) == s.client_host)
            if c2s then
                s.client_num_packets = s.client_num_packets + 1
                s.client_sent_bytes = s.client_sent_bytes + tcp_len
                s.client_observed_mss = math.max(s.client_observed_mss, tcp_len)
                s.client_sent_fin = s.client_sent_fin + bool_to_int(tcp_fin)
                s.client_sent_rst = s.client_sent_rst + bool_to_int(tcp_rst)
                if (tcp_fin or tcp_rst) and s.first_closed_by == " " then
                    s.first_closed_by = "c"
                end
            else
                s.server_num_packets = s.server_num_packets + 1
                s.server_sent_bytes = s.server_sent_bytes + tcp_len
                s.server_observed_mss = math.max(s.server_observed_mss, tcp_len)
                s.server_sent_fin = s.server_sent_fin + bool_to_int(tcp_fin)
                s.server_sent_rst = s.server_sent_rst + bool_to_int(tcp_rst)
                if (tcp_fin or tcp_rst) and s.first_closed_by == " " then
                    s.first_closed_by = "s"
                end
            end

            s.num_lost_segments   = s.num_lost_segments   + bool_to_int(is_field_present(f_tcp_analysis_lost_segment))
            s.num_retransmissions = s.num_retransmissions + bool_to_int(is_field_present(f_tcp_analysis_retransmission))
            s.num_duplicate_acks  = s.num_duplicate_acks  + bool_to_int(is_field_present(f_tcp_analysis_duplicate_ack))

            s.last_packet = pinfo.number
            s.last_timestamp = pinfo.abs_ts
            if tcp_len > 0 then
                s.last_data_timestamp = pinfo.abs_ts
            end

            for _, ht in ipairs(get_all_field_values(f_tls_handshake_type)) do
                s.seen_tls_client_hello = s.seen_tls_client_hello + bool_to_int(ht.value == 0x01)  -- Client Hello
                s.seen_tls_server_hello = s.seen_tls_server_hello + bool_to_int(ht.value == 0x02)  -- Server Hello
            end
            for _, rct in ipairs(get_all_field_values(f_tls_record_content_type)) do
                local inc = bool_to_int(rct.value == 0x17)  -- Application Data
                if c2s then
                    s.seen_tls_client_appdata = s.seen_tls_client_appdata + inc
                else
                    s.seen_tls_server_appdata = s.seen_tls_server_appdata + inc
                end
            end
            for _, rot in ipairs(get_all_field_values(f_tls_record_opaque_type)) do
                local inc = bool_to_int(rot.value == 0x17)  -- TLS 1.3 pseudo Application Data
                if c2s then
                    s.seen_tls_client_appdata = s.seen_tls_client_appdata + inc
                else
                    s.seen_tls_server_appdata = s.seen_tls_server_appdata + inc
                end
            end

            -- The process ID for the relevant ETW events is often wrong, packet being handled in the kernel while
            -- the "active process" is something irrelevant, or similar. Hence statistical methods need to be used
            -- to hopefully end up showing the right one. Usually the PID with the highest occurrence is correct.
            -- Making the initial SYN packet and any other packet with data 3 times as important seems to help too.
            local fc_success, fc_value = pcall(get_field_value, f_frame_comment)
            if fc_success then
                local pid = tonumber(string.match(fc_value, "^PID=([0-9]+)"))
                deep_set_if_not_exists(s.pids, pid, 0)
                s.pids[pid] = s.pids[pid] + ((tcp_syn or tcp_len > 0) and 3 or 1)
            end

            -- Look for proxy CONNECT requests and note the real target address if present
            if is_field_present(f_http_request_method) and get_field_value(f_http_request_method) == "CONNECT" then
                s.proxy_target = get_field_value(f_http_request_uri)
            end
        end
    end

    -- Called once at the end of the capture file
    function tap.draw()
        io.stdout:write(string.format("Captured time period: %s-%s UTC\n\n",
            os.date("!%Y-%m-%d %H:%M:%S", input_first_ts), os.date("!%H:%M:%S", input_last_ts)))

        -- Reorganize streams into a three-level tree: process (PID) -> target (host:port) -> TCP stream (ID)
        local processes = {}
        for _, s in pairs(streams) do
            if s.interesting then
                local best_pid = 0
                local best_pid_count = 0
                for pid, freq in pairs(s.pids) do
                    if freq > best_pid_count and pid ~= 0 then  -- Always discard 0 (System Idle Process)
                        best_pid = pid
                        best_pid_count = freq
                    end
                end

                local target_key = string.format("%s:%d/%s", s.server_addr, s.server_port, s.proxy_target or "")
                deep_set_if_not_exists(processes, best_pid, {}, target_key, {}, s.id, s)
            end
        end

        -- For each process, sorted by PID...
        for _, pid in sorted_keys(processes) do
            -- Print the process header, hopefully with its image name
            io.stdout:write(string.format("Process %d - %s\n", pid, process_info[pid] or "???"))
            local targets = processes[pid]

            -- For each target, sorted by its (unresolved) address...
            for _, target in sorted_keys(targets) do

                -- Gather all the DNS names observed for the target IP address
                -- (split into two groups because some domain names are less useful than others)
                local _, example_s = next(targets[target])
                local all_aliases = find_all_dns_aliases(example_s.server_addr)
                local normal_aliases = {}
                local lowprio_aliases = {}
                for alias, _ in pairs(all_aliases) do
                    if string.find(alias, "%.trafficmanager%.net$") or string.find(alias, "%.[a-z]%-msedge%.net$") or
                       string.find(alias, "%.edgekey%.net$") or string.find(alias, "%.akadns%.net$") or
                       string.find(alias, "%.ms%-acdc%.office%.com$") then
                        lowprio_aliases[alias] = true
                    else
                        normal_aliases[alias] = true
                    end
                end
                aliases = ""
                for _, alias in sorted_keys(normal_aliases) do
                    aliases = aliases .. " " .. alias
                end
                if next(lowprio_aliases) ~= nil then
                    if aliases ~= "" then
                        aliases = aliases .. "  / "
                    end
                    for _, alias in sorted_keys(lowprio_aliases) do
                        aliases = aliases .. " " .. alias
                    end
                end

                -- Print the target header, i.e. address:port, proxy target if present, and the DNS aliases
                local target_addr_port = string.format("%s:%d", example_s.server_addr, example_s.server_port)
                io.stdout:write(string.format("  %s%s%s%s%s%s\n",
                    target_addr_port,
                    (example_s.proxy_target or aliases ~= "") and string.rep(" ", 24 - string.len(target_addr_port)) or "",
                    example_s.proxy_target and "  <=  " or "", example_s.proxy_target or "",
                    (aliases ~= "") and "  <= " or "", aliases))

                -- For each TCP stream (sorted by stream ID = time)...
                for _, sid in sorted_keys(targets[target]) do
                    local s = streams[sid]

                    -- Format and print all the collected info
                    local row = string.format("    [%3d] %s:%s | ", s.id, s.client_addr, s.client_port)
                    local idle_time = s.last_timestamp - s.last_data_timestamp
                    row = row .. string.format("%s %5d-%5d (%5.1f s%s | ", os.date("!%H:%M:%S", s.first_timestamp),
                        s.first_packet, s.last_packet, s.last_timestamp - s.first_timestamp,
                        (idle_time >= 1.0) and string.format(", %3.0f s idle)", idle_time - 0.5) or ")            ")
                    row = row .. string.format("%4u out, %7u B (mss %5u) | %4u in, %7u B (mss %5u) | ",
                        s.client_num_packets, s.client_sent_bytes, s.client_observed_mss,
                        s.server_num_packets, s.server_sent_bytes, s.server_observed_mss)
                    row = row .. string.format("%s/%s %s/%s %s/%s %s%s%s%s/%s%s",
                        (s.seen_syn                > 0) and "S"  or "-",
                        (s.seen_syn_ack            > 0) and "A"  or "-",
                        (s.seen_tls_client_hello   > 0) and "cH" or "--",
                        (s.seen_tls_server_hello   > 0) and "sH" or "--",
                        (s.seen_tls_client_appdata > 0) and "cD" or "--",
                        (s.seen_tls_server_appdata > 0) and "sD" or "--",
                        s.first_closed_by,
                        (s.first_closed_by      == " ") and " " or ":",
                        (s.client_sent_fin         > 0) and "F" or "-",
                        (s.client_sent_rst         > 0) and "R" or "-",
                        (s.server_sent_fin         > 0) and "F" or "-",
                        (s.server_sent_rst         > 0) and "R" or "-")
                    local extras_prefix = " | "
                    if s.num_lost_segments > 0 then
                        row = row .. string.format("%s%3u seg.lost", extras_prefix, s.num_lost_segments)
                        extras_prefix = ", "
                    end
                    if s.num_retransmissions > 0 then
                        row = row .. string.format("%s%3u retrans.", extras_prefix, s.num_retransmissions)
                        extras_prefix = ", "
                    end
                    if s.num_duplicate_acks > 0 then
                        row = row .. string.format("%s%3u dup-acks", extras_prefix, s.num_duplicate_acks)
                        extras_prefix = ", "
                    end
                    io.stdout:write(row .. "\n")

                    -- List also any ICMP failures seen for this connection
                    local icmp_key = string.format("%s:%d-%s:%d", s.client_addr, s.client_port, s.server_addr, s.server_port)
                    for msg, count in pairs(icmp[icmp_key] or {}) do
                        io.stdout:write(string.format("          ICMP: %s%s\n", msg, (count > 1) and string.format(" %d times", count) or ""))
                    end
                end
            end

            io.stdout:write("\n")
        end
    end
end
