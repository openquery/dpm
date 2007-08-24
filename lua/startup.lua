 -- Copyright 2007 Dormando (dormando@rydia.net)
 --     This file is part of dpm.
 --
 --  dpm is free software; you can redistribute it and/or modify
 --  it under the terms of the GNU General Public License as published by
 --  the Free Software Foundation; either version 2 of the License, or
 --  (at your option) any later version.
 --
 --  dpm is distributed in the hope that it will be useful,
 --  but WITHOUT ANY WARRANTY; without even the implied warranty of
 --  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 --  GNU General Public License for more details.
 --
 --  You should have received a copy of the GNU General Public License
 --  along with Foobar; if not, write to the Free Software
 --  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

-- Hello-world style initialization script for proxy.
-- See bottom of file for connection, listening information.

-- Name -> value defines for lua
MY_SERVER = 0
MY_CLIENT = 1

MYP_OK = 0 -- "OK" means it was handled, and okay to send packet onward.
MYP_NOPROXY = 1 -- assume packet was handled earlier, don't copy.
MYP_FLUSH_DISCONNECT = 2 -- Flush packet on wire and disconnect clients

callback = {}
clients  = {}
storage  = {}

passdb   = {["whee"] = "09A4298405EF045A61DB26DF8811FEA0E44A80FD"}

function client_ok(cid)
    print("Client ready!", cid)
    -- Wipe any crazy callbacks. Act as a passthrough.
    callback[cid] = {["Client waiting"] = nil, 
                     ["Client sent command"] = new_command,
                     ["Closing"] = client_closing,}
end

-- Client just got lost. Wipe callbacks, client table.
function client_closing(cid)
    clients[cid] = nil
    callback[cid] = nil
end

function client_got_auth(auth_pkt, cid)
    print("Got auth callback", type(auth_pkt), type(cid))
    local hs_pkt = storage[cid]
    if (passdb[auth_pkt:user()] and myp.check_pass(auth_pkt, hs_pkt, passdb[auth_pkt:user()]) == 0) then
        print "OMFG passwords matched!"
        local ok_pkt = myp.new_ok_pkt()
        -- FIXME: Prior to this stage "Client waiting" should mean "Client got
        -- auth"
        callback[cid] = {["Client waiting"] = client_ok}
        myp.wire_packet(clients[cid], ok_pkt)
        -- myp.proxy_connect(clients[cid], backend)
    else
        print "OMFG passwords did NOT match!!!"
        local err_pkt = myp.new_err_pkt()
        callback[cid] = nil
        myp.wire_packet(clients[cid], err_pkt)
        clients[cid] = nil
    end

    storage[cid] = nil
end

function new_client(c)
    -- "c" is a new listening connection object.
    print("Holy crap it's a new client!", type(c), c:id(), c:listener(), c:my_type())
    clients[c:id()] = c -- Prevent client from being garbage collected
    callback[c:id()] = {["Client waiting"] = client_got_auth}

    local hs_pkt = myp.new_handshake_pkt()
    myp.wire_packet(c, hs_pkt)
    storage[c:id()] = hs_pkt
end

function new_command(cmd_pkt, cid)
    -- FIXME: cmd_pkt's argument value isn't copied into lua correctly.
    print("reconnecting client to a backend: " .. cmd_pkt:argument() .. " : " .. cmd_pkt:command())
    -- Lets set this value on every command, even though it's persistent! :)
    myp.proxy_until(clients[cid], 6) -- myc_sent_cmd
    if (cmd_pkt:command() == 1) then
        -- allow the client to close, but don't close the server.
        return MYP_NOPROXY
    end
    myp.proxy_connect(clients[cid], backend)
    if (cmd_pkt:argument() == "HELLO") then
        cmd_pkt:argument("SELECT 1 + 1")
        -- Packet has been rewritten. Attach the backend and wire it.
        myp.wire_packet(backend, cmd_pkt)
        -- Finally, return requesting to not proxy original packet.
        return MYP_NOPROXY
   end
end

function finished_command(cid)
    print "Backend completed handling command."
    return MYP_FLUSH_DISCONNECT
    -- myp.proxy_disconnect(backend)
end

function server_err(err_pkt, cid)
    print("Backend error!", type(err_pkt), err_pkt:message(), cid)
end

function server_ready(ok_pkt, cid)
    print("Backend ready!", type(ok_pkt), ok_pkt:warning_count(), cid)
    myp.proxy_until(backend, 11);
    callback[cid] = {["Server waiting command"] = finished_command,
                     ["Server got error"] = finished_command,
                     ["Closing"] = new_backend}
end

function server_handshake(hs_pkt, cid)
    print("Got callback for server handshake packet", hs_pkt:server_version())

    local auth_pkt = myp.new_auth_pkt()
    -- myp.crypt_pass(auth_pkt, hs_pkt, "toast")

    myp.wire_packet(backend, auth_pkt)
    -- Don't need to store anything, server will return 'ok' or 'err' packet.
    callback[backend:id()] = {["Server waiting command"] = server_ready,
                              ["Server got error"] = server_err,
                              ["Closing"] = new_backend}
end

function new_backend(cid)
    print "Creating new backend..."
    -- This function is overloaded slightly.
    -- If we were passed a cid, remove it from callbacks table (dead conn)
    callback[cid] = nil

    -- Then create new connection.
    backend = myp.connect("127.0.0.1", 3306)
    callback[backend:id()] = {["Server waiting auth"] = server_handshake}
end

-- Set up the listener, register a callback for new clients.
listen = myp.listener("127.0.0.1", 5500)
callback[listen:id()] = {["Client connect"] = new_client}

-- Fire off the backend. NOTE that this won't retry or event print decent
-- errors if it fails :)
new_backend(0)
