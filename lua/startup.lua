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

-- MYP_OK (default)      packet was handled, and okay to send packet onward.
-- MYP_NOPROXY           assume packet was handled earlier, don't send
--                       original packet.
-- MYP_FLUSH_DISCONNECT  Flush packet on wire and disconnect clients

callback = {}
clients  = {}
storage  = {}

passdb   = {["whee"] = "09A4298405EF045A61DB26DF8811FEA0E44A80FD"}
BACKEND_USERNAME = "happy"
BACKEND_PASSWORD = "wheefun"

function client_ok(cid)
    print("Client ready! id: " .. cid)
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
    local hs_pkt = storage[cid]
    if (passdb[auth_pkt:user()] and myp.check_pass(auth_pkt, hs_pkt, passdb[auth_pkt:user()]) == 0) then
        print "Passwords matched!"
        local ok_pkt = myp.new_ok_pkt()
        -- FIXME: Prior to this stage "Client waiting" should mean "Client got
        -- auth"
        callback[cid] = {["Client waiting"] = client_ok}
        myp.wire_packet(clients[cid], ok_pkt)
        -- myp.proxy_connect(clients[cid], backend)
    else
        print "Passwords did NOT match!"
        local err_pkt = myp.new_err_pkt()
        callback[cid] = nil
        myp.wire_packet(clients[cid], err_pkt)
        clients[cid] = nil
    end

    storage[cid] = nil
end

function new_client(c)
    -- "c" is a new listening connection object.
    print("It's a new client! id: " .. c:id())
    clients[c:id()] = c -- Prevent client from being garbage collected
    callback[c:id()] = {["Client waiting"] = client_got_auth}

    local hs_pkt = myp.new_handshake_pkt()
    myp.wire_packet(c, hs_pkt)
    storage[c:id()] = hs_pkt
end

function new_command(cmd_pkt, cid)
    print("Proxying command: " .. cmd_pkt:argument() .. " : " .. cmd_pkt:command())
    if (cmd_pkt:command() == 1) then
        -- allow the client to close, but don't close the server.
        return myp.MYP_NOPROXY
    end
    myp.proxy_connect(clients[cid], backend)
    if (cmd_pkt:argument() == "HELLO") then
        cmd_pkt:argument("SELECT 1 + 1")
        -- Packet has been rewritten. Attach the backend and wire it.
        myp.wire_packet(backend, cmd_pkt)
        -- Finally, return requesting to not proxy original packet.
        return myp.MYP_NOPROXY
   end
end

function finished_command(cid)
    print "Backend completed handling command."
    return myp.MYP_FLUSH_DISCONNECT
end

function server_err(err_pkt, cid)
    print("Backend error: " .. err_pkt:message() .. " id: " .. cid)
end

function server_ready(ok_pkt, cid)
    print("Backend ready!")
    callback[cid] = {["Server waiting command"] = finished_command,
                     ["Server got error"] = finished_command,
                     ["Closing"] = new_backend}
end

function server_handshake(hs_pkt, cid)
    print("Got handshake from server, sending auth")

    local auth_pkt = myp.new_auth_pkt()
    auth_pkt:user(BACKEND_USERNAME)
    myp.crypt_pass(auth_pkt, hs_pkt, BACKEND_PASSWORD)

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
    if cid ~= 0 then
        print "Backend died! Could not authenticate or connect!"
        callback[cid] = nil
    end

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
