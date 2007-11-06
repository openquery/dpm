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

-- DPM_OK (default)      packet was handled, and okay to send packet onward.
-- DPM_NOPROXY           assume packet was handled earlier, don't send
--                       original packet.
-- DPM_FLUSH_DISCONNECT  Flush packet on wire and disconnect clients

clients  = {}
storage  = {}

passdb   = {["whee"] = "09A4298405EF045A61DB26DF8811FEA0E44A80FD"}
BACKEND_USERNAME = "happy"
BACKEND_PASSWORD = "wheefun"

function client_ok(cid)
    print("Client ready! id: " .. cid)
    -- Wipe any crazy callbacks. Act as a passthrough.
    local client = clients[cid]
    client:register(dpm.MYC_WAITING, nil)
    client:register(dpm.MYC_SENT_CMD, new_command)
    client:register(dpm.MY_CLOSING, client_closing)
end

-- Client just got lost. Wipe callbacks, client table.
function client_closing(cid)
    print "Client died"
    clients[cid] = nil
end

function client_got_auth(auth_pkt, cid)
    local hs_pkt = storage[cid]
    if (passdb[auth_pkt:user()] and dpm.check_pass(auth_pkt, hs_pkt, passdb[auth_pkt:user()]) == 0) then
        print "Passwords matched!"
        local ok_pkt = dpm.new_ok_pkt()
        -- FIXME: Prior to this stage "Client waiting" should mean "Client got
        -- auth"
        local client = clients[cid]
        client:register(dpm.MYC_WAITING, client_ok)
        dpm.wire_packet(clients[cid], ok_pkt)
    else
        print "Passwords did NOT match!"
        local err_pkt = dpm.new_err_pkt()
        err_pkt:sqlstate("28000")
        err_pkt:errnum(1045)
        err_pkt:message("Access denied for user '" .. auth_pkt:user() .. "'@'whatever'")
        dpm.wire_packet(clients[cid], err_pkt)
    end

    storage[cid] = nil
end

function new_client(c)
    -- "c" is a new listening connection object.
    print("It's a new client! id: " .. c:id())
    clients[c:id()] = c -- Prevent client from being garbage collected
    c:register(dpm.MYC_WAITING, client_got_auth)

    -- Handshake packets are pre-generated close to how we want it.
    -- An exersize for the reader would be to tailor this a little based on
    -- the handshake packet supplied by the backend server!
    local hs_pkt = dpm.new_handshake_pkt()
    dpm.wire_packet(c, hs_pkt)
    storage[c:id()] = hs_pkt
end

function new_command(cmd_pkt, cid)
    print("Proxying command: " .. cmd_pkt:argument() .. " : " .. cmd_pkt:command())
    if (cmd_pkt:command() == dpm.COM_QUIT) then
        -- allow the client to close, but don't close the server.
        return dpm.DPM_NOPROXY
    end
    dpm.proxy_connect(clients[cid], backend)
    if (cmd_pkt:argument() == "HELLO") then
        cmd_pkt:argument("SELECT 1 + 1")
        -- Packet has been rewritten. Attach the backend and wire it.
        dpm.wire_packet(backend, cmd_pkt)
        -- Finally, return requesting to not proxy original packet.
        return dpm.DPM_NOPROXY
   end
end

function finished_command(cid)
    print "Backend completed handling command."
    return dpm.DPM_FLUSH_DISCONNECT
end

function server_err(err_pkt, cid)
    print("Backend error: " .. err_pkt:message() .. " id: " .. cid)
end

function server_ready(ok_pkt, cid)
    print("Backend ready!")
    backend:register(dpm.MYS_WAIT_CMD, finished_command)
    backend:register(dpm.MYS_RECV_ERR, finished_command)
    backend:register(dpm.MY_CLOSING, new_backend)
end

function server_handshake(hs_pkt, cid)
    print("Got handshake from server, sending auth")

    local auth_pkt = dpm.new_auth_pkt()
    auth_pkt:user(BACKEND_USERNAME)
    dpm.crypt_pass(auth_pkt, hs_pkt, BACKEND_PASSWORD)

    dpm.wire_packet(backend, auth_pkt)
    -- Don't need to store anything, server will return 'ok' or 'err' packet.
    backend:register(dpm.MYS_WAIT_CMD, server_ready)
    backend:register(dpm.MYS_RECV_ERR, server_err)
    backend:register(dpm.MY_CLOSING, new_backend)
end

-- TODO: This should sleep.
function new_backend(cid)
    print "Creating new backend..."
    -- This function is overloaded slightly.
    -- If we were passed a cid, remove it from callbacks table (dead conn)
    if cid ~= 0 then
        print "Backend died! Could not authenticate or connect!"
    end

    -- Then create new connection.
    backend = dpm.connect("127.0.0.1", 3306)
    backend:register(dpm.MYS_WAIT_AUTH, server_handshake)
end

-- Set up the listener, register a callback for new clients.
listen = dpm.listener("127.0.0.1", 5500)
listen:register(dpm.MYC_CONNECT, new_client)

-- Fire off the backend. NOTE that this won't retry or event print decent
-- errors if it fails :)
new_backend(0)
