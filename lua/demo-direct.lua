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

-- Demo of 1:1 connection mapping.
-- Each connecting client gets a dedicated backend connection.
-- Authentication is handled by the server instead of the proxy.

-- Name -> value defines for lua
MY_SERVER = 0
MY_CLIENT = 1

MYP_OK = 0 -- "OK" means it was handled, and okay to send packet onward.
MYP_NOPROXY = 1 -- assume packet was handled earlier, don't copy.
MYP_FLUSH_DISCONNECT = 2 -- Flush packet on wire and disconnect clients

callback = {}
clients  = {}
backends = {}

-- Client just got lost. Wipe callbacks, client table.
function client_closing(cid)
    clients[cid] = nil
    callback[cid] = nil
    backends[cid] = nil
end

function new_client(c)
    -- "c" is a new listening connection object.
    clients[c:id()] = c -- Prevent client from being garbage collected
    callback[c:id()] = {["Client sent command"] = new_command,
                        ["Closing"]             = client_closing,}

    -- Init a backend just for this connection.
    local backend = new_backend(0)
    backends[c:id()] = backend

    -- Connect the backend to the client (and never disconnect later).
    myp.proxy_connect(c, backend)
    -- This is a special case:
    -- When a client connects we don't send it a packet. Wait for the backend
    -- to proxy one along.
    return MYP_NOPROXY
end

function new_command(cmd_pkt, cid)
    print("Proxying command: " .. cmd_pkt:argument() .. " : " .. cmd_pkt:command())

    -- If user sends 'HELLO', rewrite it. Can do a few fun things here!
    if (cmd_pkt:argument() == "HELLO") then
        print "Rewriting packet to SELECT 1 + 1"
        cmd_pkt:argument("SELECT 1 + 1")
        -- Packet has been rewritten. Attach the backend and wire it.
        myp.wire_packet(backends[cid], cmd_pkt)
        -- Finally, return requesting to not proxy original packet.
        return MYP_NOPROXY
   end
end

function server_err(err_pkt, cid)
    print("Backend error!", type(err_pkt), err_pkt:message(), cid)
end

function backend_death(cid)
    print "Backend died"
end

function new_backend(cid)
    -- Create new connection.
    local backend = myp.connect("127.0.0.1", 3306)
    callback[backend:id()] = {["Closing"] = backend_death}
    return backend
end

-- Set up the listener, register a callback for new clients.
listen = myp.listener("127.0.0.1", 5500)
callback[listen:id()] = {["Client connect"] = new_client}
