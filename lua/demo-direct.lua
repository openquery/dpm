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

conns    = {}

-- Client just got lost. Wipe callbacks, client table.
function client_closing(cid)
    print "Client died"
    local client = conns[cid]
    conns[cid] = nil
    -- Disconnect the backend conn from mysql.
    local backend = conns[client:remote_id()]
    if backend then
        if myp.close(backend) then
            print "Successfully closed dead client's backend"
        end
    end
end

function new_client(c)
    print("New client connecting: " .. c:id())
    -- "c" is a new listening connection object.
    conns[c:id()] = c -- Prevent client from being garbage collected
    c:register(myp.MYC_SENT_CMD, new_command);
    c:register(myp.MY_CLOSING, client_closing);

    -- Init a backend just for this connection.
    local backend = new_backend(0)
    conns[backend:id()] = backend

    -- Connect the backend to the client (and never disconnect later).
    myp.proxy_connect(c, backend)
    -- This is a special case:
    -- When a client connects we don't send it a packet. Wait for the backend
    -- to proxy one along.
    return myp.MYP_NOPROXY
end

function new_command(cmd_pkt, cid)
    print("Proxying command: " .. cmd_pkt:argument() .. " : " .. cmd_pkt:command())
    local client = conns[cid]

    -- If user sends 'HELLO', rewrite it. Can do a few fun things here!
    if (cmd_pkt:argument() == "HELLO") then
        print "Rewriting packet to SELECT 1 + 1"
        cmd_pkt:argument("SELECT 1 + 1")
        -- Packet has been rewritten. Attach the backend and wire it.
        myp.wire_packet(conns[client:remote_id()], cmd_pkt)
        -- Finally, return requesting to not proxy original packet.
        return myp.MYP_NOPROXY
   end
end

function server_err(err_pkt, cid)
    print("Backend error!", type(err_pkt), err_pkt:message(), cid)
end

function backend_death(cid)
    print "Backend died"
    local backend = conns[cid]
    conns[cid] = nil
    local client = conns[backend:remote_id()]
    if client then
        if myp.close(client) then
            print "Successfully closed backend's client"
        end
    end
end

function new_backend(cid)
    -- Create new connection.
    local backend = myp.connect("127.0.0.1", 3306)
    backend:register(myp.MY_CLOSING, backend_death)
    return backend
end

-- Set up the listener, register a callback for new clients.
listen = myp.listener("127.0.0.1", 5500)
listen:register(myp.MYC_CONNECT, new_client)
