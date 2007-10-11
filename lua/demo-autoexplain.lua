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

-- Demo of 1:1 connection mapping with autoexplain on SELECT's
-- Each connecting client gets a dedicated backend connection.
-- Authentication is handled by the server instead of the proxy.

callback = {}
clients  = {}
backends = {}
cmap     = {}
rsets    = {}
squirrel = 0

-- Client just got lost. Wipe callbacks, client table.
function client_closing(cid)
    print "Client connection died."
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
    cmap[backend:id()] = c:id()
    -- Connect the backend to the client (and never disconnect later).
    myp.proxy_connect(c, backend)
    -- This is a special case:
    -- When a client connects we don't send it a packet. Wait for the backend
    -- to proxy one along.
    return myp.MYP_NOPROXY
end

function new_command(cmd_pkt, cid)
    local arg = cmd_pkt:argument();
    print("Proxying command: " .. arg .. " : " .. cmd_pkt:command())

    if string.upper(string.sub(arg, 1, 7)) == "SELECT " then
        local fake_cmd = myp.new_cmd_pkt()
        fake_cmd:argument("EXPLAIN " .. arg);
        myp.wire_packet(backends[cid], fake_cmd)
        squirrel = cmd_pkt
        return myp.MYP_NOPROXY
    end
end

function server_err(err_pkt, cid)
    print("Backend error!", type(err_pkt), err_pkt:message(), cid)
end

function backend_death(cid)
    print "Backend died"
end

function b_rset(rset_pkt, cid)
    if squirrel ~= 0 then
        rsets[cid] = rset_pkt
        return myp.MYP_NOPROXY
    end
end

function b_fields(field_pkt, cid)
    if squirrel ~= 0 then
        local rset = rsets[cid]
        rset:add_field(field_pkt)
        return myp.MYP_NOPROXY
    end
end

function b_rows(row_pkt, cid)
    if squirrel ~= 0 then
        local rset = rsets[cid]
        local rowdata = rset:parse_row_table(row_pkt)
        io.write("EXPLAIN:\n")
        for k, v in pairs(rowdata) do
          io.write(string.format(" %s: %s\n", k, v))
        end
        return myp.MYP_NOPROXY
    end
end

function b_endfields(eof_pkt, cid)
   if squirrel ~= 0 then
       return myp.MYP_NOPROXY
   end
end

function b_finish(eof_pkt, cid)
    if squirrel ~= 0 then
        myp.wire_packet(backends[cmap[cid]], squirrel)
        squirrel = 0
        return myp.MYP_NOPROXY
    end
end

function new_backend(cid)
    -- Create new connection.
    local backend = myp.connect("127.0.0.1", 3306)
    callback[backend:id()] = {["Closing"] = backend_death,
                              ["Server sent resultset"] = b_rset,
                              ["Server sending fields"] = b_fields,
                              ["Server sending rows"] = b_rows,
                              ["Server sent fields"]  = b_endfields,
                              ["Server waiting command"] = b_finish,
                             }
    return backend
end

-- Set up the listener, register a callback for new clients.
listen = myp.listener("127.0.0.1", 5500)
callback[listen:id()] = {["Client connect"] = new_client}
