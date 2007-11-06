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

conns    = {}
rsets    = {}
callback = dpm.new_callback()
squirrel = 0

-- Client just got lost. Wipe callbacks, client table.
function client_closing(cid)
    print "Client connection died."
    conns[cid] = nil
end

function new_client(c)
    -- "c" is a new listening connection object.
    conns[c:id()] = c -- Prevent client from being garbage collected
    c:register(dpm.MYC_SENT_CMD, new_command);
    c:register(dpm.MY_CLOSING, client_closing);

    -- Init a backend just for this connection.
    local backend = new_backend(0)
    conns[backend:id()] = backend

    -- Connect the backend to the client (and never disconnect later).
    dpm.proxy_connect(c, backend)
    -- This is a special case:
    -- When a client connects we don't send it a packet. Wait for the backend
    -- to proxy one along.
    return dpm.DPM_NOPROXY
end

function new_command(cmd_pkt, cid)
    local arg = cmd_pkt:argument();
    print("Proxying command: " .. arg .. " : " .. cmd_pkt:command())

    if string.upper(string.sub(arg, 1, 7)) == "SELECT " then
        local client = conns[cid]
        local fake_cmd = dpm.new_cmd_pkt()
        local backend = conns[client:remote_id()]

        -- We have a query to analyze... Swap in the callback object we
        -- prepped earlier, prepend EXPLAIN to the string, and run the
        -- command.
        backend:package_register(callback)
        fake_cmd:argument("EXPLAIN " .. arg);
        dpm.wire_packet(backend, fake_cmd)
        squirrel = cmd_pkt
        return dpm.DPM_NOPROXY
    end
end

function server_err(err_pkt, cid)
    print("Backend error!", type(err_pkt), err_pkt:message(), cid)
end

function backend_death(cid)
    print "Backend died"
end

function b_rset(rset_pkt, cid)
    rsets[cid] = rset_pkt
    return dpm.DPM_NOPROXY
end

function b_fields(field_pkt, cid)
    local rset = rsets[cid]
    rset:add_field(field_pkt)
    return dpm.DPM_NOPROXY
end

function b_rows(row_pkt, cid)
    local rset = rsets[cid]
    local rowdata = rset:parse_row_table(row_pkt)
    io.write("EXPLAIN:\n")
    for k, v in pairs(rowdata) do
      io.write(string.format(" %s: %s\n", k, v))
    end
    return dpm.DPM_NOPROXY
end

function b_endfields(eof_pkt, cid)
   return dpm.DPM_NOPROXY
end

function b_finish(eof_pkt, cid)
    local backend = conns[cid]

    -- Finished with the command, swap out the "autoexplain" callback object
    -- so the actual query results go through nice and fast, as well as
    -- simplifying the autoexplain logic.
    backend:package_register(nil)
    dpm.wire_packet(backend, squirrel)
    return dpm.DPM_NOPROXY
end

function new_backend(cid)
    -- Create new connection.
    local backend = dpm.connect("127.0.0.1", 3306)
    backend:register(dpm.MY_CLOSING, backend_death);
    return backend
end

-- Set up the listener, register a callback for new clients.
listen = dpm.listener("127.0.0.1", 5500)
listen:register(dpm.MYC_CONNECT, new_client)

-- Prep the generic "callback" object for this "package" demo.
-- When we want to analyze a query we swap this object in to define the
-- callbacks.
callback:register(dpm.MY_CLOSING, backend_death);
callback:register(dpm.MYS_SENT_RSET, b_rset);
callback:register(dpm.MYS_SENDING_FIELDS, b_fields);
callback:register(dpm.MYS_SENDING_ROWS, b_rows);
callback:register(dpm.MYS_SENT_FIELDS, b_endfields);
callback:register(dpm.MYS_WAIT_CMD, b_finish);

