--  Copyright 2008 Dormando (dormando@rydia.net).  All rights reserved.
--
--  Use and distribution licensed under the BSD license.  See
--  the LICENSE file for full text.

-- Hello-world style initialization script for proxy.
-- See bottom of file for connection, listening information.

-- DPM_OK (default)      packet was handled, and okay to send packet onward.
-- DPM_NOPROXY           assume packet was handled earlier, don't send
--                       original packet.
-- DPM_FLUSH_DISCONNECT  Flush packet on wire and disconnect clients

require "dpml"

clients  = {}
storage  = {}
bench    = {}
-- Count of queries ran through system.
queries  = {["count"] = 0}

passdb   = {["whee"] = "09A4298405EF045A61DB26DF8811FEA0E44A80FD"}
BACKEND_USERNAME = "happy"
BACKEND_PASSWORD = "wheefun"

function client_ok(cid)
    local client = clients[cid]
    local addr = client:socket_address()
    print("Client ready! id: " .. cid)
    if addr then print("Client IP: " .. addr) end
    -- Wipe any crazy callbacks. Act as a passthrough.
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

function new_client(c, lid)
    -- "c" is a new listening connection object.
    print("It's a new client! id: " .. c:id() .. " from listener id: " .. lid)
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
    -- Start the timer.
    bench["millis"] = dpm.time_hires()
    -- Up the counter
    queries["count"] = queries["count"] + 1

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
    -- Figure out how long it took.
    local milli_lapsed = dpm.time_hires() - bench["millis"]
    print("Backend completed command in " .. milli_lapsed .. "ms")
    return dpm.DPM_FLUSH_DISCONNECT
end

function new_backend(cid)
    print "Creating new backend..."
    -- This function is overloaded slightly.
    -- If we were passed a cid, remove it from callbacks table (dead conn)
    if cid ~= 0 then
        print "Backend died! Could not authenticate or connect!"
    end

    dpml.connect_mysql_server({ host = "127.0.0.1", 
                          user = BACKEND_USERNAME, pass = BACKEND_PASSWORD,
                          callback = server_ready
                          })
end

function server_ready(server, err)
    print "Backend ready!"
    if err then
        print("Error creating backend: " .. err)
        os.exit()
    end
    backend = server

    dpml.register_callbacks(backend, { [dpm.MYS_WAIT_CMD] = finished_command,
                            [dpm.MYS_RECV_ERR] = finished_command,
                            [dpm.MY_CLOSING]   = new_backend,
                           })
end

-- 'self' is the timer argument. To stop the timer you can run self:cancel()
function print_status(self, arg)
    print("STATUS UPDATE: I have ran " .. arg["count"] .. " queries.")
end

-- Set up the listener, register a callback for new clients.
-- You may specify "dpm.INADDR_ANY" instead of "127.0.0.1" to listen on all
-- addresses.
listen = dpm.listener("127.0.0.1", 5500)
listen:register(dpm.MYC_CONNECT, new_client)
-- Uncomment these lines to also listen on a unix domain socket.
-- listen2 = dpm.listener_unix("/tmp/dpmsock", "0770")
-- listen2:register(dpm.MYC_CONNECT, new_client)

-- Example of the timer interface. Every few seconds, print a count.
timer = dpm.new_timer()
timer:schedule(45, 0, print_status, queries)

-- Fire off the backend. NOTE that this won't retry or event print decent
-- errors if it fails :)
new_backend(0)
