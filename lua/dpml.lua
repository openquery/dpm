--  Copyright 2008 Dormando (dormando@rydia.net).  All rights reserved.
--
--  Use and distribution licensed under the BSD license.  See
--  the LICENSE file for full text.
--
--  This file is the lua-level standard library for using DPM.

local dpm   = dpm
-- What's the bigger package for all this?
local table = table
local pairs = pairs
local print = print
local unpack = unpack
local type = type
local io = io
local error = error
module(...)

-- "local function blah" private
-- "function blah" public

-- Temporary storage for library functions.
local conns = {}

-- Tiny helper routine for mass-setting callbacks.
function register_callbacks(cb, t)
    for k, v in pairs(t) do
        cb:register(k, v)
    end
end

-- Sends a resultset to the target connection's buffer.
-- Does not cache objects, etc.
function send_resultset(c, t)
    local fields = t["fields"]
    local rows   = t["rows"]
    local rset   = dpm.new_rset_pkt()

    rset:field_count(table.maxn(fields))

    dpm.wire_packet(c, rset)
    for k, v in pairs(fields) do
        local field = dpm.new_field_pkt()
        field:name(v["name"], v["type"])
        rset:add_field(field)
        dpm.wire_packet(c, field)
    end

    local eof = dpm.new_eof_pkt()
    dpm.wire_packet(c, eof)

    local row = dpm.new_row_pkt()
    for k, v in pairs(rows) do
        rset:pack_row(row, unpack(v))
        dpm.wire_packet(c, row)
    end

    dpm.wire_packet(c, eof)
end

function send_error(c, state, errnum, message)
    local err_pkt = dpm.new_err_pkt()
    err_pkt:sqlstate(state)
    err_pkt:errnum(errnum)
    err_pkt:message(message)
    dpm.wire_packet(c, err_pkt)
end

--
-- Routines for buffering resultsets
--

local function br_read_rset(rset, cid)
    local br = conns[cid]
    br["br_rset"] = rset
    return dpm.DPM_NOPROXY
end

local function br_read_fields(field, cid)
    local rset = conns[cid]["br_rset"]
    rset:add_field(field)
    local fname, ftype = field:name()
    table.insert(conns[cid]["br_res"]["fields"], { type = ftype, name = fname })
    return dpm.DPM_NOPROXY
end

local function br_read_rows(row, cid)
    local br = conns[cid]
    local rset = conns[cid]["br_rset"]
    table.insert(br["br_res"]["rows"], rset:parse_row_array(row))
    return dpm.DPM_NOPROXY
end

local function br_read_finish(eof, cid)
    local br     = conns[cid]
    local server = conns[cid]["conn"]
    server:package_register(nil)
    conns[cid] = nil
    br.br_cb(cid, br["br_q"], br["br_res"], nil)
    return dpm.DPM_NOPROXY
end

local function br_read_error(err, cid)
    local br = conns[cid]
    conns[cid] = nil
    br.br_cb(cid, br["br_q"], nil, err)
    return dpm.DPM_NOPROXY
end

local br_callbacks = dpm.new_callback()
register_callbacks(br_callbacks, {
                   [dpm.MYS_SENT_RSET]      = br_read_rset,
                   [dpm.MYS_SENDING_FIELDS] = br_read_fields,
                   [dpm.MYS_SENDING_ROWS]   = br_read_rows,
                   [dpm.MYS_WAIT_CMD]       = br_read_finish,
                   [dpm.MYS_RECV_ERR]       = br_read_error,
                   })

-- Buffer a resultset then return it to callback function.
-- FIXME: This will "leak" memory in the `conns` structure if the server
-- is closed before resultset buffering is completed.
function execute_query_buffered(server, query, callback)
    -- Do the right thing if we're passed a string.
    local p = type(query)
    if p == "string" then
        local q = dpm.new_cmd_pkt()
        q:command(3)
        q:argument(query)
        query = q
    elseif p ~= "userdata" then
        error("DPML: Query must be string or cmd packet")
    end
    conns[server:id()] = { br_cb = callback, br_q = query, conn = server,
                           br_res = { fields = {}, rows = {} }
                         }
    server:package_register(br_callbacks)

    -- 'query' should be a pre-populated command. Wire it along.
    dpm.wire_packet(server, query)
end

--
-- Routines for server authentication.
--

-- If the server unexpected closes before authentication is finished, we
-- handle it with the library. Otherwise the caller will handle.
local function cms_server_closed(cid)
    local dsn = conns[cid]["dsn"]
    conns[cid] = nil

    return dsn.callback(nil, "DPML: Connection closed unexpectedly")
end

-- Success! Clear the local values, unregister callbacks, and inform the
-- caller.
local function cms_server_ready(ok, cid)
    local server = conns[cid]["conn"]
    local dsn    = conns[cid]["dsn"]
    server:package_register(nil)

    server:register(dpm.MY_CLOSING, nil)
    conns[cid] = nil

    return dsn.callback(server, nil)
end

-- Propagate MySQL errors up to the caller.
local function cms_server_err(err, cid)
    local dsn = conns[cid]["dsn"]
    conns[cid] = nil

    return dsn.callback(nil, err:message())
end

-- Received a handshake packet.
-- From what information was given, set a default db, password, crypto, etc,
-- and send the authentication packet to the server.
local function cms_server_handshake(hs, cid)
    local auth = dpm.new_auth_pkt()
    local dsn  = conns[cid]["dsn"]

    auth:user(dsn["user"])

    if dsn["db"] then
        auth:databasename(dsn["db"])
    end

    if dsn["pass"] then
        dpm.crypt_pass(auth, hs, dsn["pass"])
    end

    dpm.wire_packet(conns[cid]["conn"], auth)
end

local connect_mysql_server_callbacks = dpm.new_callback()
register_callbacks(connect_mysql_server_callbacks, {
                   [dpm.MYS_WAIT_AUTH] = cms_server_handshake,
                   [dpm.MYS_WAIT_CMD]  = cms_server_ready,
                   [dpm.MYS_RECV_ERR]  = cms_server_err,
                   })

-- Helper which will attempt to authenticate against a mysql server.
-- Returns an authenticated backend connection object, or nil and an error if
-- it failed.
-- Takes: host, port, user, pass, db, callback
function connect_mysql_server(t)
    local server
    if t["path"] then
        server = dpm.connect_unix(t["path"])
    else
        server = dpm.connect(t["host"], t["port"] and t["port"] or 3306)
    end
    if server == nil then
        return t.callback(nil, "DPML: Could not establish connection")
    end
    server:register(dpm.MY_CLOSING, cms_server_closed)
    server:package_register(connect_mysql_server_callbacks)

    conns[server:id()] = { conn = server, dsn = t }
end

---
--- Utility functions
---

-- Stupid data dumper.
function dump_table(t, i)
    -- FIXME: I know there's a better way to do a stupid for.
    local n = 0
    if i == nil then i = 0 else n = i end
    for k, v in pairs(t) do
        for n=i,0,-1 do
            io.write("\t")
        end
        local p = type(v)
        if (p == "table") then
            io.write(p .. " " .. k .. "\n")
            dump_table(v, i + 1)
        else
            io.write(p .. " " .. k .. ": " .. v .. "\n")
        end
    end
end
