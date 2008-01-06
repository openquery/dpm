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
 --
 --  This file is the lua-level standard library for using DPM.

local dpm   = dpm
-- What's the bigger package for all this?
local table = table
local pairs = pairs
local print = print
local unpack = unpack
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
    local server = dpm.connect(t["host"], t["port"] and t["port"] or 3306)
    if server == nil then
        return t.callback(nil, "DPML: Could not establish connection")
    end
    server:register(dpm.MY_CLOSING, cms_server_closed)
    server:package_register(connect_mysql_server_callbacks)

    conns[server:id()] = { conn = server, dsn = t }
end

