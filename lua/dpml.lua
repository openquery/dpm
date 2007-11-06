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

