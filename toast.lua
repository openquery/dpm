-- Hello-world style initialization script for proxy.

-- Name -> value defines for lua
dofile ("defines.lua")

callback = {}
clients  = {}

function client_got_auth(c, auth_pkt)
    print "Got auth callback"
end

function new_client(c)
    -- "c" is a new listening connection object.
    print("Holy crap it's a new client!", type(c), c:id(), c:listener(), c:my_type())
    clients[c:id()] = c -- Prevent client from being garbage collected
    callback[c:id()] = {["Client waiting auth"] = client_got_auth}

    hs_pkt = myp.new_handshake_pkt()
    print("Built a new handshake packet!", type(hs_pkt), hs_pkt:protocol_version(), hs_pkt:server_version())
end

listen = myp.listener("127.0.0.1", 5500)
print("listener data: ", listen:id(), listen:listener())
callback[listen:id()] = {["Client connect"] = new_client}
-- listen2 = myp.listener("127.0.0.1", 5501)
-- print("listener2 data: ", listen2:id(), listen2:listener())
-- callback[listen2:id()] = {["Client connect"] = new_client}

