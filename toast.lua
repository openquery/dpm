-- Hello-world style initialization script for proxy.

-- Name -> value defines for lua
dofile ("defines.lua")

callback = {}

function new_client(c)
    -- "c" is a new listening connection object.
    print("Holy crap it's a new client!", type(c), c:id(), c:listener(), c:my_type())
    if (c:my_type() == MY_SERVER) then
        print("Holy crap it's a server!\n")
    elseif (c:my_type() == MY_CLIENT) then
        print("Holy crap it's a client!\n")
    end
end

listen = myp.listener("127.0.0.1", 5500)
print("listener data: ", listen:id(), listen:listener())
callback[listen:id()] = {["Client connect"] = new_client}

hs_pkt = myp.new_handshake_pkt()
print("Built a new handshake packet!", type(hs_pkt), hs_pkt:protocol_version(), hs_pkt:server_version())
