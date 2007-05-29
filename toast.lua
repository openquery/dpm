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
print("Set up new listener!", type(listen), listen:id(), listen:listener())

callback[listen:id()] = {["Client connect"] = new_client}
