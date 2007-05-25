-- Hello-world style initialization script for proxy.

callback = {}

function new_client(c)
    -- "c" is a new listening connection object.
    print("Holy crap it's a new client!", type(c), c:id(), c:listener())
end

listen = myp.listener("127.0.0.1", 5500)
print("Set up new listener!", type(listen), listen:id(), listen:listener())

callback[listen:id()] = {["Client connect"] = new_client}
