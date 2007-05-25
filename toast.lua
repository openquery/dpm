-- Hello-world style initialization script for proxy.

callback = {}

function setup_listener(c)
    -- "c" is a new listening connection object.
    print "Wow! We got a new listener!"
end

-- it's a comment!
print "Hello from lua world!"
listen = myp.listener("127.0.0.1", 5500)
print("Set up new listener!", type(listen), listen:id(), listen:listener())

callback[listen:id()] = {["Client Connect"] = new_client}
