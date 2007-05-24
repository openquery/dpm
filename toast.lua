-- Hello-world style initialization script for proxy.

callback = {}

function setup_listener(c)
    -- "c" is a new listening connection object.
    print "Wow! We got a new listener!"
end

-- it's a comment!
print "Hello from lua world!"
myp.listener("127.0.0.1", 5500, setup_listener)
print "Set up new listener!"

function say_hello (c)
    print "Got hello callback! Whee!"
end

callback[2] = {["Server waiting auth"] = say_hello}
