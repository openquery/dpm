-- it's a comment!
print "Hello from lua world!"
myp.listener("127.0.0.1", 5500)
print "Set up new listener!"

function say_hello (c)
    print "Got hello callback! Whee!"
end

callback = {}
callback[1] = {}
callback[2] = {["Server waiting auth"] = say_hello}
