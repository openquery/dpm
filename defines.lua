-- global defines

MY_SERVER = 0
MY_CLIENT = 1

MYP_OK = 0      -- "OK" means it was handled, and okay to send packet onward.
MYP_NOPROXY = 1 -- assume packet was handled earlier, don't copy.
MYP_FLUSH_DISCONNECT = 2 -- Flush packet on wire and disconnect clients
