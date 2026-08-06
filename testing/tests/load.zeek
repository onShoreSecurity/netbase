# @TEST-DOC: Netbase loads cleanly under a stock Zeek and runs zeek_init without errors.
# @TEST-EXEC: zeek %INPUT >output 2>&1
# @TEST-EXEC: grep -q "netbase loaded ok" output

@load netbase

event zeek_init()
    {
    print "netbase loaded ok";
    }
