#Bro script for jp@syncurity.net bro lesson 2
#hello-print-part-record.bro


event connection_established(c:connection)
{
print fmt("Hello Bro");
print c;
print fmt ("---------------------------");
print fmt ("Bro Layer 3 connection info:");
print fmt ("uid: %s", c$uid);
print fmt ("c$id$orig_h: %s", c$id$orig_h);
print fmt ("c$id$orig_p: %s", c$id$orig_p);
print fmt ("c$id$resp: %s", c$id$resp_h);
print fmt ("c$id$resp_p: %s", c$id$resp_p);
print fmt("---------------------------");
print fmt("---------------------------");
}


