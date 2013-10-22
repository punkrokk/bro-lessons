#bro script
#hello-print-conn.bro script for jp@syncurity.net bro lesson 1




event connection_established(c:connection)
{
print fmt("Hello Bro");
#print c;
print c$id$orig_p;
print fmt("---------------------------");
}

