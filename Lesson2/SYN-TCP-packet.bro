#Bro Script SYN-TCP-packet.bro - for lesson 2 by jp@syncurity.net

#generate some traffic - what do you see?

event connection_established(c:connection)
{
print fmt("Hello Bro");
print c;
print fmt("---------------------------");
print c$id;
print fmt("c$uid: %s", c$uid);
print fmt("c$id$orig_h: %s", c$id$orig_h);
print fmt ("c$id$orig_p: %s", c$id$orig_p);
print fmt ("c$id$resp: %s", c$id$resp_h);
print fmt ("c$id$resp_p: %s", c$id$resp_p);
print fmt("---------------------------");
print fmt("---------------------------");
}

event connection_SYN_packet(c:connection, pkt:SYN_packet)
{
print fmt("******************");
print pkt;
print fmt("******************");
}
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
print fmt("^^^^^^^^^^^^^^^");
# print fmt("Connection: %s", c);
print fmt("is_orig: %s", is_orig);
print fmt("flags: %s", flags);
print fmt("sequence count: %d", seq);
print fmt("ack: %d", ack);
print fmt("len: %d", len);
print fmt("^^^^^^^^^^^^^^^");
print fmt("payload: %s", payload);
print fmt("^^^^^^^^^^^^^^^");
}
