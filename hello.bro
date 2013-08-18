#hello.bro script for jp@syncurity.net bro lesson 1


event connection_established(c:connection)
{
print fmt("Hello Bro");
}

#Save this to hello.bro and run:
sudo bro -i en0 hello.bro #in linux replace en0 with your nic - e.g. eth0

#after you see a few Hello Bro's print out - hit Ctl-C to stop bro.
