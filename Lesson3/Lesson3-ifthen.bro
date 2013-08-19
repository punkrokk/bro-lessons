#Bro IDS Scripts for Broversity Lessons from www.syncurity.net (c) jp@syncurity.net

event http_header (c: connection, is_orig: bool, name: string, value: string)
{

#print out our event and c$http info

print c$http;
print fmt("--------------------------");
print fmt("Is Orig:   %s", is_orig);
print fmt("Name: %s", name);
print fmt("Value: %s", value);

if ( name  == "HOST") {
        print fmt("********");
        print fmt("HOST!!!!!!!!");
        print fmt("********");
    }
else
    {
    print fmt("NOT HOST :(");
    }

###Visual Separator - we'll get alot of Data here
print fmt("/////////////////////");
}
