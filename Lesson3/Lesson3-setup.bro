#Bro Script for Lesson 3 Broniversity www.syncurity.net

event http_header (c: connection, is_orig: bool, name: string, value: string)
{

#print out our event and c$http info

print c$http;
print fmt("--------------------------");
print fmt("Is Orig:   %s", is_orig);
print fmt("Name: %s", name);
print fmt("Value: %s", value);
###Visual Separator - we'll get alot of Data here
print fmt("/////////////////////");
}
