#portions of this script from Seth Hall's github 
#Copyright (c) 2010, Seth Hall <hall.692@osu.edu> and The Ohio State 
#University. All rights reserved.

#See License file in directory

#modified by JP Bourget for Broniversity Lessons (2013) w/License Permission

#we load scripts in addition to base here - so if we run this with "Bro -r it will load"
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site

module Conn;


event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    print fmt("/////////////////////");
    print c$http;
    print fmt("Name:    %s", name);
    print fmt("Value:   %s", value);
    if ( c$http$method == "POST") {
        print fmt("POST!!!!!!!!");
        }
  

    #print c$id$resp_h;
    print fmt("---------------------------");
       # if(!c?$conn)
        #    Conn::set_conn(c, F);
       # c$conn$resp_hostname = value;
}

event ssl_established(c: connection)
{
    print c;
    print fmt("SSL-Bitches: %s", c$ssl);
    if(c?$ssl && c$ssl?$server_name) {
        #print c$conn$resp_h;
        #print fmt("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
        print fmt("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
       # if(!c?$conn)
      #      Conn::set_conn(c, F);
       # c$conn$resp_hostname = c$ssl$server_name;
    }
}


event http_header (c: connection, is_orig: bool, name: string, value: string)
{

#print out our event and c$http info

print c$http;
print fmt("--------------------------");
print fmt("Is Orig:   %s", is_orig);
print fmt("Name: %s", name);
print fmt("Value: %s", value);

if ( name == "HOST") {
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




