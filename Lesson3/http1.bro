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
    print c;
    if(name == "HOST") {
        if(!c?$conn)
            Conn::set_conn(c, F);
        c$conn$resp_hostname = value;
    }
}

event ssl_established(c: connection)
{
    print c;
    if(c?$ssl && c$ssl?$server_name) {
        if(!c?$conn)
            Conn::set_conn(c, F);
        c$conn$resp_hostname = c$ssl$server_name;
    }
}





