#Copyright (c) 2012-2013, Liam Randall. All rights reserved.
#modified by JP Bourget for Broniversity Lessons (2013) w/License Permission

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site

module Conn;

redef record Conn::Info += {
    resp_hostname: string &optional &log;
};

event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name == "HOST") {
        if(!c?$conn)
            Conn::set_conn(c, F);
        c$conn$resp_hostname = value;
    }
}

event ssl_established(c: connection)
{
    if(c?$ssl && c$ssl?$server_name) {
        if(!c?$conn)
            Conn::set_conn(c, F);
        c$conn$resp_hostname = c$ssl$server_name;
    }
}

event bro_init()
{
    Log::add_filter(Conn::LOG, [$name = "conn-hostnames",
                                $path = "conn_hostnames",
                                $pred(rec: Conn::Info) = {
        return (rec?$resp_hostname);
    }]);
}



