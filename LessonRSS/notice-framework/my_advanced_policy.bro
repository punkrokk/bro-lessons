const watched_servers: set[addr] = {
172.16.238.136,
172.16.238.168,
} &redef;

redef Notice::policy += {
	[$action = Notice::ACTION_ALARM,
	 $pred(n: Notice::Info) =
		{
		return n$note == SSH::Login && n$id$resp_h in watched_servers;
		}
	]
};


