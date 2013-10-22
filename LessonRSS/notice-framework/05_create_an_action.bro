## The script that can enact blocks.  It needs to accept a single 
## argument that is the ip address.
const block_script = "echo Blocking is not enabled without setting 'block_script'.  Attempted %s" &redef;

redef enum Notice::Action += {
	ACTION_BLOCK_SRC
};

hook Notice::notice(n: Notice::Info)
	{
	if ( ! n?$src )
		{
		local host = n$src;
		when ( local result = Exec::run([$cmd=fmt(block_script, host)]) )
			{
			# You might want to check the result data structure here
			# to make sure that your blocking command worked correctly.
			# http://bro.org/sphinx-git/scripts/base/utils/exec.html?type-Exec::Result
			print fmt("Blocked %s", host);
			}
		}
	}

#######################
# Use the above script.
#######################
@load misc/scan
redef block_script = "/path/to/blocking.sh %s";

hook Notice::policy(n: Notice::Info)
	{
	# Define some condition, for example...
	# Maybe we want to block scanners doing address scans.
	if ( n$note == Scan::Address_Scan )
		add n$actions[ACTION_BLOCK_SRC];
	}