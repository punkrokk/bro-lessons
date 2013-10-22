# Sometimes the simple "always email about this notice type" isn't sufficient 
# and something more complex is needed.

@load misc/scan
@load base/utils/site

hook Notice::policy(n: Notice::Info)
	{
	# If the notice is about address scanning and the scanner is a local host
	# *only* then would the email be sent.
	if ( n$note == Scan::Port_Scan &&
	     Site::is_local_addr(n$src) )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}
	}
	
#######################
# Use the above script.
#######################
# You must define your local networks either in networks.cfg with broctl
# or by defining them directly with a Bro script...

redef Site::local_nets += {
	1.2.3.0/24,
	4.3.2.1/29,
};
