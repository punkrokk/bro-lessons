# Sometimes you will have hosts that trigger false positives in various
# scripts that generate notices.  If you want to send email or take harsher
# restrictions against those addresses you will likely want to *not* do
# the action against the host or hosts triggering the false positive.

@load base/frameworks/notice
@load policy/protocols/ssh/detect-bruteforcing

const ssh_hosts_bruteforce_false_positives: set[subnet] = set() &redef;

hook Notice::policy(n: Notice::Info)
	{
	# If the notice is for password guessing and the host doing
	# the scanning is not listed in the set of hosts that cause
	# SSH bruteforcing false positives then we want to send an email.
	if ( n$note == SSH::Password_Guessing &&
	     n$src !in ssh_hosts_bruteforce_false_positives )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}
	}
	
#######################
# Use the above script.
#######################
redef ssh_hosts_bruteforce_false_positives += {
	1.2.3.4/32
};