# Refer here: http://bro.org/sphinx-git/bro-noticeindex.html
# This variable and a few others like it are just thin wrappers around
# the normal mechanism for applying a notice policy.  In the event where you
# just want to quickly define notices that are emailed to you though, it's 
# very convenient.

@load misc/scan

redef Notice::emailed_types += {
	Scan::Address_Scan,
	Scan::Port_Scan,
};