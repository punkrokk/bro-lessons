# If you write a script to detect something of your own then 
# you will need to create a new notice type and generate your notice.

# Let's say that you are interested in people downloading MalwareBytes...

# Create the notice type which will be used later.
redef enum Notice::Type += {
	Malware_Bytes_Download
};

# Handle an event that has the data you need to make a determination.
event HTTP::log_http(rec: HTTP::Info)
	{
	# Look for the url to look like a MalwareBytes download and
	# for the server to respond with a Windows executable.
	if ( /mbam-setup-.*\.exe/ in rec$uri &&
	     rec?$resp_mime_types && "application/x-dosexec" in rec$resp_mime_types[0] )
		{
		# Yay!  Do the notice!
		NOTICE([$note=Malware_Bytes_Download,
		        $msg=fmt("%s downloaded the MalwareBytes scanner.", rec$id$orig_h),
		        $uid=rec$uid,
		        $id=rec$id,
		        $fuid=rec$resp_fuids[0],
		        $identifier=cat(rec$id$orig_h)]);
		}
	}
	

#######################
# Use the above script.
#######################
# Run: bro -r mbam_download.trace
# Then look at the notice.log and the http.log.