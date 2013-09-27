#declare table
export 
	{
	global a: table[count] of string;
#initialize table
	global t: table[count] of string = 
		{
		[1] = "subnet1",
		[2] = "subnet2",
		[5] = "subnet5",
		[25] = "subnet25",
		};
	}

event bro_init()
	{
	

	for ( x in t )
    	{
   	 	print x;
    	}
	}
