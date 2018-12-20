-- Acorn Universal Networking protocol dissector for WireShark
-- (c) Eelco Huininga 2018

aun_proto = Proto("aun","Acorn Universal Networking")

aun_types = {
	[0x01] = "Broadcast",
	[0x02] = "Unicast",
	[0x03] = "Acknowledge",
	[0x04] = "Negative acknowledge",
	[0x05] = "Immediate",
	[0x06] = "Immediate reply"
}

aun_ports = {
	[0x00] = "Immediate",
	[0x90] = "FileServerReply",
	[0x91] = "FileServerData",
	[0x92] = "FileServerData",
	[0x93] = "FileServerData / Remote",
	[0x94] = "FileServerData",
	[0x95] = "FileServerData",
	[0x96] = "FileServerData",
	[0x97] = "FileServerData",
	[0x98] = "FileServerData",
	[0x99] = "FileServerCommand",
	[0x9C] = "Bridge",
	[0x9D] = "ResourceLocator",
	[0x9E] = "PrinterServerEnquiryReply",
	[0x9F] = "PrinterServerEnquiry",
	[0xA0] = "SJ *FAST protocol",
	[0xA1] = "SJ Nexus net find reply",
	[0xB0] = "FindServer",
	[0xB1] = "FindServerReply",
	[0xB2] = "TeletextServerCommand",
	[0xB3] = "TeletextServerPage",
	[0xD0] = "PrintServerReply",
	[0xD1] = "PrintServerData",
	[0xD2] = "TCPIPOverEconet",
	[0xD3] = "SIDFrameSlave",
	[0xD4] = "Scrollarama",
	[0xD5] = "Phone",
	[0xD6] = "BroadcastControl",
	[0xD7] = "BroadcastData",
	[0xD8] = "ImpressionLicenceChecker",
	[0xD9] = "DigitalServicesSquirrel",
	[0xDA] = "SIDSecondary",
	[0xDB] = "DigitalServicesSquirrel2",
	[0xDC] = "DataDistributionControl"
}

aun_fs_functions = {
	[0x00] = "Execute command (OSCLI)",
	[0x01] = "Start client-to-server file transfer (*SAVE)",
	[0x02] = "Start server-to-client file transfer (*LOAD)",
	[0x03] = "Examine object (*EX)",
	[0x04] = "Read catalogue header",
	[0x05] = "Load as command",
	[0x06] = "Open file",
	[0x07] = "Close file",
	[0x08] = "Get byte",
	[0x09] = "Put byte",
	[0x0A] = "Get multiple bytes",
	[0x0B] = "Put multiple bytes",
	[0x0C] = "Read random access information",
	[0x0D] = "Set random access information",
	[0x0E] = "Read disc name information",
	[0x0F] = "Read logged on users",
	[0x10] = "Read date/time",
	[0x11] = "Read EOF (End Of File) information",
	[0x12] = "Read object information",
	[0x13] = "Set object information",
	[0x14] = "Delete object",
	[0x15] = "Read user environment",
	[0x16] = "Set user's boot option",
	[0x17] = "Log off",
	[0x18] = "Read user information",
	[0x19] = "Read file server version number",
	[0x1A] = "Read file server free space",
	[0x1B] = "Create directory",
	[0x1C] = "Set date/time",
	[0x1D] = "Create file of specified size",
	[0x1E] = "Read user free space",
	[0x1F] = "Set user free space",
	[0x20] = "Read client user identifier",
	[0x40] = "Read account information",
	[0x41] = "Read/write system information"
}

aun_fs03_functions = {
	[0x00] = "All information in binary format",
	[0x01] = "All information as ASCII string",
	[0x02] = "File title only",
	[0x03] = "File title and access as ASCII string"
}

aun_fs0c_functions = {
	[0x00] = "Seqeuential file pointer",
	[0x01] = "File exent",
	[0x02] = "File size"
}

aun_fs0d_functions = {
	[0x00] = "Seqeuential file pointer",
	[0x01] = "File exent"
}

aun_fs12_functions = {
	[0x01] = "Read object creation date",
	[0x02] = "Read load and execute address",
	[0x03] = "Read object extent",
	[0x04] = "Read access byte",
	[0x05] = "Read all object attributes",
	[0x06] = "Read access and cycle number of directory",
	[0x40] = "Read creation and update time"
}

aun_fs13_functions = {
	[0x01] = "Set load/exec/access",
	[0x02] = "Set load address",
	[0x03] = "Set exec address",
	[0x04] = "Set access flags",
	[0x05] = "Set creation date",
	[0x40] = "Set modify/creation date and time"
}

aun_fs40_functions = {
	[0x00] = "Read account info"
}

aun_fs41_functions = {
	[0x00] = "Reset print server information",
	[0x01] = "Read current state of printer",
	[0x02] = "Write current state of printer",
	[0x03] = "Read auto printer priority",
	[0x04] = "Write auto printer priority",
	[0x05] = "Read system message channel",
	[0x06] = "Write system message channel",
	[0x07] = "Read message level",
	[0x08] = "Write message level",
	[0x09] = "Read default printer",
	[0x0A] = "Write default printer",
	[0x0B] = "Read the privilege required to change the file servers date and time",
	[0x0C] = "Set the privilege required to change the file servers date and time"
}

aun_clientactions = {
	[0x00] = "None",
	[0x01] = "*Save",
	[0x02] = "*Load",
	[0x03] = "*Cat",
	[0x04] = "*Info, *Printer, *Printout",
	[0x05] = "*I Am",
	[0x06] = "*SDisc",
	[0x07] = "*Dir, *SDisc",
	[0x08] = "*Unrecognized command",
	[0x09] = "*Lib"
}

aun_printerstatus = {
	[0x00] = "Online",
	[0x01] = "Busy with station",
	[0x02] = "Jammed/Offline"
}

aun_bootoptions = {
	[0x00] = "Off",
	[0x01] = "Load",
	[0x02] = "Run",
	[0x03] = "Exec"
}

aun_tcpiptypes = {
	[0x81] = "IP Unicast",
	[0x8E] = "IP Broadcast Reply",
	[0x8F] = "IP Broadcast",
	[0xA1] = "ARP Request",
	[0xA2] = "ARP Reply"
}

aun_bridgetypes = {
	[0x00] = "NewBridge",
	[0x01] = "NewBridgeReply",
	[0x02] = "WhatNet",
	[0x03] = "IsNet"
}



function aun_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "AUN"

	local size = buffer:len()
	local packettype = buffer(0,1):uint()
	local port = buffer(1,1):le_uint()
	local ctrl = buffer(2,1):le_uint()

	local subtree = tree:add(aun_proto, buffer(), string.format("Acorn Universal Networking (%d bytes)", size))

	if size < 8 then
		subtree:add(buffer(0, size), "Unrecognized Data: " .. buffer(0, size))
		return
	end
	header_subtree = subtree:add(buffer(0,8),"Header (8 bytes)")
	header_subtree:add(buffer( 0,1), "Packet type: " .. get_description(aun_types, packettype))
	header_subtree:add(buffer( 1,1), "Port: " .. get_description(aun_ports, port))
	header_subtree:add(buffer( 2,1), "Control: " .. ctrl)
	header_subtree:add(buffer( 3,1), "Retransmission flag: " .. buffer(3,1):uint())
	header_subtree:add(buffer( 4,4), "Sequence identifier: " .. get_hex32_value(buffer(4,4):le_uint()))

	if size == 8 then return end

	data_subtree = subtree:add(buffer(8,size-8), string.format("Data (%d bytes)", size-8))

--	&90: FileServerReply
	if port == 0x90 then
		local cmd = buffer(8,1):le_uint()
		local err = buffer(9,1):le_uint()

		data_subtree:add(buffer( 8,1), "Client action: " .. get_description(aun_clientactions, cmd))
		if err == 0x00 then
			data_subtree:add(buffer( 9,1), "Result: 0x00 (Success)")
			data_subtree:add(buffer(10,size-10), "Data: " .. buffer(10,size-10))
			return
		else
			data_subtree:add(buffer( 9,size-9), "Result: " .. get_hex8_value(err) .. " (" .. buffer(10,size-10):string() .. ")")
			return
		end
	end

--	&99: FileServerCommand
	if port == 0x99 then
		local func = buffer(9,1):le_uint()

		data_subtree:add(buffer( 8,1), "Reply port: " .. get_description(aun_ports, buffer(8,1):uint()))
		data_subtree:add(buffer( 9,1), "Function: " .. get_description(aun_fs_functions, func))
--		&00: Command line
		if func == 0x00 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Command: " .. buffer(13,size-13):string())
			return
		end
--		&01: *Save / &1D: Create file of specified size
		if func == 0x01 or func == 0x1D then
			local data_port = buffer(10,1):uint()

			data_subtree:add(buffer(10,1), "Data transmission port: " .. get_description(aun_ports, data_port))
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13, 4), "Load address: " .. get_hex32_value(buffer(13,4):le_uint()))
			data_subtree:add(buffer(17, 4), "Exec address: " .. get_hex32_value(buffer(17,4):le_uint()))
			data_subtree:add(buffer(21, 3), "Length: " .. get_hex24_value(buffer(21,3):le_uint()))
			data_subtree:add(buffer(24,size-24),"Filename: " .. buffer(24,size-24):string())
			return
		end
--		&02: *Load / &05: Load as command
		if func == 0x02 or func == 0x05 then
			local data_port = buffer(10,1):uint()

			data_subtree:add(buffer(10,1), "Data transmission port: " .. get_description(aun_ports, data_port))
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Filename: " .. buffer(13,size-13):string())
			return
		end
--		&03: *Ex
		if func == 0x03 then 
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Sub-function: " .. get_description(aun_fs03_functions, subfunc))
			data_subtree:add(buffer(14,1), "Entry pointer to directory: " .. buffer(14,1):uint())
			data_subtree:add(buffer(15,1), "Number of objects to examine: " .. buffer(15,1):uint())
			data_subtree:add(buffer(16,size-16), "Directory name: " .. buffer(16,size-16):string())
			return
		end
--		&04: Catalogue header
		if func == 0x04 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Directory name: " .. buffer(13,size-13):string())
			return
		end
--		&06: Open file
		if func == 0x06 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Create a new file: " .. buffer(13,1):uint())
			data_subtree:add(buffer(14,1), "Open object for update: " .. buffer(14,1):uint())
			data_subtree:add(buffer(15,size-15),"Filename: " .. buffer(15,size-15):string())
			return
		end
--		&07: Close file
		if func == 0x07 then
			data_subtree:add(buffer(10,1), "File handle: " .. buffer(10,1):uint())
			return
		end
--		&08: BGET
		if func == 0x08 then
			data_subtree:add(buffer(10,1), "File handle: " .. buffer(10,1):uint())
			return
		end
--		&09: BPUT
		if func == 0x09 then
			data_subtree:add(buffer(10,1), "File handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "Byte to be written: " .. buffer(11,1):uint())
			return
		end
--		&0A: Get multiple bytes / &0B: Put multiple bytes
		if func == 0x0A or func == 0x0B then
			local ackport = buffer(10,1):le_uint()

			data_subtree:add(buffer(10,1), "Data acknowledge port: " .. get_description(aun_ports, ackport))
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "File handle: " .. buffer(13,1):uint())
			data_subtree:add(buffer(14,1), "Use specified offset: " .. buffer(14,1):uint())
			data_subtree:add(buffer(15,3), "Number of bytes: " .. get_hex24_value(buffer(15,3):le_uint()))
			data_subtree:add(buffer(18,3), "Offset: " .. get_hex24_value(buffer(18,3):le_uint()))
			return
		end
--		&0C: Read random access information
		if func == 0x0C then
			local ptrtype = buffer(11,1):uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "File handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(14,1), "Type: " .. get_description(aun_fs0c_functions, subfunc))
			return
		end
--		&0D: Set random access information
		if func == 0x0D then
			local ptrtype = buffer(11,1):uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "File handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(14,1), "Type: " .. get_description(aun_fs0d_functions, subfunc))
			data_subtree:add(buffer(15, 3), "Offset: " .. get_hex24_value(buffer(15,3):le_uint()))
			return
		end
--		&0E: Read disc information
		if func == 0x0E then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "First drive number: " .. buffer(10,1):uint())
			data_subtree:add(buffer(14,1), "Number of drives to interrogate: " .. buffer(11,1):uint())
			return
		end
--		&0F: Read current users
		if func == 0x0F then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Start entry: " .. buffer(10,1):uint())
			data_subtree:add(buffer(14,1), "Number of entries to get: " .. buffer(11,1):uint())
			return
		end
--		&10: Read date and time
		if func == 0x11 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			return
		end
--		&11: Read EOF status
		if func == 0x11 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "File handle: " .. buffer(10,1):uint())
			return
		end
--		&12: Read object information
		if func == 0x12 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Sub-function: " .. get_description(aun_fs12_functions, subfunc))
			data_subtree:add(buffer(14,size-14), "Directory name: " .. buffer(14,size-14):string())
			return
		end
--		&13: Set object attributes
		if func == 0x13 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Sub-function: " .. get_description(aun_fs13_functions, subfunc))
			data_subtree:add(buffer(14,size-14), "Data: " .. buffer(14,size-14))
			return
		end
--		&14: Delete object
		if func == 0x14 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Object name: " .. buffer(13,size-13):string())
			return
		end
--		&15: Read user environment
		if func == 0x15 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			return
		end
--		&16: Set user boot option
		if func == 0x16 then
			local bootoption = buffer(13,1):uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Boot option: " .. get_description(aun_bootoptions, bootoption))
			return
		end
--		&17: Log off
		if func == 0x17 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			return
		end
--		&18: Read user information
		if func == 0x18 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Username: " .. buffer(13,size-13):string())
			return
		end
--		&19: Read fileserver version number
		if func == 0x19 then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			return
		end
--		&1A: Read fileserver free space
		if func == 0x1A then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Disc name: " .. buffer(13,size-13):string())
			return
		end
--		&1B: Create directory
		if func == 0x1B then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Number of blocks to allocate: " .. buffer(13,1):uint())
			data_subtree:add(buffer(14,size-14),"Disc name: " .. buffer(14,size-14):string())
			return
		end
--		&1C: Set real time clock
		if func == 0x1C then
			local date = buffer(13,2):uint()
			local time = buffer(15,3):uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,2), "Date: " .. get_date(date))
			data_subtree:add(buffer(15,3), "Time: " .. get_time(time))
			return
		end
--		&1E: Read user free space
		if func == 0x1E then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,size-13),"Username: " .. buffer(13,size-13):string())
			return
		end
--		&1F: Set user free space
		if func == 0x1F then
			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13, 4), "Load address: " .. get_hex32_value(buffer(13,4):le_uint()))
			data_subtree:add(buffer(17,size-17),"Username: " .. buffer(17,size-17):string())
			return
		end
--		&40: Read account information
		if func == 0x40 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(13,1), "Sub-function: " .. get_description(aun_fs40_functions, subfunc))
			data_subtree:add(buffer(14,2), "First account to try: " .. buffer(14,2):uint())
			data_subtree:add(buffer(16,2), "Maximum number of accounts: " .. buffer(16,2):uint())
			data_subtree:add(buffer(17,1), "Disc number: " .. buffer(17,1):uint())
			return
		end
--		&41: Read/write system information
		if func == 0x41 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(13,1), "Sub-function: " .. get_description(aun_fs41_functions, subfunc))
			data_subtree:add(buffer(14,size-14), "Data: " .. buffer(14,size-14))
			return
		end
--		&xx: Unknown file server function
		data_subtree:add(buffer(10,size-10), "Data: " .. buffer(10,size-10))
		return
	end

--	&9C: Bridge
	if port == 0x9C then
		local replyport = buffer(14,1):le_uint()
		local bridgetype = buffer(2,1):le_uint()

		data_subtree:add(buffer( 2,1), "Message type: " .. get_description(aun_bridgetypes, bridgetype))

		if ctrl == 0x00 or ctrl == 0x01 or ctrl == 0x02 or ctrl == 0x03 then
			data_subtree:add(buffer( 8,6), "Bridge identifier: " .. buffer(8,6):string())
			data_subtree:add(buffer(14,1), "Reply port: " .. get_description(aun_ports, replyport))
			data_subtree:add(buffer(15,size-15), "Data: " .. buffer(15,size-15))
			return
		else
			data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
			return
		end
	end

--	&9E: PrinterServerEnquiryReply
	if port == 0x9E then
		local printer_status = buffer(8,1):uint()

		data_subtree:add(buffer( 8,1), "Printer status: " .. get_description(aun_printerstatus, printer_status))
		data_subtree:add(buffer( 9,1), "Station: " .. buffer( 9,1):uint())
		data_subtree:add(buffer(10,1), "Network: " .. buffer(10,1):uint())
		data_subtree:add(buffer(14,size-14), "Data: " .. buffer(14,size-14))
		return
	end

--	&D2: TCPIPOverEconet
	if port == 0xD2 then
		local tcpip_type = buffer(2,1):uint()

		data_subtree:add(buffer( 2,1), "Message type: " .. get_description(aun_tcpiptypes, tcpip_type))
		data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
		return
	end
--	&xx: Unknown port
	data_subtree:add(buffer(8, size-8),"Data: " .. buffer(8,size-8))
end

function get_description(array, index)
	local description = array[index] or "Unknown"

	return string.format(description .. " (0x%02x)", index)
end



function get_hex8_value(value)
-- TODO: Find out if this can be done using a native WireShark function
	return string.format("0x%02x", value)
end

function get_hex24_value(value)
-- TODO: Find out if this can be done using a native WireShark function
	return string.format("0x%06x", value)
end

function get_hex32_value(value)
-- TODO: Find out if this can be done using a native WireShark function
	return string.format("0x%08x", value)
end

function get_date(value)
-- TODO: date translation
	return string.format("%i/%i/%i;", value(0,1), value(1,1), value(1,1))
end

function get_time(value)
	return string.format("%i:%i:%i", value(0,1), value(1,1), value(2,1))
end



udp_table = DissectorTable.get("udp.port")
udp_table:add(32768,aun_proto)
