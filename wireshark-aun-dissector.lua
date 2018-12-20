-- Acorn Universal Networking protocol dissector for WireShark
-- (c) Eelco Huininga 2018

aun_proto = Proto("aun","Acorn Universal Networking")

function aun_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "AUN"

	local size = buffer:len()
	local port = buffer(1,1):le_uint()
	local ctrl = buffer(2,1):le_uint()

	local subtree = tree:add(aun_proto, buffer(), string.format("Acorn Universal Networking (%d bytes)", size))

	header_subtree = subtree:add(buffer(0,8),"Header (8 bytes)")
	header_subtree:add(buffer( 0,1), "Packet type: " .. get_transaction_desc(buffer(0,1):uint()))
	header_subtree:add(buffer( 1,1), "Port: " .. get_port_desc(port))
	header_subtree:add(buffer( 2,1), "Control: " .. ctrl)
	header_subtree:add(buffer( 3,1), "Retransmission flag: " .. buffer(3,1):uint())
	header_subtree:add(buffer( 4,4), "Sequence identifier: " .. get_hex32_value(buffer(4,4):le_uint()))

	if size <= 8 then return end

	data_subtree = subtree:add(buffer(8,size-8), string.format("Data (%d bytes)", size-8))

--	&90: FileServerReply
	if port == 0x90 then
		local cmd = buffer(8,1):le_uint()
		local err = buffer(9,1):le_uint()

		data_subtree:add(buffer( 8,1), "Client action: " .. get_clientaction_desc(cmd))
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

		data_subtree:add(buffer( 8,1), "Reply port: " .. get_port_desc(buffer(8,1):uint()))
		data_subtree:add(buffer( 9,1), "Function: " .. get_fileserver_function_desc(func))
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

			data_subtree:add(buffer(10,1), "Data transmission port: " .. get_port_desc(data_port))
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

			data_subtree:add(buffer(10,1), "Data transmission port: " .. get_port_desc(data_port))
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
			data_subtree:add(buffer(13,1), "Sub-function: " .. get_fileserver_subfunction_desc(func, subfunc))
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

			data_subtree:add(buffer(10,1), "Data acknowledge port: " .. get_port_desc(ackport))
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
			if ptrtype == 0x00 then data_subtree:add(buffer(14,1), "Type: Seqeuential file pointer")
			elseif ptrtype == 0x01 then data_subtree:add(buffer(14,1), "Type: File exent")
			elseif ptrtype == 0x02 then data_subtree:add(buffer(14,1), "Type: File size")
			else data_subtree:add(buffer(14,1), "Type: Unknown") end
			return
		end
--		&0D: Set random access information
		if func == 0x0D then
			local ptrtype = buffer(11,1):uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "File handle: " .. buffer(10,1):uint())
			if ptrtype == 0x00 then data_subtree:add(buffer(14,1), "Type: Seqeuential file pointer")
			elseif ptrtype == 0x01 then data_subtree:add(buffer(14,1), "Type: File exent")
			else data_subtree:add(buffer(14,1), "Type: Unknown") end
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
			data_subtree:add(buffer(13,1), "Sub-function: " .. get_fileserver_subfunction_desc(func, subfunc))
			data_subtree:add(buffer(14,size-14), "Directory name: " .. buffer(14,size-14):string())
			return
		end
--		&13: Set object attributes
		if func == 0x13 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(10,1), "URD handle: " .. buffer(10,1):uint())
			data_subtree:add(buffer(11,1), "CSD handle: " .. buffer(11,1):uint())
			data_subtree:add(buffer(12,1), "LIB handle: " .. buffer(12,1):uint())
			data_subtree:add(buffer(13,1), "Sub-function: " .. get_fileserver_subfunction_desc(func, subfunc))
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
			data_subtree:add(buffer(13,1), "Boot option: " .. get_boot_option(bootoption))
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

			data_subtree:add(buffer(13,1), "Sub-function: " .. get_fileserver_subfunction_desc(func, subfunc))
			data_subtree:add(buffer(14,2), "First account to try: " .. buffer(14,2):uint())
			data_subtree:add(buffer(16,2), "Maximum number of accounts: " .. buffer(16,2):uint())
			data_subtree:add(buffer(17,1), "Disc number: " .. buffer(17,1):uint())
			return
		end
--		&41: Read/write system information
		if func == 0x41 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add(buffer(13,1), "Sub-function: " .. get_fileserver_subfunction_desc(func, subfunc))
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

		if ctrl == 0x00 then
			data_subtree:add(buffer( 2,1), "Message type: NewBridge")
			data_subtree:add(buffer( 8,6), "Bridge identifier: " .. buffer(8,6):string())
			data_subtree:add(buffer(14,1), "Reply port: " .. get_port_desc(replyport))
			data_subtree:add(buffer(15,size-15), "Data: " .. buffer(15,size-15))
			return
		end
		if ctrl == 0x01 then
			data_subtree:add(buffer( 2,1), "Message type: NewBridgeReply")
			data_subtree:add(buffer( 8,6), "Bridge identifier: " .. buffer(8,6):string())
			data_subtree:add(buffer(14,1), "Reply port: " .. get_port_desc(replyport))
			data_subtree:add(buffer(15,size-15), "Data: " .. buffer(15,size-15))
			return
		end
		if ctrl == 0x02 then
			data_subtree:add(buffer( 2,1), "Message type: WhatNet")
			data_subtree:add(buffer( 8,6), "Bridge identifier: " .. buffer(8,6):string())
			data_subtree:add(buffer( 14,1), "Reply port: " .. get_port_desc(replyport))
			return
		end
		if ctrl == 0x03 then
			data_subtree:add(buffer( 2,1), "Message type: IsNet")
			data_subtree:add(buffer( 8,6), "Bridge identifier: " .. buffer(8,6):string())
			data_subtree:add(buffer( 14,1), "Reply port: " .. get_port_desc(replyport))
			data_subtree:add(buffer( 15,1), "Network ID: " .. buffer(15,1):uint())
			return
		end
		data_subtree:add(buffer( 2,1), "Message type: Unknown")
		data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
		return
	end

--	&9E: PrinterServerEnquiryReply
	if port == 0x9E then
		data_subtree:add(buffer( 8,1), "Printer status: " .. get_printerstatus_desc(buffer(8,1):uint()))
		data_subtree:add(buffer( 9,1), "Station: " .. buffer( 9,1):uint())
		data_subtree:add(buffer(10,1), "Network: " .. buffer(10,1):uint())
		data_subtree:add(buffer(14,size-14), "Data: " .. buffer(14,size-14))
		return
	end

--	&D2: TCPIPOverEconet
	if port == 0xD2 then
		if ctrl == 0x81 then
			data_subtree:add(buffer( 2,1), "Message type: IP Unicast")
			data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
			return
		end
		if ctrl == 0x8E then
			data_subtree:add(buffer( 2,1), "Message type: IP Broadcast Reply")
			data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
			return
		end
		if ctrl == 0x8F then
			data_subtree:add(buffer( 2,1), "Message type: IP Broadcast")
			data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
			return
		end
		if ctrl == 0xA1 then
			data_subtree:add(buffer( 2,1), "Message type: ARP Request")
			data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
			return
		end
		if ctrl == 0xA2 then
			data_subtree:add(buffer( 2,1), "Message type: ARP Reply")
			data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
			return
		end
		data_subtree:add(buffer( 2,1), "Message type: Unknown")
		data_subtree:add(buffer( 8,size-8), "Data: " .. buffer(8,size-8))
		return
	end

	data_subtree:add(buffer(8, size-8),"Data: " .. buffer(8,size-8))
end

function get_transaction_desc(type)
	local description = "Unknown"

	if type == 0x01 then description = "Broadcast" end
	if type == 0x02 then description = "Unicast" end
	if type == 0x03 then description = "Ack" end
	if type == 0x04 then description = "Nack" end
	if type == 0x05 then description = "Immediate" end
	if type == 0x06 then description = "Immediate Reply" end

	return description
end

function get_clientaction_desc(type)
	local description = "Unknown"

	if type == 0x00 then description = "None" end
	if type == 0x01 then description = "*Save" end
	if type == 0x02 then description = "*Load" end
	if type == 0x03 then description = "*Cat" end
	if type == 0x04 then description = "*Info, *Printer, *Printout" end
	if type == 0x05 then description = "*I Am" end
	if type == 0x06 then description = "*SDisc" end
	if type == 0x07 then description = "*Dir, *SDisc" end
	if type == 0x08 then description = "*Unrecognized command" end
	if type == 0x09 then description = "*Lib" end

	return description
end

function get_port_desc(port)
	local description = "Unknown"

	if port == 0x00 then description = "Immediate" end
	if port == 0x90 then description = "FileServerReply" end
	if port == 0x91 then description = "FileServerData" end
	if port == 0x92 then description = "FileServerData" end
	if port == 0x93 then description = "FileServerData / Remote" end
	if port == 0x94 then description = "FileServerData" end
	if port == 0x95 then description = "FileServerData" end
	if port == 0x96 then description = "FileServerData" end
	if port == 0x97 then description = "FileServerData" end
	if port == 0x98 then description = "FileServerData" end
	if port == 0x99 then description = "FileServerCommand" end
	if port == 0x9C then description = "Bridge" end
	if port == 0x9D then description = "ResourceLocator" end
	if port == 0x9E then description = "PrinterServerEnquiryReply" end
	if port == 0x9F then description = "PrinterServerEnquiry" end
	if port == 0xA0 then description = "SJ *FAST protocol" end
	if port == 0xA1 then description = "SJ Nexus net find reply" end
	if port == 0xB0 then description = "FindServer" end
	if port == 0xB1 then description = "FindServerReply" end
	if port == 0xB2 then description = "TeletextServerCommand" end
	if port == 0xB3 then description = "TeletextServerPage" end
	if port == 0xD0 then description = "PrintServerReply" end
	if port == 0xD1 then description = "PrintServerData" end
	if port == 0xD2 then description = "TCPIPOverEconet" end
	if port == 0xD3 then description = "SIDFrameSlave" end
	if port == 0xD4 then description = "Scrollarama" end
	if port == 0xD5 then description = "Phone" end
	if port == 0xD6 then description = "BroadcastControl" end
	if port == 0xD7 then description = "BroadcastData" end
	if port == 0xD8 then description = "ImpressionLicenceChecker" end
	if port == 0xD9 then description = "DigitalServicesSquirrel" end
	if port == 0xDA then description = "SIDSecondary" end
	if port == 0xDB then description = "DigitalServicesSquirrel2" end
	if port == 0xDC then description = "DataDistributionControl" end

	return description
end

function get_fileserver_function_desc(type)
	local description = "Unknown"

	if type == 0x00 then description = "Execute command (OSCLI)" end
	if type == 0x01 then description = "Start client-to-server file transfer (*SAVE)" end
	if type == 0x02 then description = "Start server-to-client file transfer (*LOAD)" end
	if type == 0x03 then description = "Examine object (*EX)" end
	if type == 0x04 then description = "Read catalogue header" end
	if type == 0x05 then description = "Load as command" end
	if type == 0x06 then description = "Open file" end
	if type == 0x07 then description = "Close file" end
	if type == 0x08 then description = "Get byte" end
	if type == 0x09 then description = "Put byte" end
	if type == 0x0A then description = "Get multiple bytes" end
	if type == 0x0B then description = "Put multiple bytes" end
	if type == 0x0C then description = "Read random access information" end
	if type == 0x0D then description = "Set random access information" end
	if type == 0x0E then description = "Read disc name information" end
	if type == 0x0F then description = "Read logged on users" end
	if type == 0x10 then description = "Read date/time" end
	if type == 0x11 then description = "Read EOF (End Of File) information" end
	if type == 0x12 then description = "Read object information" end
	if type == 0x13 then description = "Set object information" end
	if type == 0x14 then description = "Delete object" end
	if type == 0x15 then description = "Read user environment" end
	if type == 0x16 then description = "Set user's boot option" end
	if type == 0x17 then description = "Log off" end
	if type == 0x18 then description = "Read user information" end
	if type == 0x19 then description = "Read file server version number" end
	if type == 0x1A then description = "Read file server free space" end
	if type == 0x1B then description = "Create directory" end
	if type == 0x1C then description = "Set date/time" end
	if type == 0x1D then description = "Create file of specified size" end
	if type == 0x1E then description = "Read user free space" end
	if type == 0x1F then description = "Set user free space" end
	if type == 0x20 then description = "Read client user identifier" end
	if type == 0x40 then description = "Read account information" end
	if type == 0x41 then description = "Read/write system information" end

	return description
end

function get_fileserver_subfunction_desc(func, subfunc)
	local description = "Unknown"

	if func == 0x03 then
		if subfunc == 0x00 then description = "All information (binary format)" end
		if subfunc == 0x01 then description = "All information (ASCII string)" end
		if subfunc == 0x02 then description = "File title only" end
		if subfunc == 0x03 then description = "File title and access (ASCII string)" end
	end
	if func == 0x12 then
		if subfunc == 0x01 then description = "Read object creation date" end
		if subfunc == 0x02 then description = "Read load and execute address" end
		if subfunc == 0x03 then description = "Read object extent" end
		if subfunc == 0x04 then description = "Read access byte" end
		if subfunc == 0x05 then description = "Read all object attributes" end
		if subfunc == 0x06 then description = "Read access and cycle number of directory" end
		if subfunc == 0x40 then description = "Read creation and update time" end
	end
	if func == 0x13 then
		if subfunc == 0x01 then description = "Set load/exec/access" end
		if subfunc == 0x02 then description = "Set load address" end
		if subfunc == 0x03 then description = "Set exec address" end
		if subfunc == 0x04 then description = "Set access flags" end
		if subfunc == 0x05 then description = "Set creation date" end
		if subfunc == 0x40 then description = "Set modify/creation date and time" end
	end
	if func == 0x40 then
		if subfunc == 0x00 then description = "Read account info" end
	end
	if func == 0x41 then
		if subfunc == 0x00 then description = "Reset print server information" end
		if subfunc == 0x01 then description = "Read current state of printer" end
		if subfunc == 0x02 then description = "Write current state of printer" end
		if subfunc == 0x03 then description = "Read auto printer priority" end
		if subfunc == 0x04 then description = "Write auto printer priority" end
		if subfunc == 0x05 then description = "Read system message channel" end
		if subfunc == 0x06 then description = "Write system message channel" end
		if subfunc == 0x07 then description = "Read message level" end
		if subfunc == 0x08 then description = "Write message level" end
		if subfunc == 0x09 then description = "Read default printer" end
		if subfunc == 0x0A then description = "Write default printer" end
		if subfunc == 0x0B then description = "Read the privilege required to change the file servers date and time" end
		if subfunc == 0x0C then description = "Set the privilege required to change the file servers date and time" end
	end

	return description
end

function get_printerstatus_desc(type)
	local description = "Unknown"

	if type == 0x00 then description = "Online" end
	if type == 0x01 then description = "Busy with station" end
	if type == 0x02 then description = "Jammed/Offline" end

	return description
end

function get_boot_option(bootoption)
	local description = "Unknown"

	if bootoption == 0x00 then description = "Off" end
	if bootoption == 0x01 then description = "Load" end
	if bootoption == 0x02 then description = "Run" end
	if bootoption == 0x03 then description = "Exec" end

	return description
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
