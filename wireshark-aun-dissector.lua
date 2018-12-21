-------------------------------------------------------------------------------
-- wireshark-aun-dissector.lua
-- Acorn Universal Networking protocol dissector for WireShark
-- (c) Eelco Huininga 2018
-------------------------------------------------------------------------------

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

aun_immediate_functions = {
	[0x00] = "Execute command (OSCLI)",
	[0x01] = "Peek",
	[0x02] = "Poke",
	[0x03] = "Start program (JSR)",
	[0x04] = "UserProc",
	[0x05] = "OSProc",
	[0x06] = "Halt",
	[0x07] = "Continue",
	[0x08] = "MachineType",
	[0x09] = "GetRegisters"
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

aun = Proto("aun","Acorn Universal Networking")

aun.fields.packettype    = ProtoField.uint8 ("aun.packettype",    "Packet type",                base.DEC, aun_types)
aun.fields.bridgetype    = ProtoField.uint8 ("aun.bridgetype",    "Message type",               base.DEC, aun_bridgetypes)
aun.fields.tcpiptype     = ProtoField.uint8 ("aun.tcpiptype",     "Message type",               base.HEX, aun_tcpiptype)
aun.fields.port          = ProtoField.uint8 ("aun.port",          "Port",                       base.HEX, aun_ports)
aun.fields.control       = ProtoField.uint8 ("aun.control",       "Control byte",               base.HEX)
aun.fields.retrans       = ProtoField.uint8 ("aun.retrans",       "Retransmission flag",        base.HEX)
aun.fields.sequence      = ProtoField.uint32("aun.sequence",      "Sequence ID",                base.HEX)
aun.fields.im_function   = ProtoField.uint8 ("aun.im_function",   "Function",                   base.HEX, aun_immediate_functions)
aun.fields.fs_function   = ProtoField.uint8 ("aun.fs_function",   "Function",                   base.HEX, aun_fs_functions)
aun.fields.fs_subfunc03  = ProtoField.uint8 ("aun.fs_subfunc03",  "Sub-function",               base.HEX, aun_fs03_functions)
aun.fields.fs_subfunc0c  = ProtoField.uint8 ("aun.fs_subfunc0c",  "Type",                       base.HEX, aun_fs0c_functions)
aun.fields.fs_subfunc0d  = ProtoField.uint8 ("aun.fs_subfunc0d",  "Type",                       base.HEX, aun_fs0d_functions)
aun.fields.fs_subfunc12  = ProtoField.uint8 ("aun.fs_subfunc12",  "Sub-function",               base.HEX, aun_fs12_functions)
aun.fields.fs_subfunc13  = ProtoField.uint8 ("aun.fs_subfunc13",  "Sub-function",               base.HEX, aun_fs13_functions)
aun.fields.fs_subfunc40  = ProtoField.uint8 ("aun.fs_subfunc40",  "Sub-function",               base.HEX, aun_fs40_functions)
aun.fields.fs_subfunc41  = ProtoField.uint8 ("aun.fs_subfunc41",  "Sub-function",               base.HEX, aun_fs41_functions)
aun.fields.clientaction  = ProtoField.uint8 ("aun.clientaction",  "Client action",              base.HEX)
aun.fields.result        = ProtoField.uint8 ("aun.result",        "Result",                     base.HEX)
aun.fields.replyport     = ProtoField.uint8 ("aun.replyport",     "Reply port",                 base.HEX, aun_ports)
aun.fields.dataport      = ProtoField.uint8 ("aun.dataport",      "Data transmission port",     base.HEX, aun_ports)
aun.fields.ackport       = ProtoField.uint8 ("aun.ackport",       "Data acknowledge port",      base.HEX, aun_ports)
aun.fields.urd           = ProtoField.uint8 ("aun.urd",           "URD handle",                 base.HEX)
aun.fields.csd           = ProtoField.uint8 ("aun.csd",           "CSD handle",                 base.HEX)
aun.fields.lib           = ProtoField.uint8 ("aun.lib",           "LIB handle",                 base.HEX)
aun.fields.filehandle    = ProtoField.uint8 ("aun.filehandle",    "File handle",                base.HEX)
aun.fields.loadaddr      = ProtoField.uint32("aun.loadaddr",      "Load address",               base.HEX)
aun.fields.execaddr      = ProtoField.uint32("aun.execaddr",      "Exec address",               base.HEX)
aun.fields.length        = ProtoField.uint24("aun.length",        "Length",                     base.HEX)
aun.fields.offset        = ProtoField.uint24("aun.offset",        "Offset",                     base.HEX)
aun.fields.useoffset     = ProtoField.bool  ("aun.useoffset",     "Use specified offset",       base.NONE)
aun.fields.bytes8        = ProtoField.uint8 ("aun.bytes8",        "Number of bytes",            base.HEX)
aun.fields.bytes24       = ProtoField.uint8 ("aun.bytes24",       "Number of bytes",            base.HEX)
aun.fields.identifier    = ProtoField.string("aun.identifier",    "Identifier string",          base.NONE)
aun.fields.command       = ProtoField.string("aun.command",       "Command",                    base.NONE)
aun.fields.filename      = ProtoField.string("aun.filename",      "Filename",                   base.NONE)
aun.fields.dirname       = ProtoField.string("aun.dirname",       "Directory name",             base.NONE)
aun.fields.objectname    = ProtoField.string("aun.objectname",    "Object name",                base.NONE)
aun.fields.username      = ProtoField.string("aun.username",      "User name",                  base.NONE)
aun.fields.discname      = ProtoField.string("aun.discname",      "Disc name",                  base.NONE)
aun.fields.discnumber    = ProtoField.string("aun.discnumber",    "Disc number",                base.NONE)
aun.fields.startat       = ProtoField.uint8 ("aun.startat",       "Start at number",            base.HEX)
aun.fields.items         = ProtoField.uint8 ("aun.items",         "Number of items to get",     base.HEX)
aun.fields.firstaccount  = ProtoField.uint16("aun.firstaccount",  "First account to try",       base.HEX)
aun.fields.maxaccounts   = ProtoField.uint16("aun.maxaccounts",   "Maximum number of accounts", base.HEX)
aun.fields.blocks        = ProtoField.uint8 ("aun.blocks",        "Blocks to allocate",         base.HEX)
aun.fields.bootoption    = ProtoField.uint8 ("aun.bootoption",    "Boot option",                base.HEX, aun_bootoptions)
aun.fields.createnew     = ProtoField.bool  ("aun.createnew",     "Create new file",            base.NONE)
aun.fields.openupdate    = ProtoField.bool  ("aun.openupdate",    "Open object for update",     base.NONE)
aun.fields.printerstatus = ProtoField.uint8 ("aun.printerstatus", "Printer status",             base.HEX, aun_printerstatus)
aun.fields.station       = ProtoField.uint8 ("aun.station",       "Station",                    base.HEX)
aun.fields.network       = ProtoField.uint8 ("aun.network",       "Network",                    base.HEX)
aun.fields.data          = ProtoField.bytes ("aun.data",          "Data",                       base.SPACE)




function aun.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "AUN"

	local size = buffer:len()
	local packettype = buffer(0,1):uint()
	local port = buffer(1,1):le_uint()
	local ctrl = buffer(2,1):le_uint()

	local subtree = tree:add(aun, buffer(), string.format(aun.description .. " (%d bytes)", size))

	if size < 8 then
		subtree:add(buffer(0, size), "Malformed data: " .. buffer(0, size))
		return
	end

--	local header_subtree = subtree:add(buffer(0,8),"Header (8 bytes)")
	local header_subtree = subtree
	header_subtree:add_le(aun.fields.packettype, buffer(0,1))
	header_subtree:add_le(aun.fields.port,       buffer(1,1))
	header_subtree:add_le(aun.fields.control,    buffer(2,1))
	header_subtree:add_le(aun.fields.retrans,    buffer(3,1))
	header_subtree:add_le(aun.fields.sequence,   buffer(4,4))

	if size == 8 then return end

--	local data_subtree = subtree:add(buffer(8,size-8), string.format("Data (%d bytes)", size-8))
	local data_subtree = subtree

--	Port &00: Immediate
	if port == 0x00 then
		data_subtree:add_le(aun.fields.im_function, buffer(2,1))
		data_subtree:add_le(aun.fields.data, buffer(8,size-8))
		return
	end

--	Port &90: FileServerReply
	if port == 0x90 then
		data_subtree:add_le(aun.fields.clientaction, buffer(8,1))
		if err == 0x00 then
			data_subtree:add_le(aun.fields.result, buffer(9,size-9), 0, nil, "(Success)")
			data_subtree:add_le(aun.fields.data, buffer(10,size-10))
			return
		else
			data_subtree:add_le(aun.fields.result, buffer(9,size-9), 0, nil, "(" .. buffer(10,size-10):string() .. ")")
			return
		end
	end

--	Port &99: FileServerCommand
	if port == 0x99 then
		local fs_func= buffer(9,1):le_uint()

		data_subtree:add_le(aun.fields.replyport,            buffer(8,1))
		data_subtree:add_le(aun.fields.fs_function,          buffer(9,1))
--		&00: Command line
		if fs_func== 0x00 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.command,      buffer(13,size-13))
			return
		end
--		&01: *Save / &1D: Create file of specified size
		if fs_func== 0x01 or fs_func== 0x1D then
			data_subtree:add_le(aun.fields.dataport,     buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.loadaddr,     buffer(13,4))
			data_subtree:add_le(aun.fields.execaddr,     buffer(17,4))
			data_subtree:add_le(aun.fields.length,       buffer(21,3))
			data_subtree:add_le(aun.fields.filename,     buffer(24,size-24))
			return
		end
--		&02: *Load / &05: Load as command
		if fs_func== 0x02 or fs_func== 0x05 then
			data_subtree:add_le(aun.fields.dataport,     buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.filename,     buffer(13,size-13))
			return
		end
--		&03: *Ex
		if fs_func== 0x03 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.fs_subfunc03, buffer(13,1))
			data_subtree:add_le(aun.fields.startat,      buffer(14,1))
			data_subtree:add_le(aun.fields.items,        buffer(15,1))
			data_subtree:add_le(aun.fields.dirname,      buffer(16,size-16))
			return
		end
--		&04: Catalogue header
		if fs_func== 0x04 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.dirname,      buffer(13,size-13))
			return
		end
--		&06: Open file
		if fs_func== 0x06 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.createnew,    buffer(13,1))
			data_subtree:add_le(aun.fields.openupdate,   buffer(14,1))
			data_subtree:add_le(aun.fields.filename,     buffer(15,size-15))
			return
		end
--		&07: Close file
		if fs_func== 0x07 then
			data_subtree:add_le(aun.fields.filehandle,   buffer(10,1))
			return
		end
--		&08: BGET
		if fs_func== 0x08 then
			data_subtree:add_le(aun.fields.filehandle,   buffer(10,1))
			return
		end
--		&09: BPUT
		if fs_func== 0x09 then
			data_subtree:add_le(aun.fields.filehandle,   buffer(10,1))
			data_subtree:add_le(aun.fields.bytes8,       buffer(11,1))
			return
		end
--		&0A: Get multiple bytes / &0B: Put multiple bytes
		if fs_func== 0x0A or fs_func== 0x0B then
			data_subtree:add_le(aun.fields.ackport,      buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.filehandle,   buffer(13,1))
			data_subtree:add_le(aun.fields.useoffset,    buffer(14,1))
			data_subtree:add_le(aun.fields.bytes24,      buffer(15,3))
			data_subtree:add_le(aun.fields.offset,       buffer(18,3))
			return
		end
--		&0C: Read random access information
		if fs_func== 0x0C then
			local ptrtype = buffer(11,1):uint()

			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.filehandle,   buffer(13,1))
			data_subtree:add_le(aun.fields.fs_subfunc0c, buffer(14,1))
			return
		end
--		&0D: Set random access information
		if fs_func== 0x0D then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.filehandle,   buffer(13,1))
			data_subtree:add_le(aun.fields.fs_subfunc0d, buffer(14,1))
			data_subtree:add_le(aun.fields.offset,       buffer(15,3))
			return
		end
--		&0E: Read disc information
		if fs_func== 0x0E then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.startat,      buffer(13,1))
			data_subtree:add_le(aun.fields.items,        buffer(14,1))
			return
		end
--		&0F: Read current users
		if fs_func== 0x0F then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.startat,      buffer(13,1))
			data_subtree:add_le(aun.fields.items,        buffer(14,1))
			return
		end
--		&10: Read date and time
		if fs_func== 0x11 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			return
		end
--		&11: Read EOF status
		if fs_func== 0x11 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.filehandle,   buffer(13,1))
			return
		end
--		&12: Read object information
		if fs_func== 0x12 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.fs_subfunc12, buffer(13,1))
			data_subtree:add_le(aun.fields.dirname,      buffer(14,size-14))
			return
		end
--		&13: Set object attributes
		if fs_func== 0x13 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.fs_subfunc13, buffer(13,1))
-- 		TODO: print attributes correctly
			data_subtree:add_le(aun.fields.data,         buffer(14,size-14))
			return
		end
--		&14: Delete object
		if fs_func== 0x14 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.objectname,   buffer(13,1))
			return
		end
--		&15: Read user environment
		if fs_func== 0x15 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			return
		end
--		&16: Set user boot option
		if fs_func== 0x16 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.bootoption,   buffer(13,1))
			return
		end
--		&17: Log off
		if fs_func== 0x17 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			return
		end
--		&18: Read user information
		if fs_func== 0x18 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.username,     buffer(13,size-13))
			return
		end
--		&19: Read fileserver version number
		if fs_func== 0x19 then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			return
		end
--		&1A: Read fileserver free space
		if fs_func== 0x1A then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.filename,     buffer(13,size-13))
			return
		end
--		&1B: Create directory
		if fs_func== 0x1B then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.blocks,       buffer(13,1))
			data_subtree:add_le(aun.fields.filename,     buffer(14,size-14))
			return
		end
--		&1C: Set real time clock
		if fs_func== 0x1C then
			local date = buffer(13,2):uint()
			local time = buffer(15,3):uint()

			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add(buffer(13,2), "Date: " .. get_date(date))
			data_subtree:add(buffer(15,3), "Time: " .. get_time(time))
			return
		end
--		&1E: Read user free space
		if fs_func== 0x1E then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.username,     buffer(13,size-13))
			return
		end
--		&1F: Set user free space
		if fs_func== 0x1F then
			data_subtree:add_le(aun.fields.urd,          buffer(10,1))
			data_subtree:add_le(aun.fields.csd,          buffer(11,1))
			data_subtree:add_le(aun.fields.lib,          buffer(12,1))
			data_subtree:add_le(aun.fields.loadaddr,     buffer(13,4))
			data_subtree:add_le(aun.fields.username,     buffer(17,size-17))
			return
		end
--		&40: Read account information
		if fs_func== 0x40 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add_le(aun.fields.fs_subfunc40, buffer(13,1))
			data_subtree:add_le(aun.fields.firstaccount, buffer(14,2))
			data_subtree:add_le(aun.fields.maxaccounts,  buffer(16,2))
			data_subtree:add_le(aun.fields.discnumber,   buffer(18,1))

			return
		end
--		&41: Read/write system information
		if fs_func== 0x41 then
			local subfunc = buffer(13,1):le_uint()

			data_subtree:add_le(aun.fields.fs_subfunc41, buffer(13,1))
			data_subtree:add_le(aun.fields.data,         buffer(14,size-14))
			return
		end
--		&xx: Unknown file server function
		data_subtree:add_le(aun.fields.data,                 buffer(10,size-10))
		return
	end

--	Port &9C: Bridge
	if port == 0x9C then
		data_subtree:add_le(aun.fields.bridgetype,   buffer(2,1))

		if ctrl == 0x00 or ctrl == 0x01 or ctrl == 0x02 or ctrl == 0x03 then
			data_subtree:add_le(aun.fields.identifier,   buffer(8,6))
			data_subtree:add_le(aun.fields.replyport,    buffer(14,1))
			data_subtree:add_le(aun.fields.data,         buffer(15,size-15))
			return
		else
			data_subtree:add_le(aun.fields.data,         buffer(8,size-8))
			return
		end
	end

--	Port &9E: PrinterServerEnquiryReply
	if port == 0x9E then
		data_subtree:add_le(aun.fields.printerstatus,        buffer(8,1))
		data_subtree:add_le(aun.fields.station,              buffer(9,1))
		data_subtree:add_le(aun.fields.network,              buffer(10,1))
		data_subtree:add_le(aun.fields.data,                 buffer(14,size-14))
		return
	end

--	Port &D2: TCPIPOverEconet
	if port == 0xD2 then
		data_subtree:add_le(aun.fields.tcpiptype,            buffer(2,1))
		data_subtree:add_le(aun.fields.data,                 buffer(8,size-8))
		return
	end
--	Port &xx: Unknown port
	data_subtree:add_le(aun.fields.data,         buffer(8,size-8))
end

function get_date(value)
-- TODO: date translation
	return string.format("%i/%i/%i;", value(0,1), value(1,1), value(1,1))
end

function get_time(value)
	return string.format("%i:%i:%i", value(0,1), value(1,1), value(2,1))
end



udp_table = DissectorTable.get("udp.port")
udp_table:add(32768,aun)
