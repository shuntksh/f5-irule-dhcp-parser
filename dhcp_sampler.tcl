#
# DHCP Option Field Sampler rev 0.2 (2013/01/03)
#
#   Written By:  Shunsuke Takahashi (s.takahashi at f5.com)
#
#   Original By: Jun Chen (j.chen at f5.com)
#   Original At: https://devcentral.f5.com/community/group/aft/25727/asg/50
#
#   Description: Capture DHCP traffic and create user table 
#
#                [tabe set -subtable dhcp-<framed-ip> <option> <value>]
#                                                   
#
#   Information: 
#
#
#
#   Requirement: 
#
#
#   Reference:   RFC 2132 DHCP Options and BOOTP Vendor Extensions
#                RFC 1533 DHCP Options and BOOTP Vendor Extensions (Obsolated)
#                RFC 4702 The Dynamic Host Configuration Protocol (DHCP) Client
#                         Fully Qualified Domain Name (FQDN) Option
#
#
timing off
when RULE_INIT {

	# Rule Name and Version shown in the log
	set static::RULE_NAME "Simple DHCP Option Sampler v0.1"
	set static::RULE_ID   "dhcp_sampler-0.1"
	
	# 0: No Debug Logging 1: Debug Logging
	set DBG 1
	
	# Using High-Speed Logging in thie rule
	set log_prefix   "\[$static::RULE_ID\]([IP::client_addr])"
	set log_prefix_d "$log_prefix\(debug\)"

}


when CLIENT_DATA {

	if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: $static::RULE_NAME executed *****"}

	if { [UDP::payload length] < 200 } { 
		log local0.info "$log_prefix Not a DHCP packet\(less than 200 octet\)" 
		drop 
		return 
	} else { 
		# Omit first 240 octet of UDP payload for extracting DHCP
		# options field 
		binary scan [UDP::payload] x240H* dhcp_option_payload 
		
		set option_hex 0 
		set options_length [expr {([UDP::payload length] -240) * 2 }] 

		for {set i 0} {$i < $options_length} {incr i [expr { $length * 2 + 2 }]} { 

			# extract option value and convert into decimal
			# for human readability
			binary scan $dhcp_option_payload x[expr $i]a2 option_hex
			set option [expr 0x$option_hex]
			
			# move index to get length field 
			incr i 2 

			# extract length value and convert length from Hex string to decimal	
			binary scan $dhcp_option_payload x[expr $i]a2 length_hex 
			set length [expr 0x$length_hex]

			# extract value filed in hexadecimal format
			binary scan $dhcp_option_payload x[expr $i + 2]a[expr { $length * 2 }] value_hex

			set value ""
			switch $option {
				
				12 {
				#
				# Host Name
				#
				# This option specifies the name of the client.  The name may or may
        # not be qualified with the local domain name.
				#
				#    Code   Len                 Host Name
				#   +-----+-----+-----+-----+-----+-----+-----+-----+--
				#   |  12 |  n  |  h1 |  h2 |  h3 |  h4 |  h5 |  h6 |  ...
				#   +-----+-----+-----+-----+-----+-----+-----+-----+--
				#
				for {set j 0} {$j < [expr ($length * 2)]} {incr j 2} {
					set temp_hex [string range $value_hex $j [expr {$j + 1}]]
					set temp_ascii [binary format c* [expr 0x$temp_hex]]
					append value $temp_ascii
				}
				}
				
				50 { 
				#
				# Requested IP Address
				#
				# This option is used in a client request (DHCPDISCOVER) to allow the
				# client to request that a particular IP address be assigned.
				#
				#    Code   Len          Address
				#   +-----+-----+-----+-----+-----+-----+
				#   |  50 |  4  |  a1 |  a2 |  a3 |  a4 |
				#   +-----+-----+-----+-----+-----+-----+
				#
				scan $value_hex %2x%2x%2x%2x a b c d  
				set value "$a.$b.$c.$d"
				}
				
				53 { 
				#
				# DHCP Message Type
				#
				# This option is used to convey the type of the DHCP message.
				#
				#    Code   Len  Type
				#   +-----+-----+-----+
				#   |  53 |  1  | 1-7 |
				#   +-----+-----+-----+
				#
				switch $value_hex {
					01 { set value "DHCP_DISCOVER" }
					02 { set value "DHCP_OFFER" }
					03 { set value "DHCP_REQUEST" }
					04 { set value "DHCP_DECLINE" }
					05 { set value "DHCP_ACK" }
					06 { set value "DHCP_NAK" }
					07 { set value "DHCP_RELEASE" }
					08 { set value "DHCP_INFORM" }
					default { set value "NO_MATCH\($value_hex\)" }
				}
				}
				
				54 {
				#
				# DHCP Server Identifier
				#
				# This option is used in DHCPOFFER and DHCPREQUEST messages, and may
				# optionally be included in the DHCPACK and DHCPNAK messages.  DHCP
				# servers include this option in the DHCPOFFER in order to allow the
				# client to distinguish between lease offers
				#
				#    Code   Len            Address
				#  +-----+-----+-----+-----+-----+-----+
				#  |  54 |  4  |  a1 |  a2 |  a3 |  a4 |
				#  +-----+-----+-----+-----+-----+-----+
				#
				scan $value_hex %2x%2x%2x%2x a b c d  
				set value "$a.$b.$c.$d"
				}
				
				60 {
				#
				# Vendor Class Identifier
				#
				# This option is used by DHCP clients to optionally identify the type
				# and configuration of a DHCP client.  The information is a string of n
				# octets, interpreted by servers.  Vendors and sites may choose to
				# define specific class identifiers to convey particular configuration
				# or other identification information about a client.
				#
				#   Code   Len   Class-Identifier
				#  +-----+-----+-----+-----+---
				#  |  60 |  n  |  i1 |  i2 | ...
				#  +-----+-----+-----+-----+---
				#
				for {set j 0} {$j < [expr ($length * 2)]} {incr j 2} {
					set temp_hex [string range $value_hex $j [expr {$j + 1}]]
					set temp_ascii [binary format c* [expr 0x$temp_hex]]
					append value $temp_ascii
				}
				}
				
				61 { 
				#
				# Client Identifier
				#
				# This option is used by DHCP clients to specify their unique
				# identifier.  DHCP servers use this value to index their database of
				# address bindings.  This value is expected to be unique for all
				# clients in an administrative domain.
				#
				#   Code   Len   Type  Client-Identifier
				#   +-----+-----+-----+-----+-----+---
				#   |  61 |  n  |  t1 |  i1 |  i2 | ...
				#   +-----+-----+-----+-----+-----+---
				#
				binary scan $value_hex a2a* htype id
				switch $htype {
					01 {
						# Ethernet (MAC format)
						binary scan $id a2a2a2a2a2a2 m(a) m(b) m(c) m(d) m(e) m(f)
						set value "$m(a):$m(b):$m(c):$m(d):$m(e):$m(f)"
					} 
					
					default {
						set value "$id"
					}
				}
				}
				
				81 {
				#
				# Client Fully Qualified Domain Name
				#
				# To update the IP address to FQDN mapping a DHCP server needs to know
				# the FQDN of the client to which the server leases the address.  To
				# allow the client to convey its FQDN to the server this document
				# defines a new DHCP option, called "Client FQDN".  The Client FQDN
				# option also contains Flags, which DHCP servers can use to convey
				# information about DNS updates to clients, and two deprecated RCODEs.
				#
				#   Code   Len    Flags  RCODE1 RCODE2   Domain Name
				#   +------+------+------+------+------+------+--
				#   |  81  |   n  |      |      |      |       ...
				#   +------+------+------+------+------+------+--
				#
				#   The format of the 1-octet Flags field is:
				#
				#        0 1 2 3 4 5 6 7
				#       +-+-+-+-+-+-+-+-+
				#       |  MBZ  |N|E|O|S|
				#       +-+-+-+-+-+-+-+-+
				#
				
				
				
				}
				
				255 { 
				#
				# End Option
				#
				# The end option marks the end of valid information in the vendor
				# field.  Subsequent octets should be filled with pad options.
				#
				return	
				}
			}
		
			if {$DBG}{log local0.debug "$log_prefix_d Option:$option\(0x$option_hex\)\
				\($length\) $value\(0x$value_hex\)"}	
		}
	} 
	
	if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: $static::RULE_NAME competed *****"}
}
