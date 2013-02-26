#
# DHCP Option Field Parser rev 0.3 (2013/02/25)
#
#   Written By:  Shun Takahashi (s.takahashi at f5.com)
#
#   Original By: Jun Chen (j.chen at f5.com)
#   Original At: https://devcentral.f5.com/community/group/aft/25727/asg/50
#
#   Description: iRule to demonstrate how tocapture and binary scan UDP payload
#                and store them into session table for logging enrichment and
#                intelligent traffic steering decision. 
#
#                RFC2131 defines DHCP packet structure. This irule is to scan 
#                UDP payload and store information into session tables with
#                your_ip as a key.
#
#                All the optin and value is stored into following session table.
#
#                          [tabe set -subtable <your_ip_addr> <option> <value>]
#                                                   
#   Requirement: The rule requires virtual server to listen on DHCP traffic in the
#                middle either in inline or out of band.
#
#                1) In-Line to DHCP traffic
#
#                          profile udp udp_dhcp {
#                              allow-no-payload disabled
#                              app-service none
#                              datagram-load-balancing disabled
#                              idle-timeout immediate
#                              ip-tos-to-client 0
#                              link-qos-to-client 0
#                              proxy-mss disabled
#                          }
#
#                          ltm virtual vs_dhcp {
#                              destination 0.0.0.0:bootps
#                              ip-protocol udp
#                              mask any
#                              profiles {
#                                  udp_dhcp { }
#                              } 
#                              rules {
#                                  dhcp_sampler
#                              }
#                              source 0.0.0.0/0
#                              translate-address disabled
#                              vlans {
#                                  local
#                              }
#                              vlans-enabled
#                          }
#
#                2) Receiving mirrored DHCP stream
#
#   References:  RFC 2132 DHCP Options and BOOTP Vendor Extensions
#                RFC 1533 DHCP Options and BOOTP Vendor Extensions (Obsolated)
#                RFC 4702 The Dynamic Host Configuration Protocol (DHCP) Client
#                         Fully Qualified Domain Name (FQDN) Option
#
timing off
when CLIENT_ACCEPTED priority 100 {

    # Rule Name and Version shown in the log
    set static::RULE_NAME "Simple DHCP Parser v0.3"
    set static::RULE_ID   "dhcp_parser"
    
    # 0: No Debug Logging 1: Debug Logging
    set DBG 1
    
    # Using High-Speed Logging in thie rule
    set log_prefix   "\[$static::RULE_ID\]([IP::client_addr])"
    set log_prefix_d "$log_prefix\(debug\)"
 
}


when CLIENT_DATA {

    if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: \
        $static::RULE_NAME executed *****"}

    if { [UDP::payload length] < 200 } { 
        log local0.info "$log_prefix Ignored due to length\(less than 200 octet\)" 
        drop 
        return 
    } else { 
        # BOOTP
        binary scan [UDP::payload] ccccH8SB1xa4a4a4a4H2H2H2H2H2H2 \
            msg_type hw_type hw_len hops transaction_id seconds\
            bootp_flags client_ip_hex your_ip_hex server_ip_hex \
            relay_ip_hex m(a) m(b) m(c) m(d) m(e) m(f)

        # Put client address into variables for session key
        set your_ip [IP::addr $your_ip_hex mask 255.255.255.255]
        set client_mac "$m(a):$m(b):$m(c):$m(d):$m(e):$m(f)"
        
        binary scan [UDP::payload] H32H64H128H8 \
            padding server_host_name boot_file magic_cookie
        
        if {$DBG}{log local0.debug "$log_prefix_d  BOOTP: $your_ip $client_mac"}

        # DHCP
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
                # Host Name
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
                
                15 {
                # Domain Name
                # This option specifies the domain name that client should use when
                # resolving hostnames via the Domain Name System.
                #
                #    Code   Len        Domain Name
                #   +-----+-----+-----+-----+-----+-----+--
                #   |  15 |  n  |  d1 |  d2 |  d3 |  d4 |  ...
                #   +-----+-----+-----+-----+-----+-----+--
                #
                    for {set j 0} {$j < [expr ($length * 2)]} {incr j 2} {
                        set temp_hex [string range $value_hex $j [expr {$j + 1}]]
                        set temp_ascii [binary format c* [expr 0x$temp_hex]]
                        append value $temp_ascii
                    }
                }
                
                50 { 
                # Requested IP Address
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
                # DHCP Message Type
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
                # DHCP Server Identifier
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
                # Vendor Class Identifier
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
                # Client Identifier
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
                    binary scan $value_hex a2a* ht id
                    switch $ht {
                        01 {
                            binary scan $id a2a2a2a2a2a2 m(a) m(b) m(c) m(d) m(e) m(f)
                            set value "$m(a):$m(b):$m(c):$m(d):$m(e):$m(f)"
                        } 
                        
                        default {
                            set value "$id"
                        }
                    }
                }
                
                81 {
                # Client Fully Qualified Domain Name
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
                # extract the length for suboption, and convert the length from Hex string to decimal 

                    binary scan $value_hex ccca* flags rcode1 rcode2 domain_name
                    set value $domain_name
                }
                
                82 {
                # Relay Agent Information Option
                # This document defines a new DHCP Option called the Relay Agent
                # Information Option.  It is a "container" option for specific agent-
                # supplied sub-options.  The format of the Relay Agent Information
                # option is:
                #
                #   Code   Len     Agent Information Field
                #   +------+------+------+------+------+------+--...-+------+
                #   |  82  |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
                #   +------+------+------+------+------+------+--...-+------+
                #
                # The length N gives the total number of octets in the Agent
                # Information Field.  The Agent Information field consists of a
                # sequence of SubOpt/Length/Value tuples for each sub-option, encoded
                # in the following manner:
                #
                #    SubOpt  Len     Sub-option Value
                #    +------+------+------+------+------+------+--...-+------+
                #    |  1   |   N  |  s1  |  s2  |  s3  |  s4  |      |  sN  |
                #    +------+------+------+------+------+------+--...-+------+
                #    SubOpt  Len     Sub-option Value
                #    +------+------+------+------+------+------+--...-+------+
                #    |  2   |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
                #    +------+------+------+------+------+------+--...-+------+
                #
                #   The initial assignment of DHCP Relay Agent Sub-options is as follows:
                #
                #        DHCP Agent              Sub-Option Description
                #        Sub-option Code
                #        ---------------         ----------------------
                #            1                   Agent Circuit ID Sub-option
                #            2                   Agent Remote ID Sub-option
                #
                #   Current Version Only Extracts Circuit ID Sub-option value        
                    set sub1 [string range $value_hex 0 1]
                    set sub1_len_hex [string range $value_hex 2 3]
                    set sub1_length [expr 0x$sub1_len_hex]
                    set sub1_value_hex [string range $value_hex 4 [expr {($sub1_length+2)*2-1}]]
                    for {set j 0} {$j < [expr ($sub1_length * 2)]} {incr j 2} {
                        set temp_hex [string range $sub1_value_hex $j [expr {$j + 1}]]
                        set temp_ascii [binary format c* [expr 0x$temp_hex]]
                        append value $temp_ascii
                    }
                }
                
                255 { 
                # End Option
                # The end option marks the end of valid information in the vendor
                # field.  Subsequent octets should be filled with pad options.
                    break
                }
            }
            
            # Outputs
            table set -subtable $your_ip $option $value
            
            if {$DBG}{log local0.debug "$log_prefix_d Option:$option\(0x$option_hex\)\
                \($length\) $value\(0x$value_hex\)"}    
        }
    } 
    
    if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: $static::RULE_NAME competed *****"}
}