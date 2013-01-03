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
timing off
when CLIENT_ACCEPTED priority 100 {

  # Rule Name and Version shown in the log
  set static::RULE_NAME "Simple DHCP Option Sampler v0.1"
  set static::RULE_ID   "dhcp_sampler-0.1"
  
  # 0: No Debug Logging 1: Debug Logging
  set DBG 1
  
  # Using High-Speed Logging in thie rule
  set log_prefix   "\[$static::RULE_ID\]([IP::client_addr])"
  set log_prefix_d "$log_prefix\(debug\)"
  
  if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: $static::RULE_NAME executed *****"}

}


when CLIENT_DATA {

  if { [UDP::payload length] < 200 } { 
    log local0.info "$log_prefix Ignored due to length\(less than 200 octet\)" 
    drop 
    return 
  } else { 
    # Omit first 240 octet of UDP payload for extracting DHCP
    # options field 
    binary scan [UDP::payload] x240H* dhcp_option_payload 

    if {$DBG}{log local0.debug "$log_prefix_d Options Field(raw_hex):0x$dhcp_option_payload"}
    
    # extract out circuit_id 
    set option_hex 0 
    set options_length [expr {([UDP::payload length] -240) * 2 }] 

    for {set i 0} {$i < $options_length} {incr i [expr { $length * 2 + 2 }]} { 

      # extract option value and convert into decimal
      # for human readability
      binary scan $dhcp_option_payload x[expr $i]a2 option_hex
      set option [expr 0x$option_hex]
      

      # move index to get length field 
      incr i 2 

      #extract length value and convert length from Hex string to decimal 
      binary scan $dhcp_option_payload x[expr $i]a2 length_hex 
      set length [expr 0x$length_hex]

      binary scan $dhcp_option_payload x[expr $i + 2]a[expr { $length * 2 }] value_hex

      if {$DBG}{log local0.debug "Option:$option\(0x$option_hex\)\($length\) $value_hex"} 

      switch $option {
        
        50 { 
        # Requested IP Address
        # This option is used in a client request (DHCPDISCOVER) to allow the
        # client to request that a particular IP address be assigned.
          scan $value_hex %2x%2x%2x%2x a b c d  
          set value "$a.$b.$c.$d"
          log local0. "50 - $value"
        }
        
        53 { 
        # DHCP Message Type
        # This option is used to convey the type of the DHCP message.
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
          log local0. "53 - $value"
        }
        
        61 { 
        # Client Identifier
        # This option is used by DHCP clients to specify their unique
        # identifier.  DHCP servers use this value to index their database of
        # address bindings.  This value is expected to be unique for all
        # clients in an administrative domain.
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
          log local0. "$value"
        }
        
        255 { 
        # End Option
        # The end option marks the end of valid information in the vendor
        # field.  Subsequent octets should be filled with pad options.
          return
        }
      }
    }
  } 
}
