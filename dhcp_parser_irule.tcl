when CLIENT_ACCEPTED {
  set VER "-"
  set RST 0
}

when CLIENT_DATA {
  binary scan [UDP::payload] H2H16 public_flag CID

  switch $public_flag {
    "0c" {
      # Version: No, Reset: No, CID Len: 8 bytes, Seq Len: 1 byte
      binary scan [UDP::payload] x9H2a* SEQ_HEX data
    }
    "0d" {
      # Version: Yes, Reset: No, CID Len: 8 bytes, Seq Len: 1 byte      
      binary scan [UDP::payload] x9a4H2a* VER SEQ_HEX data
    }
    "0e" {
      # Version: No, Reset: Yes, CID Len: 8 bytes, Seq Len: 1 byte
      binary scan [UDP::payload] x9H2a* SEQ_HEX data
      set RST 1      
    }
  }

  # Convert Hexadecimal Sequence Number into Deciman (Integer)
  set SEQ  [expr { "0x$SEQ_HEX" } ]

  log local0. "SRC:[IP::remote_addr]:[UDP::remote_port], DST:[IP::local_addr][UDP::local_port], LEN:[UDP::payload length], CID:$CID, SEQ:$SEQ, VER:$VER, RST:$RST"

  if { [string length $data] == 1336 }{
    set padding 0
    for {set offset 0} {$offset < [string length $data]} {incr offset 16} {
      binary scan $data x[expr $offset]H16 MSG
      if { $MSG == "2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d" }{
        set padding 1
      } else {
        if { $padding == 1 }{ break }
      }
     log local0. "$offset\t\t$MSG"
    }
  }
}
