f5 irule for parsing DHCP (BOOTP) payload
=====================

An iRule to parse DHCP packet to extract option field into session table for log enrichment and traffic steering.

## Description

Rule to demonstrate how tocapture and binary scan UDP payload and store them into session table for logging enrichment and intelligent traffic steering decision. 

* All the optin and value is stored into following session table.

    ```[tabe set -subtable <your_ip_addr> <option> <value>]```
    
## How to use
The rule requires virtual server to listen on DHCP traffic in the middle either in inline or out of band.

1. Change DB key 

   ```tmsh modify sys db vlangroup.forwarding.override value disable```

2. In-Line to DHCP traffic

    ```
    profile udp udp_dhcp {
        allow-no-payload disabled
        app-service none
        datagram-load-balancing disabled
        idle-timeout immediate
        ip-tos-to-client 0
        link-qos-to-client 0
        proxy-mss disabled
    }

    ltm virtual vs_dhcp {
        destination 0.0.0.0:bootps
        ip-protocol udp
        mask any
        profiles {
            udp_dhcp { }
        } 
        rules {
            dhcp_sampler
        }
        source 0.0.0.0/0
        translate-address disabled
        vlans {
            local
        }
        vlans-enabled
    }
    ```

3. Receiving mirrored DHCP stream

    TBA

## Sample Log

```
 [dhcp_sampler-0.1](10.1.101.200)(debug) Option:53(0x35) (1) DHCP_INFORM(0x08)
 [dhcp_sampler-0.1](10.1.101.200)(debug) Option:61(0x3d) (7) 00:50:56:b9:38:74(0x01005056b93874)
 [dhcp_sampler-0.1](10.1.101.200)(debug) Option:12(0x0c) (7) shun-PC(0x7368756e2d5043)
 [dhcp_sampler-0.1](10.1.101.200)(debug) Option:60(0x3c) (8) MSFT 5.0(0x4d53465420352e30)
 [dhcp_sampler-0.1](10.1.101.200)(debug) Option:55(0x37) (13) (0x010f03062c2e2f1f2179f92bfc)
```

## Reference

* RFC 2132 DHCP Options and BOOTP Vendor Extensions
* RFC 1533 DHCP Options and BOOTP Vendor Extensions (Obsolated)
* RFC 4702 The Dynamic Host Configuration Protocol (DHCP) Client Fully Qualified Domain Name (FQDN) Option
