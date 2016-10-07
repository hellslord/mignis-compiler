type config           =  firewall list

and firewall          =  Firewall of (option list) *
                                     (interface list) *
                                     (alias list) *
                                     (rule list) *
                                     (policy list) *
                                     (custom list)
                                    
and option            = Option of id * id
                                    
and  interface        = Interface of id * id * net_ip

and alias             = Hostalias of id * host_ip
                      | Netalias of id * net_ip

and rule              = op

and policy            = Default of pop * endpoint * endpoint * protocol

and custom            = crule

and endpoint          = Name of id * ifc * port
                      | Ip of host_ip * ifc * port
                      | Local of port
                      | Star
        
and ifc               = Noif
                      | If of id

and nat               = Nat of endpoint
                      | Masquerade
                      | Nonat

and op                = Allow of endpoint * nat * 
                                 nat * endpoint * 
                                 protocol *
                                 formula
                      | Twallow of endpoint * nat * 
                                   nat * endpoint * 
                                   protocol *
                                   formula
                      | Drop of endpoint * nat * 
                                nat * endpoint * 
                                protocol *
                                formula
                      | Reject of endpoint * nat * 
                                  nat * endpoint * 
                                  protocol *
                                  formula

and pop               = Pdrop
                      | Preject

and protocol          = Tcp
                      | Udp
                      | Icmp
                      | Noprotocol

and formula           = Formula of crule
                      | Noformula

and id = string
and crule = string
and net_ip = string
and host_ip = string
and port = int