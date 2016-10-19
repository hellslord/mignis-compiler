__author__ = 'Alessio Zennaro'

from generic_engine import GenericEngine

''' This class allows for the translation from mignis to Juniper (JunOS)
    commands via the intermediate representation.
    See example_engine.py file for full documentation regarding the structure of
    the file/class.
'''


class JunosEngine(GenericEngine):

    # Parametric string used to generate rules
    STATIC_ROUTE = "set routing-options static route 0.0.0.0/0 next-hop {0}\n"

    DEL_INT = "delete interfaces {0}\n"
    DEL_POL = "delete security policies\n"
    DEL_NAT = "delete security nat\n"

    SET_INT = "set interfaces {0} unit 0 family inet address {1}\n"
    SET_ZONE = "set security zones security-zone {0} interfaces {1}\n"
    SET_AB = "set security zones security-zone {0} address-book address " + \
             "{1} {2}\n"
    SET_PPRO = "set security policies from-zone {0} to-zone {1} policy {2} " + \
               "match protocol {3}\n"
    SET_SPRT = "set security policies from-zone {0} to-zone {1} policy {2} " + \
               "match source-port {3}\n"
    SET_DPRT = "set security policies from-zone {0} to-zone {1} policy {2} " + \
               "match destination-port {3}\n"
    SET_PLCY = "set security policies from-zone {0} to-zone {1} policy {2} " + \
               "match source-address {3}\n" + \
               "{4}" + \
               "set security policies from-zone {0} to-zone {1} " + \
               "policy {2} match destination-address {5}\n" + \
               "{6}" + \
               "{7}" + \
               "set security policies from-zone {0} to-zone {1} policy {2} " + \
               "then {8}\n"
    SET_RULE = "set firewall family inet filter {0} term 0 from " + \
               "source-address {1}\n" + \
               "{2}" + \
               "{3}" + \
               "set firewall family inet filter {0} term 0 then accept\n" + \
               "set firewall family inet filter {4} term 0 from " + \
               "destination-address {5}\n" + \
               "{6}" + \
               "{7}" + \
               "set firewall family inet filter {4} term 0 then accept\n"
    SET_RSPR = "set firewall family inet filter {0} term 0 from " + \
               "source-port {1}\n"
    SET_RDPR = "set firewall family inet filter {0} term 0 from " + \
               "destination-port {1}\n"
    SET_RPRO = "set firewall family inet filter {0} term 0 from " + \
               "protocol {1}\n"

    INT_IADD = "set interfaces {0} unit 0 family inet filter input-list {1}\n"
    INT_OADD = "set interfaces {0} unit 0 family inet filter output-list {1}\n"

    NAT_SNAT = "set security nat source rule-set {0} from zone {1}\n" + \
               "set security nat source rule-set {0} to zone {2}\n" + \
               "set security nat source rule-set {0} rule {3} " + \
               "match source-address {4}\n" + \
               "set security nat source rule-set {0} rule {3} " + \
               "match destination-address {5}\n" + \
               "set security nat source rule-set {0} rule {3} " + \
               "then source-nat {6}\n"
    NAT_DNAT = "set security nat destination rule-set {0} rule {1} " + \
               "match destination-address {2}\n" + \
               "set security nat destination rule-set {0} rule {1} " + \
               "match destination-port {3}\n" + \
               "set security nat destination rule-set {0} rule {1} then " + \
               "destination-nat pool {4}\n"

    NAT_POOL = "set security nat {0} pool {1} address {2}\n" + \
               "set security nat {0} pool {1} port {3}\n"

    ACT_DISC = "discard"
    ACT_RJCT = "reject"
    ACT_PRMT = "permit"

    NAT_MSQR = "interface"
    NAT_NPRT = "no-translation"

    DST_PORT = "destination-port"
    SRC_PORT = "source-port"

    SOURCE = "source"
    DESTINATION = "destination"

    SW_S_PORT = [(SRC_PORT, DST_PORT)]
    SW_D_PORT = [(DST_PORT, SRC_PORT)]

    ''' Constructor '''
    def __init__(self, directory):
        GenericEngine.__init__(self, directory)
        self.language = "junos"
        self.address_book = [{"ip" : "0.0.0.0/0", "name" : "any"}]

    ''' Ok, let's do the job! '''
    def translate(self, configuration):
        static_route = ""  # For the static route option
        reset_int = ""  # Reset interfaces
        bindings = ""  # Interfaces bounds
        zones = ""  # Security zones
        adbook = ""  # Address book
        policies = ""  # Policies
        rules = ""  # Rules
        nat = ""  # NAT
        pools = ""  # Address pools

        ep_counter = 0  # Counter for the endpoints
        pl_counter = 0  # Counter for the policy rules
        ri_counter = 0  # Counter for the input filters
        ro_counter = 0  # Counter for the output filters
        rs_counter = 0  # Counter for the nat rule set
        po_counter = 0  # Counter for the address pools

        # Ok, these are all the lines in the intermediate representation
        lines = configuration.split('\n')

        # BETA
        print("WARNING: JUNOS LANGUAGE SUPPORT IS STILL IN BETA")
        print("Check the rules before setting up your Juniper appliance.")

        for l in lines:  # For each line
            if l == "":
                continue

            parsed = self.parse_line(l)  # Parse it

            if parsed[0] == self.OPTN:  # If the line is an OPTN
                if parsed[1][0] == "static_route":  # static_route
                    ip = self.create_ip(parsed[1][1])
                    if ip != "":  # If a valid IP is given
                        # The static route string is activated
                        static_route = self.STATIC_ROUTE.format(ip)
                else:
                    print("WARNING: Unknown option %s" % parsed[1][0])
            elif parsed[0] == self.BIND:  # If the line is BIND
                # We get the interface name
                interface_name = self.create_interface_name(parsed[1][0])
                # We reset the interface name
                reset_int += self.DEL_INT.format(interface_name)
                # We bind the interface name to the address
                bindings += self.SET_INT.format(interface_name, parsed[1][1])
                # We also set security zones
                zones += self.SET_ZONE.format(parsed[1][0],
                                              interface_name + ".0")
            # DROP and RJCT are not actually needed since they are not allowed
            # in Mignis+. However, to catch this exception we must enter this
            # branch if a DROP or RJCT is present.
            elif parsed[0] == self.ALLW or \
                    parsed[0] == self.DROP or \
                    parsed[0] == self.RJCT or \
                    parsed[0] == self.TALW:
                #We need the rule details
                rule_detail = self.get_rule_details(parsed[1])

                # JunOS firewall rules MUST be localized. Mignis+ is mandatory
                if rule_detail[0][1] == "" or rule_detail[2][1] == "":
                    print("FATAL: Rules in Juniper appliance must be " + \
                          "localized! Use Mignis+ syntax")
                    exit(-1)

                # We need the interfaces' names
                input_interface = self.create_interface_name(rule_detail[0][1])
                output_interface = self.create_interface_name(rule_detail[2][1])

                # Rules must have a name, we use counters
                input_name = "ri" + str(ri_counter)
                output_name = "ro" + str(ro_counter)
                ri_counter += 1
                ro_counter += 1

                # Is the rule related to a specific protocol?
                if rule_detail[4] == "ANY":
                    protocol_i = ""
                    protocol_o = ""
                else:
                    protocol_i = self.SET_RPRO.format(input_name,
                                                      rule_detail[4].lower())
                    protocol_o = self.SET_RPRO.format(output_name,
                                                      rule_detail[4].lower())

                # Source port
                if rule_detail[0][2] == "0":
                    source_port = ""
                else:
                    source_port = self.SET_RSPR.format(input_name,
                                                       rule_detail[0][2])

                # Destination protocol
                if rule_detail[2][2] == "0":
                    destination_port = ""
                else:
                    destination_port = self.SET_RDPR.format(output_name,
                                                     rule_detail[2][2])

                # Any source/destination address management
                if rule_detail[0][0] == "n-0.0.0.0/0":
                    source_addr = "any"
                else:
                    source_addr = rule_detail[0][0][2:]

                if rule_detail[2][0] == "n-0.0.0.0/0":
                    destination_addr = "any"
                else:
                    destination_addr = rule_detail[2][0][2:]

                # Rule generation
                rules += self.SET_RULE.format(input_name, source_addr,
                                              source_port, protocol_i,
                                              output_name, destination_addr,
                                              destination_port, protocol_o)
                bindings += self.INT_IADD.format(input_interface, input_name)
                bindings += self.INT_OADD.format(output_interface, output_name)

                # If the rule is two way allow, we must set another rule
                # with switched parameters!
                if parsed[0] == self.TALW:
                    # We set the new rules' names
                    new_i_name = "ri" + str(ri_counter)
                    new_o_name = "ro" + str(ro_counter)
                    ri_counter += 1
                    ro_counter += 1

                    # Names have to be switched
                    sw_names = [(input_name, new_i_name),
                                (output_name, new_o_name)]

                    # Switch all that must be switched!!
                    protocol_i = self.switch_elements(protocol_i, sw_names)
                    protocol_o = self.switch_elements(protocol_o, sw_names)
                    source_port = self.switch_elements(source_port,
                                                       self.SW_S_PORT + sw_names)
                    destination_port = self.switch_elements(destination_port,
                                                            self.SW_D_PORT + \
                                                             sw_names)

                    # Create the new rule
                    rules += self.SET_RULE.format(new_i_name, destination_addr,
                                                  source_port, protocol_i,
                                                  new_o_name, source_addr,
                                                  destination_port, protocol_o)

                    # And the new bounds
                    bindings += self.INT_IADD.format(output_interface,
                                                     new_i_name)
                    bindings += self.INT_OADD.format(input_interface,
                                                     new_o_name)

                # Nat must be considered only when the operator is the
                # one way allow
                if parsed[0] == self.ALLW:
                    # If a Masquerade has been requested
                    if rule_detail[1][0] == self.MASQUERADE:
                        set_name = "rs" + str(rs_counter)
                        rs_counter += 1
                        nat_name = "masquerade"

                        nat += self.NAT_SNAT.format(set_name, rule_detail[0][1],
                                                    rule_detail[2][1], nat_name,
                                                    rule_detail[0][0][2:],
                                                    rule_detail[2][0][2:],
                                                    self.NAT_MSQR)
                    # Regular source NAT
                    elif len(rule_detail[1][0]) > 1 \
                         and rule_detail[1][0][1] == '-':
                        pool_name = "pool" + str(po_counter)
                        po_counter += 1
                        set_name = "rs" + str(rs_counter)
                        rs_counter += 1
                        nat_name = "source-nat"

                        if rule_detail[1][2] == '0':
                            port = self.NAT_NPRT
                        else:
                            port = rule_detail[1][2]

                        pools += self.NAT_POOL.format(self.SOURCE, pool_name,
                                                      rule_detail[1][0][2:],
                                                      port)

                        nat += self.NAT_SNAT.format(set_name, rule_detail[0][1],
                                                    rule_detail[2][1], nat_name,
                                                    rule_detail[0][0][2:],
                                                    rule_detail[2][0][2:],
                                                    pool_name)
                    # Destination NAT
                    elif len(rule_detail[3][0]) > 1 \
                         and rule_detail[3][0][1] == '-':
                        pool_name = "pool" + str(po_counter)
                        po_counter += 1
                        set_name = "rs" + str(rs_counter)
                        rs_counter += 1
                        nat_name = "destination-nat"

                        if rule_detail[2][2] == '0':
                            port = self.NAT_NPRT
                        else:
                            port = rule_detail[2][2]

                        pools += self.NAT_POOL.format(self.DESTINATION,
                                                      pool_name,
                                                      rule_detail[2][0][2:],
                                                      port)

                        nat += self.NAT_DNAT.format(set_name, nat_name,
                                                    rule_detail[3][0][2:],
                                                    rule_detail[3][2],
                                                    pool_name)
            # Here we have the policies
            elif parsed[0] == self.PDRP or parsed[0] == self.PRJC:
                # JunOS firewall policies MUST be localized as well
                if parsed[1][1] == "" or parsed[1][4] == "":
                    print("FATAL: Policies in Juniper appliance must be " + \
                         "localized! Use Mignis+ syntax")
                # If the source endpoin has been never found before in the
                # configuration, then insert it in the address book
                # and declare it.
                if self.get_adbook_entry(parsed[1][0][2:]) == []:
                    # endpoint number
                    name = "ep" + str(ep_counter)
                    ep_counter += 1  # increment
                    self.address_book.append(  # Add the new entry
                        {
                            "ip"    :   parsed[1][0][2:],
                            "name"  :   name
                        }
                    )
                    # Declare it in the configuration
                    adbook += self.SET_AB.format(parsed[1][1], name,
                                                 parsed[1][0][2:])

                # Same thing for the destination endpoint
                if self.get_adbook_entry(parsed[1][3][2:]) == []:
                    # endpoint number
                    name = "ep" + str(ep_counter)
                    ep_counter += 1  # increment
                    self.address_book.append(  # Add the new entry
                        {
                            "ip"    :   parsed[1][3][2:],
                            "name"  :   name
                        }
                    )
                    # Declare it in the configuration
                    adbook += self.SET_AB.format(parsed[1][4], name,
                                                 parsed[1][3][2:])

                # Policy number
                p_number = "pr" + str(pl_counter)
                pl_counter += 1  # increment

                # Source node
                source = self.get_adbook_entry(parsed[1][0][2:])[0]['name']
                # Destination node
                destination = self.get_adbook_entry(parsed[1][3][2:])[0]['name']
                if parsed[1][2] == "0":  # Source port
                    sport = ""
                else:
                    sport = self.SET_SPRT.format(parsed[1][1], parsed[1][4],
                                                 p_number,
                                                 parsed[1][2])
                if parsed[1][5] == "0":  # Destination port
                    dport = ""
                else:
                    dport = self.SET_DPRT.format(parsed[1][1], parsed[1][4],
                                                 p_number,
                                                 parsed[1][5])
                if parsed[1][6] == "ANY": # Protocol matching
                    protocol = ""  # If no protocol is specified
                else:
                    # If a protocol is specified
                    protocol = self.SET_PPRO.format(parsed[1][1], parsed[1][4],
                                                    p_number,
                                                    parsed[1][6].lower())
                if parsed[0] == self.PDRP:  # Action: drop or reject?
                    action = self.ACT_DISC
                else:
                    action = self.ACT_RJCT

                # Ok: build the policy rule!!
                policies += self.SET_PLCY.format(parsed[1][1], parsed[1][4],
                                                 p_number, source, sport,
                                                 destination, dport,
                                                 protocol, action)
            # Custom rules, they are put after the policies... Use with cautions
            elif parsed[0] == self.CSTM:
                rules += parsed[1][0] + "\n"

        # The whole interface binding string
        interfaces = reset_int + bindings + static_route + zones
        # The whole policy string
        policies = adbook + self.DEL_POL + policies
        # The whole NAT string
        nats = self.DEL_NAT + pools + nat

        return rules + interfaces + policies + nats +  "commit\n"

    ''' Interfaces names in JunOS are called as xx-n/m/i (where xx are two
        letters, n m and i are numbers) but Mignis(+) syntax forbids the use
        of - and / in the identifiers. Interfaces' name must be written in the
        form xx_n_m_i.
        This method transforms underscores in the correct character
    '''
    def create_interface_name(self, interface):
        return \
            interface[0:2] + "-" + \
            interface[3] + "/" + \
            interface[5] + "/" + \
            interface[7]

    ''' Juniper could need to know where to route packets going to 0.0.0.0/0
        In order to allow this, an option with the static routing ip must be
        specified. Options allow only for identifiers so this syntax must be
        used: IP_XX_XX_XX_XX. Underscores must be replaced by dots
    '''
    def create_ip(selfself, address):
        toRet = ""
        if len(address) < 10 or  address[0:3] != "IP_":
            print("WARNING: illegal value for static_route option %s " % \
                  address[0:3])
        else:
            toRet = address[3:].replace('_', '.')

        return toRet

    ''' This method is used to extract the couple {ip, ab_entry} '''
    def get_adbook_entry(self, ip):
        # List comprehension approach
        return [item for item in self.address_book if item['ip'] == ip]