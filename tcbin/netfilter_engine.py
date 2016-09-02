__author__ = "Alessio Zennaro"

from generic_engine import GenericEngine

''' This class allows for the translation from mignis to netfilter/iptables
    via the intermediate representation.
    See example_engine.py file for full documentation regarding the structure of the file/class.
'''


class NetfilterEngine(GenericEngine):

    # Here all the iptables rule templates are defined in variables, to avoid the use of strings in the code.
    BASIC_FILTER = "*filter\n" + \
                   "-P INPUT DROP\n" + \
                   "-P FORWARD DROP\n" + \
                   "-P OUTPUT DROP\n{0}"
    BASIC_MANGLE = "*mangle\n" + \
                   "-P PREROUTING DROP\n"
    MANGLE_LO = "-A PREROUTING -i lo -j ACCEPT\n"
    BASIC_NAT = "*nat\n"
    DEFAULT_ESTABLISHED = "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n" + \
                          "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n" + \
                          "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n{0}"
    DEFAULT_FILTER = "-A INPUT -i lo -j ACCEPT -m comment --comment \"loopback (default rules)\"\n" + \
                     "-A INPUT -d 255.255.255.255 -j ACCEPT -m comment --comment \"broadcast (default r.)\"\n" + \
                     "-A INPUT -d 224.0.0.0/4 -j ACCEPT -m comment --comment \"multicast (default r.)\"\n"
    DEFAULT_MANGLE = "-A PREROUTING -m state --state INVALID,UNTRACKED -j DROP -m comment --comment \"inv. def.\"\n" + \
                     "-A PREROUTING -d 255.255.255.255 -j ACCEPT -m comment --comment \"default r.\"\n" + \
                     "-A PREROUTING -d 224.0.0.0/4 -j ACCEPT -m comment --comment \"default r.\"\n"
    LOGGING_FILTER = "-N filter_drop\n" + \
                     "-N filter_drop_icmp" + \
                     "-A filter_drop_icmp -j LOG --log-prefix \"DROP-icmp \"\n" + \
                     "-A filter_drop_icmp -j DROP\n" + \
                     "-A filter_drop -p icmp -j filter_drop_icmp\n" + \
                     "-N filter_drop_udp\n" + \
                     "-A filter_drop_udp -j LOG --log-prefix \"DROP-udp \"\n" + \
                     "-A filter_drop_udp -j DROP\n" + \
                     "-A filter_drop -p udp -j filter_drop_udp\n" + \
                     "-N filter_drop_tcp\n" + \
                     "-A filter_drop_tcp -j LOG --log-prefix \"DROP-tcp \"\n" + \
                     "-A filter_drop_tcp -j DROP\n" + \
                     "-A filter_drop -p tcp -j filter_drop_tcp\n" + \
                     "-A filter_drop -j LOG --log-prefix \"DROP-UNK \"\n" + \
                     "-A filter_drop -j DROP\n" + \
                     "-A INPUT -j filter_drop\n" + \
                     "-A OUTPUT -j filter_drop\n" + \
                     "-A FORWARD -j filter_drop\n"
    LOGGING_MANGLE = "-N mangle_drop\n" + \
                     "-N mangle_drop_icmp\n" + \
                     "-A mangle_drop_icmp -j LOG --log-prefix \"MANGLE-DROP-ICMP \"\n" + \
                     "-A mangle_drop_icmp -j DROP\n" + \
                     "-A mangle_drop -p icmp -j mangle_drop_icmp\n" + \
                     "-N mangle_drop_udp\n" + \
                     "-A mangle_drop_udp -j LOG --log-prefix \"MANGLE-DROP-UDP \"\n" + \
                     "-A mangle_drop_udp -j DROP\n" + \
                     "-A mangle_drop -p udp -j mangle_drop_udp\n" + \
                     "-N mangle_drop_tcp\n" + \
                     "-A mangle_drop_tcp -j LOG --log-prefix \"MANGLE-DROP-TCP \"\n" + \
                     "-A mangle_drop_tcp -j DROP\n" + \
                     "-A mangle_drop -p tcp -j mangle_drop_tcp\n" + \
                     "-A mangle_drop -j LOG --log-prefix \"MANGLE-DROP-UNK \"\n" + \
                     "-A mangle_drop -j DROP\n" + \
                     "-A PREROUTING -j mangle_drop\n"

    BIND_ACCEPT = "-A PREROUTING -i {0} -s {1} -j ACCEPT -m comment --comment \"{2}\"\n"
    BIND_ANY_ACCEPT = "-A PREROUTING -i {0} -j ACCEPT -m comment --comment \"{1}\"\n"
    BIND_ANY_DROP = "-A PREROUTING -i {0} -s {1} -j DROP -m comment --comment \"{2}\"\n"
    MANGLE_NAT = "-A PREROUTING {0} {1} {2} {3} {4} -m state --state NEW -j DROP -m comment --comment \"{5}\"\n"
    RULE_FWD = "-A FORWARD {0} {1} {2} {3} {4} {5} -j {6} -m comment --comment \"{7}\"\n"
    RULE_IN = "-A INPUT {0} {1} {2} {3} {4} -j {5} -m comment --comment \"{6}\"\n"
    RULE_OUT = "-A OUTPUT {0} {1} {2} {3} {4} -j {5} -m comment --comment \"{6}\"\n"
    RULE_MASQUERADE = "-A POSTROUTING {0} {1} {2} {3} {4} -j MASQUERADE -m comment --comment \"{5}\"\n"
    RULE_SNAT = "-A POSTROUTING {0} {1} {2} {3} {4} -j SNAT --to-source {5} -m comment --comment \"{6}\"\n"
    RULE_DNAT = "-A PREROUTING {0} {1} {2} {3} {4} -j DNAT --to-destination {5} -m comment --comment \"{6}\"\n"

    SOURCE_HOST = "-s "
    SOURCE_INTF = "-i "
    DESTINATION_HOST = "-d "
    DESTINATION_INTF = "-o "
    SPORT = "--sport "
    DPORT = "--dport "
    PROTOCOL = "-p "
    IPT_ACCEPT = "ACCEPT"
    IPT_DROP = "DROP"
    IPT_REJECT = "REJECT"

    # Variables (list of tuples) used in the switch_elements method. For each tuple the first element is substituted
    # with the second element
    SW_SOURCE = [("-i", "-o"), ("-s", "-d")]
    SW_DESTINATION = [("-o", "-i"), ("-d", "-s")]
    SW_SPORT = [("sport", "dport")]
    SW_DPORT = [("dport", "sport")]

    ''' Constructor '''
    def __init__(self, directory):
        GenericEngine.__init__(self, directory)
        self.language = "iptables"  # The language is iptables for Netfilter
        self.int_ip = []  # This dictionary list keeps track of the interface name with the corresponding net ip

    ''' Ok, let's do the job! '''
    def translate(self, configuration):
        # Default rules
        def_rul = True
        # Logging
        logging = True
        # Established
        estb = False
        # This string is used to implement all the bindings between interfaces and ips
        bindings = ""
        # This string is used to implement the filters (with basic rules)
        filters = self.BASIC_FILTER
        # This string is used to implement the NAT rules
        nat = self.BASIC_NAT
        # When an interface accepts any ip, the ips bound to other interfaces must be dropped to avoid overlaps.
        # This string keeps track of the infos useful to do such a thing
        bind_any_drop = self.BIND_ANY_DROP.format("{0}", "127.0.0.0/8", "{1}")
        # This string is used to set up the mangle rules for the NATs
        binding_nat = ""
        # This list keeps track of the interfaces that accept anything
        intfs = []

        # Ok, here we have all the conf lines
        lines = configuration.split('\n')
        for index, l in enumerate(lines):  # For all the lines
            if l == "":  # If the line is empty, simply continue
                continue

            parsed = self.parse_line(l)  # Parse the line

            if parsed[0] == self.OPTN:  # If the line is an OPTN
                # We manage the options by setting flags
                if parsed[1][0] == "default_rules":  # Default rules
                    if parsed[1][1] == "yes":
                        def_rul = True
                    elif parsed[1][1] == "no":
                        def_rul = False
                    else:
                        print("WARNING: Value for option '%s' not valid: %s" % (parsed[1][0], parsed[1][1]))
                elif parsed[1][0] == "logging":  # Logging
                    if parsed[1][1] == "yes":
                        logging = True
                    elif parsed[1][1] == "no":
                        logging = False
                    else:
                        print("WARNING: Value for option '%s' not valid: %s" % (parsed[1][0], parsed[1][1]))
                elif parsed[1][0] == "established":  # Established management
                    if parsed[1][1] == "yes":
                        estb = True
                    elif parsed[1][1] == "no":
                        estb = False
                    else:
                        print("WARNING: Value for option '%s' not valid: %s" % (parsed[1][0], parsed[1][1]))
                else:
                    print("WARNING: Unknown option %s" % parsed[1][0])
            elif parsed[0] == self.BIND:  # If the line is BIND
                if parsed[1][1] == "0.0.0.0/0":  # If an interface accepts anything
                    intfs.append(parsed[1][0])  # Remember it...
                else:  # If it is a "normal" interface
                    bindings += self.BIND_ACCEPT.format(parsed[1][0], parsed[1][1], l)  # We set the bound
                    bind_any_drop += self.BIND_ANY_DROP.format("{0}", parsed[1][1], "{1}")  # drops set enlarged
                self.int_ip.append(
                    {
                        "int_name": parsed[1][0],
                        "net_ip": parsed[1][1]
                    }
                )  # Keep track of the int name and ip
            elif parsed[0] == self.ALLW or \
                    parsed[0] == self.DROP or \
                    parsed[0] == self.RJCT or \
                    parsed[0] == self.TALW:  # If we're dealing with a firewall rule
                source = ""  # String for the source
                sport = ""  # String for the source port
                destination = ""  # String for the destination
                dport = ""  # String for the destination port
                protocol = self.PROTOCOL + "all"  # String for the protocol, the default case is "-p all"
                action = ""  # The action
                s_local = False  # Is there a local keyword in the source?
                d_local = False  # Is there a local keyword in the destination?

                # Let's begin: we get all the details from the rule
                rule_detail = self.get_rule_details(parsed[1])

                if rule_detail[0][1] != "" or rule_detail[2][1] != "":
                    print("Warning: Mignis+ interface specification not yet supported")

                if rule_detail[0][0][1] == '-':  # If there's an ip in the source, we set "-s <ip>"
                    source = self.SOURCE_HOST + rule_detail[0][0][2:]
                elif rule_detail[0][0] == self.LOCAL:  # If there's a local il the source field, we set the flag
                    s_local = True
                elif rule_detail[0][0] != self.ANY:  # If there isn't a star in the source field we set "-i <intf>"
                    source = self.SOURCE_INTF + rule_detail[0][0]

                # Same for destination but with "-d" and "-o" instead of "-s" and "-i" respectively
                if rule_detail[2][0][1] == '-':
                    destination = self.DESTINATION_HOST + rule_detail[2][0][2:]
                elif rule_detail[2][0] == self.LOCAL:
                    d_local = True
                elif rule_detail[2][0] != self.ANY:
                    destination = self.DESTINATION_INTF + rule_detail[2][0]

                if rule_detail[0][2] != "0":  # Source port
                    sport = self.SPORT + rule_detail[0][2]
                if rule_detail[2][2] != "0":  # Destination port
                    dport = self.DPORT + rule_detail[2][2]

                if rule_detail[4] != self.ANY:  # If a protocol is specified, we set it with "-p <protocol"
                    protocol = self.PROTOCOL + rule_detail[4].lower()

                if parsed[0] == self.ALLW or parsed[0] == self.TALW:  # If the operator is > or <>
                    action = self.IPT_ACCEPT
                elif parsed[0] == self.DROP:  # /
                    action = self.IPT_DROP
                elif parsed[0] == self.RJCT:  # //
                    action = self.IPT_REJECT

                current_rule = ""  # The current rule
                if d_local and not s_local:  # If the destination is "local"
                    current_rule = self.RULE_IN.format(protocol, source, sport, dport, rule_detail[5], action, l)
                    if parsed[0] == self.TALW:  # <> needs to add a second rule with switched operands
                        source = self.switch_elements(source, self.SW_SOURCE)  # "-s" and "-i" becomes "-d" and "-o"
                        dport = self.switch_elements(dport, self.SW_DPORT)  # "--dport" becomes "--sport"
                        sport = self.switch_elements(sport, self.SW_SPORT)  # "--sport" becomes "--dport"
                        current_rule += self.RULE_OUT.format(protocol, dport, source, sport, rule_detail[5], action, l)
                if s_local and not d_local:  # If the source is "local"
                    current_rule = self.RULE_OUT.format(protocol, sport, destination, dport, rule_detail[5], action, l)
                    if parsed[0] == self.TALW:  # <>
                        destination = self.switch_elements(destination, self.SW_DESTINATION)
                        dport = self.switch_elements(dport, self.SW_DPORT)
                        sport = self.switch_elements(sport, self.SW_SPORT)
                        current_rule += \
                            self.RULE_IN.format(protocol, destination, dport, sport, rule_detail[5], action, l)
                if d_local and s_local:  # Weird case: source and destination are "local"... Here we need 127.0.0.0/8
                    lip = "127.0.0.0/8"
                    ldest = self.DESTINATION_HOST + lip
                    lsrc = self.SOURCE_HOST + lip
                    current_rule = self.RULE_OUT.format(protocol, sport, ldest, dport, rule_detail[5], action, l)
                    dport = self.switch_elements(dport, self.SW_DPORT)
                    sport = self.switch_elements(sport, self.SW_SPORT)
                    current_rule += self.RULE_IN.format(protocol, dport, lsrc + lip, sport, rule_detail[5], action, l)
                    if parsed[0] == self.TALW:  # <> is really stupid in this case: it doubles the rules
                        current_rule += current_rule
                if not d_local and not s_local:  # Standard case: no local
                    current_rule = \
                        self.RULE_FWD.format(protocol, source, sport, destination, dport, rule_detail[5], action, l)
                    if parsed[0] == self.TALW:  # <>
                        source = self.switch_elements(source, self.SW_SOURCE)
                        destination = self.switch_elements(destination, self.SW_DESTINATION)
                        sport = self.switch_elements(sport, self.SW_SPORT)
                        dport = self.switch_elements(dport, self.SW_DPORT)
                        current_rule += \
                            self.RULE_FWD.format(protocol, destination, dport, source, sport, rule_detail[5], action, l)
                filters += current_rule  # The set of filter rules is updated!

                # We consider NATs only when the operator is a >
                if parsed[0] == self.ALLW:
                    if rule_detail[1][0] == self.MASQUERADE:  # If we have a MASQUERADE case
                        if source != "" and source[1] != 's':
                            # if the source is an interface, translate it into its corresponding net_ip
                            source = self.SOURCE_HOST + self.get_ip_by_name(source[3:])[0]["net_ip"]
                        nat += self.RULE_MASQUERADE.format(protocol, source, sport, destination, dport, l)
                    elif rule_detail[1][0] != "":  # A Source NAT is requested
                        if rule_detail[1][0][1] != "-":
                            to_source = "None"  # A special case: NAT with an interface instead of a host
                        else:
                            to_source = rule_detail[1][0][2:]
                        if rule_detail[1][2] != "0":  # The sNAT port
                            to_source += ":" + rule_detail[1][2]
                        if source != "" and source[1] != 's':  # Again: translate interfaces into its net_ip
                            source = self.SOURCE_HOST + self.get_ip_by_name(source[3:])[0]["net_ip"]
                        nat += self.RULE_SNAT.format(protocol, source, sport, destination, dport, to_source, l)
                    elif rule_detail[3][0] != "":  # Destination NAT
                        if destination != "" and destination[1] == 'o':  # We avoid to open unnecessary doors...
                            dest_mangle = self.DESTINATION_HOST + self.get_ip_by_name(destination[3:])[0]["net_ip"]
                        else:
                            dest_mangle = destination
                        binding_nat += self.MANGLE_NAT.format(protocol, source, sport, dest_mangle, dport, l)
                        # Here all the parameters for the NAT rule are set
                        if destination == "" or destination[1] != "d":
                            to_destination = "None"
                        else:
                            to_destination = destination[3:]
                        if dport != "":
                            to_destination += ":" + dport[8:]
                        if rule_detail[3][0][1] != '-':
                            destination = self.DESTINATION_HOST + self.get_ip_by_name(rule_detail[3][0])[0]["net_ip"]
                        else:
                            destination = self.DESTINATION_HOST + rule_detail[3][0][2:]
                        if rule_detail[3][2] != 0:
                            dport = self.DPORT + rule_detail[3][2]
                        else:
                            dport = ""
                        nat += self.RULE_DNAT.format(protocol, source, sport, destination, dport, to_destination, l)
            elif parsed[0] == self.PDRP or parsed[0] == self.PRJC:  # Here we have the policies
                action = self.DROP if parsed[0] == self.PDRP else self.RJCT  # Set the action...
                # A policy can be translated as a normal firewall rule put below all the other rules, so
                # we add a new rule to be evaluated...
                # @@@@@@@ IMPORTANT @@@@@@@
                # THIS WORKS ONLY IF POLICIES RULES COMES AFTER ALL THE NORMAL RULES! USE THE MIGNIS COMPILER,
                # DO NOT WRITE RULES BY HAND IN INTERMEDIATE REPRESENTATION! YOU ARE ADVICED!
                new_command = action + ":" + parsed[1][0] + ";" + parsed[1][1] + ";" + parsed[1][2] + ";;;0;" + \
                                             parsed[1][3] + ";" + parsed[1][4] + ";" + parsed[1][5] + ";;;0;" + \
                                             parsed[1][6] + ";"
                lines.insert(index + 1, new_command)
            elif parsed[0] == self.CSTM:  # Custom rules, they are put after the policies... Use with cautions
                filters += parsed[1][0] + "\n"

        for intf in intfs:  # For all the interfaces that accepts anything
            comment = "BIND:" + intf + ";0.0.0.0/0"  # Set the comment...
            # Add the drops and the final accept to the bindings string
            bindings = bind_any_drop.format(intf, comment) + \
                        self.BIND_ANY_ACCEPT.format(intf, comment) + \
                        bindings

        # Final mangle rules list
        bindings = self.BASIC_MANGLE + \
                    (self.DEFAULT_MANGLE if def_rul else "") + \
                    binding_nat + \
                    bindings + \
                    self.MANGLE_LO + \
                    (self.LOGGING_MANGLE if logging else "")
        # Final filter rules list - First add established, then all the rest!
        filters = (filters.format(self.DEFAULT_ESTABLISHED) if estb else filters.format("{0}"))
        filters = (filters.format(self.DEFAULT_FILTER) if def_rul else filters.format("")) + \
                    (self.LOGGING_FILTER if logging else "")

        # Return!
        return filters + "COMMIT\n" + bindings + "COMMIT\n" + nat + "COMMIT" + "\n"

    ''' This method is used to extract the couple (in a dictionary) {int_name, net_ip} '''
    def get_ip_by_name(self, name):
        return [item for item in self.int_ip if item['int_name'] == name]  # List comprehension approach
