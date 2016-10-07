%{
  open Mast
%}

/* Main key words */
%token OPTION INTERFACE ALIAS FIREWALL POLICY CUSTOM LOCAL STAR AT
/* Ids, addresses and ports */
%token <string> FORMULA
%token <string> CUSTOMRULE
%token <string> IDENTIFIER
%token <string> NET_IP
%token <string> HOST_IP
%token <int> PORT
/* Operators */
%token ALLOW DROP REJECT TWALLOW
/* Brackets and dots */ 
%token LBRACK DOT RBRACK
/* Protocols */
%token TCP UDP ICMP
/* EOF */
%token EOF

%start config
%type <Mast.config> config

%%
/* The options part always begins with the keyword OPTION */
Options:
  OPTION OptionList                    { $2 }
;
/* The list of options is made of two IDs, one for the keyword, one for the */
/* value */
OptionList:
  IDENTIFIER IDENTIFIER OptionList     { Option($1, $2)::$3 }
 |                                     { [] }
;
/* The interface part begins with the keyword INTERFACE */
InterfaceDecl:
  INTERFACE InterfList                 { $2 }
;
/* This is the structure of an interface declaration */
InterfList:
  IDENTIFIER IDENTIFIER NET_IP  InterfList
                                       { Interface($1, $2, $3)::$4 }
 |                                     { [] } /* Empty list */
;
/* The alias part begins with the keyword ALIAS */
AliasDecl:
  ALIAS AliasList                      { $2 }
;
/* This is how a new alias is declared */
AliasList:
  IDENTIFIER HOST_IP AliasList         { Hostalias($1, $2)::$3 }
 |IDENTIFIER NET_IP AliasList          { Netalias($1, $2)::$3 }
 |                                     { [] }
;
/* Firewall rules are specified after the keyword FIREWALL */
FirewallConf:
  FIREWALL FirewList                   { $2 }
;
/* Firewall rules have a rather complex structure: */
/* Each of them has two endpoints, possibly two nats (snat and dnat) */
/* an operator and a protocol. Some of them could not be specified but in the */
/* AST they are all explicit */
FirewList:
  Endp Nt ALLOW Nt Endp Prtc Formula FirewList
                                       { Allow($1, $2, $4, $5, $6, $7)::$8 }
 |Endp Nt TWALLOW Nt Endp Prtc Formula FirewList
                                       { Twallow($1, $2, $4, $5, $6, $7)::$8 }
 |Endp Nt DROP Nt Endp Prtc Formula FirewList
                                       { Drop($1, $2, $4, $5, $6, $7)::$8 }
 |Endp Nt REJECT Nt Endp Prtc Formula FirewList
                                       { Reject($1, $2, $4, $5, $6, $7)::$8 }
 |                                     { [] }
;
/* This is how an endpoint looks like */
Endp:
  IDENTIFIER If Prt                    { Name($1, $2, $3) }
 |HOST_IP If Prt                       { Ip("h-" ^ $1, $2, $3) }
 |NET_IP If Prt                        { Ip("n-" ^ $1, $2, $3) } 
 |LOCAL Prt                            { Local($2) }
 |STAR                                 { Star }
;
/* Basically if no port is explicitly specified, we use the dummy 0 value */
Prt:
  PORT                                 { $1 }
 |                                     { 0 }
;
/* Interface management for Mignis+ */
If:
  AT IDENTIFIER                        { If($2) }
 |                                     { Noif }
;
/* Nat, managing the masquerade case */
Nt:
  LBRACK DOT RBRACK                    { Masquerade }
 |LBRACK Endp RBRACK                   { Nat($2) }
 |                                     { Nonat } /* No nat is specified */
;
/* The protocol */
Prtc:
  TCP                                  { Tcp }
 |UDP                                  { Udp }
 |ICMP                                 { Icmp }
 |                                     { Noprotocol } /* no explicit protocol */
; 
/* Formulas in mignis+ */
Formula:
  FORMULA                              { Formula($1) }
 |                                     { Noformula }
/* The policy section begins with the keyword POLICY */
PolicyConf:
  POLICY PolicyList                    { $2 }
;
/* This is the structure of a default policy rule */
PolicyList:
  Endp DROP Endp Prtc PolicyList       { Default(Pdrop, $1, $3, $4)::$5 }
 |Endp REJECT Endp Prtc PolicyList     { Default(Preject, $1, $3, $4)::$5 }
 |                                     { [] }
;
/* The custom rules section begins with the keyword CUSTOM */
CustomRules:
  CUSTOM CustomList                    { $2 }
;
/* All the custom rules are added to a specific list */
CustomList:
  CUSTOMRULE CustomList                { $1::$2 }
 |                                     { [] }
;
/* Main configuration */
config:
  Options InterfaceDecl AliasDecl FirewallConf PolicyConf CustomRules config
                                       { Firewall($1, $2, $3, $4, $5, $6)::$7 }
 |EOF                                  { [] }
;

%%
