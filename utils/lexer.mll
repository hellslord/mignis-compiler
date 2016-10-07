{
  open Parser
  open String
  
  (* This function is used to get a string without spaces and any instances *)
  (* of character c at the string beginning *)
  let rec clean s c =
    let len = String.length s in
    if s.[0] == c || s.[0] == ' ' then clean (String.sub s 1 (len - 1)) c
    else s
    
  (* This is the type used to keep trace of the current state *)
  type state_t = MainConf | CustomRules
}

(* Definition of some regular expressions, useful to recognize tokens *)

(* Auxiliary expressions *)
(* Single number *)
let number = ['0' - '9']

(* Ingeger *)
let int = number+

(* Octet in IPs *)
let octet = number number? number?

(* Subnet mask *)
let subnet = number number?

(* Main definitions *)
(* A generic identifier, used to give names to interfaces, hosts and so on *)
let identifier = (['A' - 'Z'] | ['a' - 'z']) 
                 (['A' - 'Z'] | ['a' - 'z'] | '_' | int)*
                
(* A custom rule, with spaces and symbols *)
let custom = (['A' - 'Z'] | ['a' - 'z'] | int |
              ' ' | '-' | '\"')+

(* An additional rule for mignis+ *)
let additional = '|' [^'\n']*

(* A full network address *)
let net_addr = octet '.' octet '.' octet '.' octet '/' subnet

(* A full host address *)
let host_addr = octet '.' octet '.' octet '.' octet

(* Port recognition pattern *)
let port = ':' (' ')* int

(* Definition of the lexer rules *)
(* Main entrypoint *)
rule main state_ref = parse
  (* End of file is matched *)
  | eof                          { EOF }
  (* Ignore blank spaces, tabs and CRLF *)
  | (" " | "\t" | "\n")          { main state_ref lexbuf }
  (* Comments *)
  | '#'                          { comment state_ref lexbuf }
  (* Main keywords, the one defining the configuration sections and local *)
  | "OPTIONS"                    { OPTION }
  | "INTERFACES"                 { INTERFACE }
  | "ALIASES"                    { ALIAS }
  | "FIREWALL"                   { FIREWALL }
  | "POLICIES"                   { POLICY }
  (* The custom rules section is a rather special one because custon rules *)
  (* are recognized with a regex that overlaps with the one for the *)
  (* identifiers. So the state is changed in order to persistently use *)
  (* the cstrule entrypoint *)
  | "CUSTOM"                     { state_ref := CustomRules; CUSTOM }
  | "local"                      { LOCAL }
  (* There are a fixed number of recognized protocols, higher priority *)
  (* compared to the identifiers, meaning that there can't be aliases *)
  (* or interfaces called with a protocol name *)
  | "tcp"                        { TCP }
  | "udp"                        { UDP }
  | "icmp"                       { ICMP }
  (* Identifiers and IPs *)
  | identifier as value          { IDENTIFIER value }
  | additional as value          { FORMULA (clean value '|') }
  | "*"                          { STAR }
  | "@"                          { AT }
  | net_addr  as value           { NET_IP value }
  | host_addr  as value          { HOST_IP value }
  (* Ports are not always specified, so we manage them with a specific rule *)
  | port as value                { PORT (int_of_string (clean value ':')) }
  (* Operators for firewall policies *)
  | ">"                          { ALLOW }
  | "<>"                         { TWALLOW }
  | "/"                          { DROP }
  | "//"                         { REJECT }
  (* Brackets are used to define SNATs and DNATs togehter with the char *)
  (*  '.' used when masquerade is requested *)
  | "["                          { LBRACK }
  | "."                          { DOT }
  | "]"                          { RBRACK }
(* Comment entrypoint: used to ignore comments in the main conf part *)
and comment state_ref = parse
  | "\n"                         { main state_ref lexbuf }
  | eof                          { EOF }
  | _                            { comment state_ref lexbuf }
(* Ccomment entrypoint: used to ignore comments in the Custom rules part *)
and ccomment state_ref = parse
  | "\n"                         { cstrule state_ref lexbuf }
  | eof                          { EOF }
  | _                            { ccomment state_ref lexbuf }
(* Cstrule entrypoint: used to recognize the custom rules *)
and cstrule state_ref = parse
  | "OPTIONS"                    { state_ref := MainConf; OPTION }
  | "\n"                         { cstrule state_ref lexbuf }
  | '#'                          { ccomment state_ref lexbuf }
  | custom as value              { CUSTOMRULE value }
  | eof                          { EOF }

{
  (* Current state is MainConf *)
  let current = ref MainConf;;

  (* To get the next token, the current state is matched and decisions are *)
  (* taken *)
  let next_token =
    (fun lexbuf -> match !current with
     | MainConf -> main current lexbuf
     | CustomRules -> cstrule current lexbuf)
;;
}