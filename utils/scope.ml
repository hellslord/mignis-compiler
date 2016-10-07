open Lexer;;
open Parser;;
open List;;

(* Definition of several list: each of them keeps track of a certain part of *)
(* the Mignis Abstract Syntax Tree. For all list, the n-th position describes *)
(* the configuration of the n-th firewall *)

(* Options *)
let option_list:((Mast.id * Mast.id) list) list ref = ref [];;
(* Interfaces *)
let interface_list:((Mast.id * Mast.id * Mast.net_ip) list) list ref = ref [];;
(* Aliases *)
let alias_list:((Mast.id * string) list) list ref = ref [];;
(* Firewall rules *)
let rule_list:(Mast.op list) list ref = ref [];;
(* Policies *)
let policy_list:(Mast.policy list) list ref = ref [];;
(* Custom rules *)
let crule_list:(Mast.crule list) list ref = ref [];;

(* Aux function to read from a source file *)
let read_source file = Lexing.from_channel (open_in file);;

(* Aux func to lex and parse a configuration file *)
let lex_and_parse file = 
  try config next_token (read_source file) with 
  | Failure error -> failwith ("Lexer error: " ^ error)
  | Parsing.Parse_error -> failwith ("Parse error")
;;

(* Aux func to create the option structure *)
let rec create_option (opt:Mast.option list) =
  match opt with
  | Mast.Option(keyword,value)::rest    -> (keyword,value)::create_option rest
  | []                                  -> []
;;

(* Aux func to create the interface alias and binding structure *)
let rec create_interface (ifs:Mast.interface list) =
  match ifs with
  | Mast.Interface(name,noi,nip)::rest  -> (name,noi,nip)::create_interface rest
  | []                                  -> []
;;

(* Aux func to create the alias table *)
let rec create_alias (als:Mast.alias list) =
  match als with
  | Mast.Hostalias(name,ip)::rest       -> (name,"h-" ^ ip)::create_alias rest
  | Mast.Netalias(name,nip)::rest       -> (name,"n-" ^ nip)::create_alias rest
  | []                                  -> []
;;

(* This function create a complete firewall structure *)
let conf_firewall (fw:Mast.firewall) =
  let Mast.Firewall(options,interfaces,aliases,rules,policies,custom) = fw in
  option_list := !option_list @ [(create_option options)];
  interface_list := !interface_list @ [(create_interface interfaces)];
  alias_list := !alias_list @ [(create_alias aliases)];
  rule_list := !rule_list @ [rules];
  policy_list := !policy_list @ [policies];
  crule_list := !crule_list @ [custom]
;;

(* This function manages all the firewalls structures *)
let rec create_conf_table (ast:Mast.config) =
  match ast with
  | fw::rest                            -> conf_firewall fw; 
                                           create_conf_table rest
  | []                                  -> ()
;;

(* Main function: it creates the complete configuration table *)
let start source =
  let ast = lex_and_parse source in
  option_list := [];
  interface_list := [];
  alias_list := [];
  rule_list := [];
  policy_list := [];
  crule_list := [];
  create_conf_table ast
;;