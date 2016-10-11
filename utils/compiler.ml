(* List of strings in which we save the compiled configuration for each *)
(* firewall *)
let compiled:(string list) ref = ref [];;

(* List of operands to keep track of overlapping rules *)
let overlaps:(string list) ref = ref [];;

(* Are we on a Mignis or Mignis+ configuration file? *)
type conf_t = Mignis | MignisPlus | NotSet;;
let conf:(conf_t) ref = ref NotSet;;

(* This global expression is used to tokenize the operands. It's global *)
(* because we need it in more than one function and for since the overlaps *)
(* detection is not efficient, we don't want to call the Str.regexp more *)
(* than once*)
let comma = Str.regexp ";";;

(* This global expression is used as a dummy rule useful to check some *)
(* conditions on the first real rule *)
let dummy = ";;;;;;;;;;;;;;";;

(* This global expression is used only to pass a message in case of bad rules *)
let warning:string ref = ref "";;

(* Aux function that is used to create the option string *)
let rec create_options opt =
  match opt with
  | (keyword,value)::rest        -> 
    "OPTN:" ^ keyword ^ ";" ^ value ^ "\n" ^ create_options rest
  | []                           -> ""
;;

(* Aux function that is used to create the bounds between interfaces and *)
(* network ip addresses *)
let rec create_interfaces ifs =
  match ifs with
  | (name,nic,ip)::rest          ->
    "BIND:" ^ nic ^ ";" ^ ip ^ "\n" ^ create_interfaces rest
  | []                           -> ""
;;

(* The following two aux functions are used to find an alias or an interface *)
(* Note that interfaces are bound to a net ip address, so here the nic name *)
(* is returned, while aliases are never actually saved: the corresponding ip *)
(* is returned *)
let rec find_alias lst needle =
  match lst with
  | (name,ip)::rest              ->
    if name = needle then
      ip
    else
      find_alias rest needle
  |  []                          -> ""
;;

let rec find_interface lst needle =
  match lst with
  | (name,nic,ip)::rest          ->
    if name = needle then
      nic
    else
      find_interface rest needle
  |  []                          -> ""
;;

(* Aux function used to find an alias or an interface *)
(* Please note that aliases have a higher priority *)
let rec find needle ambient =
  let alias = List.nth !Scope.alias_list ambient in
  let result_alias = find_alias alias needle in
  if result_alias = "" then
    let interface = List.nth !Scope.interface_list ambient in
    find_interface interface needle 
  else
    result_alias
;;

(* This function is the one that is allowed to track if we are on a Mignis *)
(* or Mignis+ configuration file and it keeps things coherent *)
let set_interface inf amb nat =
  match inf with
  | Mast.Noif                    -> 
    if !conf = MignisPlus && nat = false then
      failwith("Mignis and Mignis+ rules cannot be used together")
    else if !conf = NotSet then
      begin
        conf := Mignis;
        ""
      end
    else
      ""
  | Mast.If(id)                  ->
    let resolved = find id amb in
    if resolved = "" then
      failwith("Interface not declared")
    else
      if !conf = Mignis && nat = false then
        failwith("Mignis and Mignis+ rules cannot be used together")
      else if !conf = NotSet then
        begin
          conf := MignisPlus;
          resolved
        end
      else
        resolved
;;

(* Aux functions to correctly compile all the components of a rule *)
let set_endpoint e amb nat= 
  match e with
  | Mast.Name(host,interface,port)
                                 ->
    let resolved = find host amb in
    if resolved = "" then
      failwith("Alias or interface not declared")
    else
      resolved ^ ";" ^ (set_interface interface amb nat) ^ ";" ^ 
        string_of_int(port)
  | Mast.Ip(host,interface,port)
                                 ->
    host ^ ";" ^ (set_interface interface amb nat) ^ ";" ^ string_of_int(port)
  | Mast.Local(port)             ->
    "LOCAL" ^ ";;" ^ string_of_int(port)
  | Mast.Star                    -> "ANY;;0"
;;

let set_nat n amb = 
  match n with
  | Mast.Nat(ep)                 -> set_endpoint ep amb true
  | Mast.Masquerade              -> "MASQUERADE;;0"
  | Mast.Nonat                   -> ";;0"
;;

let set_protocol p =
  match p with
  | Mast.Tcp                     -> "TCP"
  | Mast.Udp                     -> "UDP"
  | Mast.Icmp                    -> "ICMP"
  | Mast.Noprotocol              -> "ANY"
;;

let set_formula f =
  match f with
  | Mast.Formula(f)              -> f
  | Mast.Noformula               -> ""
;;

(* Aux function used to create the operands of a rule *)
let set_op se sn dn de pr fr amb = 
  (set_endpoint se amb false) ^ ";" ^
  (set_nat sn amb) ^ ";" ^
  (set_endpoint de amb false) ^ ";" ^
  (set_nat dn amb) ^ ";" ^
  (set_protocol pr) ^ ";" ^
  (set_formula fr)
;;

(* Aux function to check if a string is a substring of another *)
(* Source code found at *)
(* http://stackoverflow.com/questions/11193783/ocaml-strings-and-substrings *)
(* Last checked october 4th 2016 *)
let contains s1 s2 =
  let re = Str.regexp_string s2 in
  try 
    ignore (Str.search_forward re s1 0); 
    true
  with Not_found -> false

(* Aux function to find overlaps in two rules *)
let chk_rule r1 r2 = 
  let s1 = List.nth r1 0 ^ "," ^ List.nth r1 1 ^ "," ^ List.nth r1 2 in
  let s2 = List.nth r2 0 ^ "," ^ List.nth r2 1 ^ "," ^ List.nth r2 2 in
  let sn1 = List.nth r1 3 ^ "," ^ List.nth r1 4 ^ "," ^ List.nth r1 5 in
  let sn2 = List.nth r2 3 ^ "," ^ List.nth r2 4 ^ "," ^ List.nth r2 5 in
  let d1 = List.nth r1 6 ^ "," ^ List.nth r1 7 ^ "," ^ List.nth r1 8 in
  let d2 = List.nth r2 6 ^ "," ^ List.nth r2 7 ^ "," ^ List.nth r2 8 in
  let dn1 = List.nth r1 9 ^ "," ^ List.nth r1 10 ^ "," ^ List.nth r1 11 in
  let dn2 = List.nth r2 9 ^ "," ^ List.nth r2 10 ^ "," ^ List.nth r2 11 in
  if s1 = s2 && d1 = d2 &&
     sn1 = sn2 && sn1 = ",,0" &&
     dn1 = dn2 && dn1 = ",,0" then
    begin
      warning := !warning ^ 
        "A rule with same source and destination has been found\n";
      true
    end
  else if s1 = s2 && d1 = d2 &&
          dn1 <> dn2 &&
          (dn1 = ",,0" || dn2 = ",,0") &&
          sn1 = sn2 then
    begin
      warning := !warning ^ "A rule with dNAT is overlapping a generic rule\n";
      true
    end
  else if s1 = s2 && d1 <> d2 &&
          dn1 = dn2 && dn1 <> ",,0" then
    begin
      warning := !warning ^ "A rule with an overlapping dNAT has been found\n";
      true
    end
  else if s1 = s2 && 
          d1 <> d2 && 
          (d1 = "ANY,,0" || d2 = "ANY,,0") then
    begin
      warning := !warning ^ "A rule is overlapping a * destination\n";
      true
    end
  else if sn1 <> ",,0" && dn1 <> ",,0" then
    begin
      warning := "A rule cannot specify a sNAT and a dNAT at the same time";
      false
    end
  else if dn1 = "MASQUERADE,,0" then
    begin
      warning := "Destination masquarade is not allowed";
      false
    end
  else if sn1 = "ANY,,0" || dn1 = "ANY,,0" then
    begin
      warning := "Wildcard * cannot be used in NAT declarations";
      false
    end
  else if (contains sn1 "LOCAL") || (contains dn1 "LOCAL") then
    begin
      warning := "Keyword local cannot be used in NAT declarations";
      false
    end
  else
    true
;;
  

(* Function to check whether there are overlaps or not *)
let rec check_overlaps opns current = 
  match current with
  | rule::rest                   -> let rule_token = Str.split comma rule in
                                    if chk_rule opns rule_token = false then
                                      false
                                    else
                                      check_overlaps opns rest
  | []                           -> let dummy_token = Str.split comma dummy in
                                    chk_rule opns dummy_token
;;

(* Aux function used to create the list of rules *)
let rec create_rules rls ambient = 
  warning := "";
  match rls with
  | Mast.Allow(from,snat,dnat,dest,prt,frm)::rest 
                                 -> let operands =
                                      set_op from snat dnat dest prt frm ambient 
                                                                              in 
                                    if check_overlaps (Str.split comma operands)
                                      !overlaps = true then
                                      begin
                                        overlaps := !overlaps @ [operands];
                                        if !warning <> "" then
                                          Printf.printf "Warning: %s" !warning;
                                        (create_rules rest ambient) ^
                                        "ALLW:" ^ 
                                        operands ^
                                        "\n"
                                      end
                                    else
                                      failwith(!warning)
  | Mast.Twallow(from,snat,dnat,dest,prt,frm)::rest 
                                 -> let operands =
                                      set_op from snat dnat dest prt frm ambient
                                                                              in
                                    if check_overlaps (Str.split comma operands)
                                      !overlaps = true then
                                      begin
                                        overlaps := !overlaps @ [operands];
                                        if !warning <> "" then
                                          Printf.printf "Warning: %s" !warning;
                                        (create_rules rest ambient) ^
                                        "TALW:" ^ 
                                        operands ^
                                        "\n"
                                      end
                                    else
                                      failwith(!warning)
  | Mast.Drop(from,snat,dnat,dest,prt,frm)::rest 
                                 -> if !conf = MignisPlus then
                                      failwith("Mignis+ does not allow " ^ 
                                               "for negative rules");
                                    let operands =
                                      set_op from snat dnat dest prt frm ambient
                                                                              in
                                    if check_overlaps (Str.split comma operands)
                                      !overlaps = true then
                                      begin
                                        overlaps := !overlaps @ [operands];
                                        if !warning <> "" then
                                          Printf.printf "Warning: %s" !warning;
                                       "DROP:" ^ 
                                       operands ^
                                       "\n" ^ (create_rules rest ambient)
                                     end
                                   else
                                     failwith(!warning);
  | Mast.Reject(from,snat,dnat,dest,prt,frm)::rest 
                                 -> if !conf = MignisPlus then
                                      failwith("Mignis+ does not allow " ^ 
                                               "for negative rules");
                                    let operands =
                                      set_op from snat dnat dest prt frm ambient
                                                                              in
                                    if check_overlaps (Str.split comma operands)
                                      !overlaps = true then
                                      begin
                                        overlaps := !overlaps @ [operands];
                                        if !warning <> "" then
                                          Printf.printf "Warning: %s" !warning;
                                        "RJCT:" ^ 
                                        operands ^
                                        "\n" ^ (create_rules rest ambient)
                                      end
                                    else
                                      failwith(!warning);
  | []                           -> ""
;;

let set_policy_rule r =
  match r with
  | Mast.Pdrop                   -> "PDRP:"
  | Mast.Preject                 -> "PRJC:"
;;

(* Aux function used to create the policy rules *)
let rec create_policies pol amb =
  match pol with
  | Mast.Default(op,end1,end2,pr)::rest
                                 -> (set_policy_rule op) ^
                                    (set_endpoint end1 amb false) ^ ";" ^
                                    (set_endpoint end2 amb false) ^ ";" ^
                                    (set_protocol pr) ^ "\n" ^
                                    create_policies rest amb
  | []                           -> ""
;;

(* Aux function to include all the custom rules *)
let rec create_custom cstm = 
  match cstm with
  | str::rest                    -> "CSTM:" ^ str ^ "\n" ^ create_custom rest
  | []                           -> ""
;;

(* Aux function that is used to actually compile the configurations *)
let rec build_conf len =
  if len > 0 then
    begin
      let current_option = List.nth !Scope.option_list (len - 1) in
      let current_interface = List.nth !Scope.interface_list (len - 1) in
      let current_rules = List.nth !Scope.rule_list (len - 1) in
      let current_policies = List.nth !Scope.policy_list (len - 1) in
      let current_custom = List.nth !Scope.crule_list (len - 1) in
      let option_string = create_options current_option in
      let interface_string = create_interfaces current_interface in
      overlaps := [];
      let rules_string = create_rules current_rules (len - 1) in
      let policies_string = create_policies current_policies (len - 1) in
      let custom_string = create_custom current_custom in
      let all = option_string ^ 
                interface_string ^ 
                rules_string ^
                policies_string ^ 
                custom_string in
      compiled := all::(!compiled);
      build_conf (len - 1)
    end
  else
    if len < 0 then
      failwith("General error")
    else
      ()
;;

(* Main function of the backend component. It just call the build_conf *)
(* with the correct length. Please note that all the lists in the Scope *)
(* module have the same length *)
let compile file = 
  Scope.start file;
  build_conf (List.length !Scope.option_list)
;;