(* List of string in which we save the compiled configuration for each *)
(* firewall *)
let compiled:(string list) ref = ref [];;

(* Aux function that is used to create the option string *)
let rec create_options opt =
	match opt with
	| (keyword,value)::rest		-> 
		"OPTN:" ^ keyword ^ "," ^ value ^ "\n" ^ create_options rest
	| [] 											-> ""
;;

(* Aux function that is used to create the bindings between interfaces and *)
(* network ip addresses *)
let rec create_interfaces ifs =
	match ifs with
	| (name,nic,ip)::rest			->
		"BIND:" ^ nic ^ "," ^ ip ^ "\n" ^ create_interfaces rest
	| []											-> ""
;;

(* The following two aux functions are used to find an alias or an interface *)
(* Note that interfaces are bound to a net ip address, so here the nic name *)
(* is returned, while aliases are never actually saved: the corresponding ip*)
(* is returned *)
let rec find_alias lst needle =
	match lst with
	| (name,ip)::rest					->
		if name = needle then
			ip
		else
			find_alias rest needle
	|	[]											-> ""
;;

let rec find_interface lst needle =
	match lst with
	| (name,nic,ip)::rest			->
		if name = needle then
			nic
		else
			find_interface rest needle
	|	[]											-> ""
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

let set_interface inf amb =
	match inf with
	| Mast.Noif								-> ""
	| Mast.If(id)							->
		let resolved = find id amb in
		if resolved = "" then
			failwith("Interface not declared")
		else
			resolved
;;

(* Aux functions to correctly compile all the components of a rule *)
let set_endpoint e amb = 
	match e with
	| Mast.Name(host,interface,port)
														->
		let resolved = find host amb in
		if resolved = "" then
			failwith("Alias or interface not declared")
		else
			resolved ^ "," ^ (set_interface interface amb) ^ "," ^ string_of_int(port)
	| Mast.Ip(host,interface,port)
														->
		host ^ "," ^ (set_interface interface amb) ^ "," ^ string_of_int(port)
	| Mast.Local(port)				->
		"LOCAL" ^ ",," ^ string_of_int(port)
	| Mast.Star								-> "ANY,,0"
;;

let set_nat n amb = 
	match n with
	| Mast.Nat(ep)						-> set_endpoint ep amb
	| Mast.Masquerade					-> "MASQUERADE,,0"
	| Mast.Nonat							-> ",,0"
;;

let set_protocol p =
	match p with
	| Mast.Tcp								-> "TCP"
	| Mast.Udp								-> "UDP"
	| Mast.Icmp								-> "ICMP"
	| Mast.Noprotocol					-> "ANY"
;;

let set_formula f =
	match f with
	| Mast.Formula(f) 				-> f
	| Mast.Noformula					-> ""
;;

(* Aux function used to create the operands of a rule *)
let set_op se sn dn de pr fr amb = 
	(set_endpoint se amb) ^ "," ^
	(set_nat sn amb) ^ "," ^
	(set_endpoint de amb) ^ "," ^
	(set_nat dn amb) ^ "," ^
	(set_protocol pr) ^ "," ^
	(set_formula fr)
;;

(* Aux function used to create the list of rules *)
let rec create_rules rls ambient = 
	match rls with
	| Mast.Allow(from,snat,dnat,dest,prt,frm)::rest 
														-> "ALLW:" ^ 
														   (set_op from snat dnat dest prt frm ambient) ^
															"\n" ^ (create_rules rest ambient)
	| Mast.Twallow(from,snat,dnat,dest,prt,frm)::rest 
														-> "TALW:" ^ 
														   (set_op from snat dnat dest prt frm ambient) ^
															"\n" ^ (create_rules rest ambient)
	| Mast.Drop(from,snat,dnat,dest,prt,frm)::rest 
														-> "DROP:" ^ 
														   (set_op from snat dnat dest prt frm ambient) ^
															"\n" ^ (create_rules rest ambient)
	| Mast.Reject(from,snat,dnat,dest,prt,frm)::rest 
														-> "RJCT:" ^ 
														   (set_op from snat dnat dest prt frm ambient) ^
															"\n" ^ (create_rules rest ambient)
	| []											-> ""
;;

let set_policy_rule r =
	match r with
	| Mast.Pallow							-> "PLLW:"
	| Mast.Ptwallow						-> "PTLW:"
	| Mast.Pdrop							-> "PDRP:"
	| Mast.Preject						-> "PRJC:"
;;

(* Aux function used to create the policy rules *)
let rec create_policies pol =
	match pol with
	| Mast.Default(op,pr)::rest
														-> (set_policy_rule op) ^
															 (set_protocol pr) ^ "\n" ^
															 create_policies rest
	| []											-> ""
;;

(* Aux function to include all the custom rules *)
let rec create_custom cstm = 
	match cstm with
	| str::rest								-> "CSTM:" ^ str ^ "\n" ^ create_custom rest
	| []											-> ""
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
			let rules_string = create_rules current_rules (len - 1) in
			let policies_string = create_policies current_policies in
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

(* Main function of the compiler component. It just call the build_conf *)
(* with the correct length. Please note that all the lists in the Scope *)
(* module have the same length *)
let compile file = 
	Scope.start file;
	build_conf (List.length !Scope.option_list)
;;