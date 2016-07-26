open Printf;;

let forced = ref false;;

let rec write_to_file comp_conf prog dir = 
	match comp_conf with
	| str::rest				->
		let filename = dir ^ "fw" ^ (string_of_int prog) ^ ".config" in
		let outfile = open_out filename in
		fprintf outfile "%s" str;
		printf "Configuration file %s successfully created\n" filename;
		write_to_file rest (prog + 1) dir
	| []							-> ()
;;
	

let par_len = Array.length (Sys.argv) in
if par_len < 2 || par_len > 3 then
	begin
		printf "Usage: ./mignis [-f] <file_name>\n";
		exit 0
	end
else
	begin
		for i = 1 to par_len - 2 do
			if Sys.argv.(i) = "-f" then
				forced := true
			else
				begin
					printf "Unrecognized option: %s\n" Sys.argv.(i);
					exit 0
				end
		done;
		if Sys.file_exists Sys.argv.(par_len - 1) then
			begin
				let dest_dir = (Filename.dirname Sys.argv.(par_len - 1) ^ 
					"/compiled/") in
				if Sys.file_exists dest_dir then
					begin
						if !forced = false then
							begin
								printf "Directory %s already exists. Use -f to overwrite\n" 
											 dest_dir;
								exit 0
							end
						else
							let _ = Sys.command ("rm -Rf " ^ dest_dir ^ "*") in
							let _ = Sys.command ("rmdir " ^ dest_dir) in
							printf "Directory %s has been deleted\n" dest_dir;
					end	
				else ();
								
				let _ = Sys.command ("mkdir " ^ dest_dir) in
				printf "Directory %s created\n" dest_dir;
				Compiler.compile Sys.argv.(par_len - 1);
				write_to_file !Compiler.compiled 0 dest_dir
			end
		else
			printf "File %s does not exist\n" Sys.argv.(par_len - 1)
	end
;;