include = setmetatable ( {} , {
	__call = function  ( include , lib )
		lib = "ffi_ev.include." .. lib:gsub(".h$",""):gsub("/",".")
		return require ( lib )
	end
}) -- Is the table modules go into, and the function that pulls them in
