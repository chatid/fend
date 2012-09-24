include = function  ( lib )
	lib = "fend.include." .. lib:gsub("%.h$",""):gsub("/",".")
	return require ( lib )
end
