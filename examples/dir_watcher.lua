local e = require "fend.poll"()

local cbs = { }
for i , event_name in ipairs {
	"access" , "attrib" , "close_write" , "close_nowrite" ,
	"create" , "delete" , "delete_self" , "modify" , "move" ,
	"moved_from" , "moved_to" , "open" } do
	cbs [ event_name ] = function ( watcher , name )
		local path = watcher.path:gsub("/$","") -- Remove trailing slash
		if name then path = path .. "/" .. name end
		print ( string.format ( "%20s  %s" , event_name , path ) )
	end ;
end

assert ( arg [ 1 ] , "no paths to watch" )
for i , path in ipairs ( arg ) do
	e:add_path ( path , cbs )
end

while true do
	e:dispatch ( )
end

