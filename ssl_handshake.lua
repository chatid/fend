-- Call to handshake an ssl connection
local function handshake ( sock , dispatch , cb )
	local ok , err = sock:dohandshake ( )
	if ok then
		cb ( sock )
	elseif err == "wantread" then
		dispatch:add_fd ( sock:getfile() , {
				read = function ( file , cbs ) return handshake ( sock , dispatch , cb ) end ;
				error = function ( file , cbs ) return cb ( nil , sock:get_error ( ) ) end ;
				oneshot = true ;
				edge = true ;
			} )
	elseif err == "wantwrite" then
		dispatch:add_fd ( sock:getfile() , {
				write = function ( file , cbs ) return handshake ( sock , dispatch , cb ) end ;
				error = function ( file , cbs ) return cb ( nil , sock:get_error ( ) ) end ;
				oneshot = true ;
				edge = true ;
			} )
	else
		cb ( nil , err )
	end
end ;

return {
	handshake = handshake ;
}
