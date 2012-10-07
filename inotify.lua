local bit = require "bit"
local ffi = require "ffi"
local new_file = require "fend.file".wrap
require "fend.common"
include "string"
include "sys/inotify"
include "linux/limits"

local watcher_methods = { }
local watcher_mt = {
	__index = watcher_methods ;
}

local event_size = ffi.sizeof ( "struct inotify_event" )
local event_max_size = event_size + defines.NAME_MAX + 1
local global_buff = ffi.new ( "char[?]" , event_max_size )

local i_fd_map = setmetatable ( { } , { __mode = "k" } )

local i_cb_table = {
	read = function ( file , read_cbs )
		local r = tonumber ( ffi.C.read ( file:getfd() , global_buff , event_max_size ) )
		if r == -1 then
			local err = ffi.errno ( )
			if err == defines.EAGAIN then
				return
			else
				error ( ffi.string ( ffi.C.strerror ( err ) ) )
			end
		end

		local self = i_fd_map [ file ]

		local buff = global_buff
		while r > 0 do
			local event = ffi.cast ( "struct inotify_event*" , buff )
			local actual_size = event_size + event.len

			local watcher = self [ event.wd ]
			if watcher then
				local mask = event.mask

				local name -- name field is only present when an event is returned for a file inside a watched directory
				if event.len > 0 then
					name = ffi.string ( event.name , event.len-1 )
				end
				local cbs = watcher.cbs

				if bit.band ( mask , defines.IN_ACCESS        ) ~= 0 and cbs.access then
					cbs.access      ( watcher , name )
				end
				if bit.band ( mask , defines.IN_ATTRIB        ) ~= 0 and cbs.attrib then
					cbs.attrib      ( watcher , name )
				end
				if bit.band ( mask , defines.IN_CLOSE_WRITE   ) ~= 0 and ( cbs.close_write   or cbs.close ) then
					( cbs.close_write   or cbs.close ) ( watcher , name )
				end
				if bit.band ( mask , defines.IN_CLOSE_NOWRITE ) ~= 0 and ( cbs.close_nowrite or cbs.close ) then
					( cbs.close_nowrite or cbs.close ) ( watcher , name )
				end
				if bit.band ( mask , defines.IN_CREATE        ) ~= 0 and cbs.create then
					cbs.create      ( watcher , name )
				end
				if bit.band ( mask , defines.IN_DELETE        ) ~= 0 and cbs.delete then
					cbs.delete      ( watcher , name )
				end
				if bit.band ( mask , defines.IN_DELETE_SELF   ) ~= 0 and cbs.delete_self then
					cbs.delete_self ( watcher , name )
				end
				if bit.band ( mask , defines.IN_MODIFY        ) ~= 0 and cbs.modify then
					cbs.modify      ( watcher , name )
				end
				if bit.band ( mask , defines.IN_MOVE_SELF     ) ~= 0 and cbs.move_self then
					cbs.move_self   ( watcher , name )
				end
				if bit.band ( mask , defines.IN_MOVED_FROM    ) ~= 0 and cbs.moved_from then
					cbs.moved_from  ( watcher , name , event.cookie )
				end
				if bit.band ( mask , defines.IN_MOVED_TO      ) ~= 0 and cbs.moved_to then
					cbs.moved_to    ( watcher , name , event.cookie )
				end
				if bit.band ( mask , defines.IN_OPEN          ) ~= 0 and cbs.open then
					cbs.open        ( watcher , name )
				end
			end

			r    = r    - actual_size
			buff = buff + actual_size
		end

		return read_cbs.read ( file , read_cbs ) -- Call self until EAGAIN
	end ;
	close = function ( file , cbs )
		error ( "inotify closed" )
	end ;
	error = function ( file , cbs )
		error ( "inotify error" )
	end ;
	edge = true ;
}

local function new_inotify ( dispatcher )
	local i_fd = ffi.C.inotify_init1 ( ffi.C.IN_NONBLOCK )
	if i_fd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	i_fd = new_file ( i_fd )

	local self = {
		i_fd = i_fd ;
		-- numeric keys are wds
	}
	i_fd_map [ i_fd ] = self

	dispatcher:add_fd ( i_fd , i_cb_table )

	return self
end

local function cbs_to_mask ( cbs )
	return bit.bor (
		-- Actual callbacks
		cbs.access                         and defines.IN_ACCESS        or 0,
		cbs.attrib                         and defines.IN_ATTRIB        or 0,
		( cbs.close_write   or cbs.close ) and defines.IN_CLOSE_WRITE   or 0,
		( cbs.close_nowrite or cbs.close ) and defines.IN_CLOSE_NOWRITE or 0,
		cbs.create                         and defines.IN_CREATE        or 0,
		cbs.delete                         and defines.IN_DELETE        or 0,
		cbs.delete_self                    and defines.IN_DELETE_SELF   or 0,
		cbs.modify                         and defines.IN_MODIFY        or 0,
		cbs.move_self                      and defines.IN_MOVE_SELF     or 0,
		cbs.moved_from                     and defines.IN_MOVED_FROM    or 0,
		cbs.moved_to                       and defines.IN_MOVED_TO      or 0,
		cbs.open                           and defines.IN_OPEN          or 0,
		-- Flags
		cbs.dont_follow                    and defines.IN_DONT_FOLLOW   or 0,
		cbs.excl_unlink                    and defines.IN_EXCL_UNLINK   or 0,
		cbs.mask_add                       and defines.IN_MASK_ADD      or 0,
		cbs.oneshot                        and defines.IN_ONESHOT       or 0,
		cbs.onlydir                        and defines.IN_ONLYDIR       or 0
		)
end

local function add_path ( dispatcher , path , cbs )
	local self = dispatcher.inotify

	local mask = cbs_to_mask ( cbs )
	local wd = ffi.C.inotify_add_watch ( self.i_fd:getfd() , path , mask )
	if wd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end

	local watcher = setmetatable ( {
			inotify = self ;
			wd      = wd ;
			path    = path ;
			cbs     = cbs ;
		} , watcher_mt )

	self [ wd ] = watcher

	return watcher
end

function watcher_methods:edit ( cbs )
	local mask = cbs_to_mask ( cbs )
	if ffi.C.inotify_add_watch ( self.inotify.i_fd , self.path , mask ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.cbs = cbs
end

function watcher_methods:rm ( )
	if ffi.C.inotify_rm_watch ( self.inotify.i_fd , self.wd ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end
watcher_methods.del = watcher_methods.rm

return {
	new = new_inotify ;
	add = add_path ;
}
