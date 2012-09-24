local ffi = require "ffi"

ffi.cdef [[
void ERR_load_PEM_strings(void);
]]
