include "sys/socket"

require "ffi".cdef [[
struct sockaddr_un
  {
    sa_family_t sun_family;
    char sun_path[108];
  };
]]

