NR_OPEN        =   1024

NGROUPS_MAX    =  65536 -- supplemental group IDs are available
ARG_MAX        = 131072 -- # bytes of args + environ for exec()
LINK_MAX       =    127 -- # links a file may have
MAX_CANON      =    255 -- size of the canonical input queue
MAX_INPUT      =    255 -- size of the type-ahead buffer
NAME_MAX       =    255 -- # chars in a file name
PATH_MAX       =   4096 -- # chars in a path name including nul
PIPE_BUF       =   4096 -- # bytes in atomic write to a pipe
XATTR_NAME_MAX =    255 -- # chars in an extended attribute name
XATTR_SIZE_MAX =  65536 -- size of an extended attribute value (64k)
XATTR_LIST_MAX =  65536 -- size of extended attribute namelist (64k)

RTSIG_MAX      =     32
