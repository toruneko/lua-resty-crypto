-- Copyright (C) by Jianhao Dai (Toruneko)

local ffi = require "ffi"
local bit = require "bit"
local band = bit.band
local ffi_new = ffi.new
local ffi_str = ffi.string
local C = ffi.C
local tab_concat = table.concat

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
unsigned long ERR_get_error(void);
const char *ERR_reason_error_string(unsigned long e);
void ERR_clear_error(void);

unsigned long ERR_get_error_line_data(const char **file, int *line,
                                      const char **data, int *flags);
]]

local ERR_TXT_STRING = 0x02

function _M.get_error()
    local err_queue = {}
    local i = 1
    local data = ffi_new("const char*[1]")
    local flags = ffi_new("int[1]")

    while true do
        local code = C.ERR_get_error_line_data(nil, nil, data, flags)
        if code == 0 then
            break
        end

        local err = C.ERR_reason_error_string(code)
        err_queue[i] = ffi_str(err)
        i = i + 1

        if data[0] ~= nil and band(flags[0], ERR_TXT_STRING) > 0 then
            err_queue[i] = ffi_str(data[0])
            i = i + 1
        end
    end

    return tab_concat(err_queue, ": ", 1, i - 1)
end

return _M