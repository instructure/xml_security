require 'ffi'

module XMLSecurity
  module C
    module XMLSecApp
      extend FFI::Library
      ffi_lib_flags :now, :global
      ffi_lib 'xmlsec1'

      attach_function :xmlSecCryptoDLGetFunctions, [], :pointer
    end
  end
end

