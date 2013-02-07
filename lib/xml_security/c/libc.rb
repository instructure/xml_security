module XMLSecurity
  module C
    module LibC
      extend FFI::Library
      ffi_lib [FFI::CURRENT_PROCESS, 'c']

      attach_function :malloc, [:size_t], :pointer
      attach_function :free, [:pointer], :void
    end
  end
end
