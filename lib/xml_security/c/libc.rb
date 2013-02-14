module XMLSecurity
  module C
    module LibC
      extend FFI::Library
      ffi_lib [FFI::CURRENT_PROCESS, 'c']

      typedef :pointer, :FILE

      attach_function :malloc, [:size_t], :pointer
      attach_function :free, [:pointer], :void
      attach_function :fopen, [:string, :string], :FILE
      attach_function :fclose, [:FILE], :int
    end
  end
end
