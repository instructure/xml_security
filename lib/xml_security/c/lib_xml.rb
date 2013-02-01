require 'ffi'

module XMLSecurity
  module C
    module LibXML
      extend FFI::Library
      ffi_lib 'libxml2'

      # libxml functions
      attach_function :xmlInitParser, [], :void
      attach_function :xmlDocGetRootElement, [ :pointer ], :pointer
      attach_function :xmlDocDumpFormatMemory, [ :pointer, :pointer, :pointer, :int ], :void
      attach_function :xmlFreeDoc, [ :pointer ], :void
      attach_function :xmlParseFile, [ :string ], :pointer
      attach_function :xmlParseMemory, [ :pointer, :int ], :pointer
      attach_function :xmlAddChild, [ :pointer, :pointer ], :pointer

      def self.init
        xmlInitParser
      end
    end
  end
end
