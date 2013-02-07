module XMLSecurity
  module C
    module LibXML
      extend FFI::Library
      ffi_lib 'libxml2'

      class XmlNode < FFI::Struct
        layout \
           :_private,   :pointer,
           :type,       :int,          # <- cheating, actually an xmlElementType enum
           :name,       :string,
           :children,   XmlNode.by_ref,
           :last,       :pointer,
           :parent,     :pointer,
           :next,       :pointer,
           :prev,       :pointer,
           :doc,        :pointer,

           :ns,         :pointer,
           :content,    :string,
           :properties, :pointer,
           :nsDef,      :pointer,
           :psvi,       :pointer,
           :line,       :ushort,
           :extra,      :ushort
      end

      # libxml functions
      attach_function :xmlInitParser, [], :void
      attach_function :xmlDocGetRootElement, [ :pointer ], :pointer
      attach_function :xmlDocDumpFormatMemory, [ :pointer, :pointer, :pointer, :int ], :void
      attach_function :xmlFreeDoc, [ :pointer ], :void
      attach_function :xmlParseFile, [ :string ], :pointer
      attach_function :xmlParseMemory, [ :pointer, :int ], :pointer
      attach_function :xmlAddChild, [ :pointer, :pointer ], :pointer
      attach_function :xmlCleanupParser, [], :void
      attach_function :xmlNodeGetContent, [ :pointer ], :pointer # xmlChar *

      #
      # Patching over to straight libc malloc/free until we can figure out why
      # xml{Malloc,Free} cause ruby to blow up so spectacularly. See the
      # following thread for more info:
      #
      # https://groups.google.com/d/topic/ruby-ffi/wClez3YsLQE/discussion
      #
      # attach_function :xmlFree, [ :pointer ], :void
      # attach_function :xmlMalloc, [ :int ], :pointer

      def self.xmlMalloc(*args)
        C::LibC.malloc(*args)
      end

      def self.xmlFree(*args)
        C::LibC.free(*args)
      end

      def self.init
        xmlInitParser
      end

      def self.shutdown
        xmlCleanupParser
      end
    end
  end
end
