module XMLSecurity
  module Common
    def set_exception_class(exception_class)
      @exception_class = exception_class
    end

    def exception_class
      raise XMLSecurity::Exception.new("must set exception_class for #{self.name}") unless @exception_class
      @exception_class
    end

    def _init_keys_manager
      keys_manager = C::XMLSec.xmlSecKeysMngrCreate
      raise "failed to create keys manager" if keys_manager.null?

      if C::XMLSec.xmlSecOpenSSLAppDefaultKeysMngrInit(keys_manager) < 0
        raise "failed to init and load default openssl keys into keys manager"
      end

      keys_manager
    end

    def _assert(expression, error_message)
     unless expression
        raise exception_class.new(error_message)
      end
    end

    def _assert_pointer(pointer, error_message)
      _assert(!pointer.null?, error_message)
      pointer
    end

    def _assert_success(exit_code, error_message)
      _assert(exit_code >= 0, error_message)
    end

    def _dump_doc(doc)
      ptr = FFI::MemoryPointer.new(:pointer, 1)
      sizeptr = FFI::MemoryPointer.new(:pointer, 1)
      C::LibXML.xmlDocDumpFormatMemory(doc, ptr, sizeptr, 1)
      strptr = ptr.read_pointer
      result = strptr.null? ? nil : strptr.read_string

      result
    ensure
      ptr.free if defined?(ptr) && ptr
      sizeptr.free if defined?(sizeptr) && sizeptr
      C::LibXML.xmlFree(strptr) if defined?(strptr) && strptr && !strptr.null?
    end
  end
end
