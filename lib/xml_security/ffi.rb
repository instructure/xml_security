require 'ffi'

module XMLSecurity
  module FFI
    extend ::FFI::Library

    def self.included(base)
      load_libs
      define_enums
      puts "SELF IS #{self.name}"
      define_structs
      attach_functions
      init_xml_sec
    end

    def self.load_libs
      ffi_lib "xmlsec1-openssl"
    end

    def self.define_enums
      enum :xmlSecKeyDataFormat, [
        :xmlSecKeyDataFormatUnknown,
        :xmlSecKeyDataFormatBinary,
        :xmlSecKeyDataFormatPem,
        :xmlSecKeyDataFormatDer,
        :xmlSecKeyDataFormatPkcs8Pem,
        :xmlSecKeyDataFormatPkcs8Der,
        :xmlSecKeyDataFormatPkcs12,
        :xmlSecKeyDataFormatCertPem,
        :xmlSecKeyDataFormatCertDer
      ]

      enum :xmlSecKeyInfoMode, [
        :xmlSecKeyInfoModeRead,
        :xmlSecKeyInfoModeWrite
      ]

      enum :xmlSecAllocMode, [
        :xmlSecAllocModeExact,
        :xmlSecAllocModeDouble
      ]

      enum :xmlSecTransformStatus, [
        :xmlSecTransformStatusNone,
        :xmlSecTransformStatusWorking,
        :xmlSecTransformStatusFinished,
        :xmlSecTransformStatusOk,
        :xmlSecTransformStatusFail
      ]

      enum :xmlSecTransformOperation, [
        :xmlSecTransformOperationNone, 0,
        :xmlSecTransformOperationEncode,
        :xmlSecTransformOperationDecode,
        :xmlSecTransformOperationSign,
        :xmlSecTransformOperationVerify,
        :xmlSecTransformOperationEncrypt,
        :xmlSecTransformOperationDecrypt
      ]

      enum :xmlSecDSigStatus, [
        :xmlSecDSigStatusUnknown, 0,
        :xmlSecDSigStatusSucceeded,
        :xmlSecDSigStatusInvalid
      ]
      debugger
    end

    def self.define_structs
      require 'xml_security/xml_sec_ptr_list'
      require 'xml_security/xml_sec_key_info_ctx'
      require 'xml_security/xml_sec_d_sig_ctx'
      require 'xml_security/xml_sec_key_req'
      require 'xml_security/xml_sec_transform_ctx'
    end

    def self.attach_functions
      # xmlsec functions
      attach_function :xmlSecInit, [], :int
      attach_function :xmlSecParseMemory, [ :pointer, :uint, :int ], :pointer
      attach_function :xmlSecFindNode, [ :pointer, :string, :string ], :pointer
      attach_function :xmlSecDSigCtxCreate, [ :pointer ], XmlSecDSigCtx.by_ref
      attach_function :xmlSecDSigCtxVerify, [ XmlSecDSigCtx.by_ref, :pointer ], :int
      attach_function :xmlSecOpenSSLInit, [], :int
      attach_function :xmlSecOpenSSLAppInit, [ :pointer ], :int
      attach_function :xmlSecAddIDs, [ :pointer, :pointer, :pointer ], :void
      attach_function :xmlSecDSigCtxDestroy, [ XmlSecDSigCtx.by_ref ], :void

      attach_function :xmlSecKeysMngrCreate, [], :pointer
      attach_function :xmlSecOpenSSLAppDefaultKeysMngrInit, [ :pointer ], :int
      attach_function :xmlSecOpenSSLAppKeyLoad, [ :string, :xmlSecKeyDataFormat, :pointer, :pointer, :pointer ], :pointer
      attach_function :xmlSecOpenSSLAppKeyLoadMemory, [ :pointer, :uint, :xmlSecKeyDataFormat, :pointer, :pointer, :pointer ], :pointer
      attach_function :xmlSecOpenSSLAppDefaultKeysMngrAdoptKey, [ :pointer, :pointer ], :int
      attach_function :xmlSecKeysMngrDestroy, [ :pointer ], :void

      attach_function :xmlSecEncCtxCreate, [ :pointer ], :pointer
      attach_function :xmlSecEncCtxDecrypt, [ :pointer, :pointer ], :int
      attach_function :xmlSecEncCtxDestroy, [ :pointer ], :void

      # libxml functions
      attach_function :xmlInitParser, [], :void
      attach_function :xmlDocGetRootElement, [ :pointer ], :pointer
      attach_function :xmlDocDumpFormatMemory, [ :pointer, :pointer, :pointer, :int ], :void
      attach_function :xmlFreeDoc, [ :pointer ], :void
    end

    def self.init_xml_sec
      self.xmlInitParser
      raise "Failed initializing XMLSec" if self.xmlSecInit < 0
      raise "Failed initializing app crypto" if self.xmlSecOpenSSLAppInit(nil) < 0
      raise "Failed initializing crypto" if self.xmlSecOpenSSLInit < 0
    end
  end
end
