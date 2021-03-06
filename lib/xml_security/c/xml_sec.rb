require 'ffi'

module XMLSecurity
  module C
    module XMLSec
      extend FFI::Library
      ffi_lib_flags :now, :global
      ffi_lib 'xmlsec1-openssl'

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

      class XmlSecPtrList < FFI::Struct
        layout \
          :id,                          :string,
          :data,                        :pointer,        # xmlSecPtr*
          :use,                         :uint,
          :max,                         :uint,
          :allocMode,                   :xmlSecAllocMode
      end

      class XmlSecKeyReq < FFI::Struct
        layout \
          :keyId,                       :string,         # xmlSecKeyDataId
          :keyType,                     :uint,           # xmlSecKeyDataType
          :keyUsage,                    :uint,           # xmlSecKeyUsage
          :keyBitsSize,                 :uint,           # xmlSecSize
          :keyUseWithList,              XmlSecPtrList,
          :reserved1,                   :pointer,        # void *
          :reserved2,                   :pointer         # void *
      end

      class XmlSecTransformId < FFI::Struct
        layout \
           :klassSize,   :uint,
           :objSize,     :uint,

           :name,        :string,
           :href,        :string,
           :usage,       :uint,

           :initialize,  :pointer,
           :finalize,    :pointer,

           :readNode,    :pointer,
           :writeNode,   :pointer,

           :setKeyReq,   :pointer,
           :setKey,      :pointer,
           :verify,      :pointer,
           :getDataType, :pointer,

           :pushBin,     :pointer,
           :popBin,      :pointer,
           :pushXml,     :pointer,
           :popXml,      :pointer,

           :execute,     :pointer,

           :reserved0,   :pointer,
           :reserved1,   :pointer
      end

      class XmlSecTransformCtx < FFI::Struct
        layout \
          :userData,                    :pointer,        # void *
          :flags,                       :uint,
          :flags2,                      :uint,
          :enabledUris,                 :uint,
          :enabledTransforms,           XmlSecPtrList,
          :preExecCallback,             :pointer,        # xmlSecTransformCtxPreExecuteCallback
          :result,                      :pointer,        # xmlSecBufferPtr
          :status,                      :xmlSecTransformStatus,
          :uri,                         :string,
          :xptrExpr,                    :string,
          :first,                       :pointer,        # xmlSecTransformPtr
          :last,                        :pointer,        # xmlSecTransformPtr
          :reserved0,                   :pointer,        # void *
          :reserved1,                   :pointer         # void *
      end

      class XmlSecKeyInfoCtx < FFI::Struct
        layout \
          :userDate,                    :pointer,
          :flags,                       :uint,
          :flags2,                      :uint,
          :keysMngr,                    :pointer,
          :mode,                        :xmlSecKeyInfoMode,
          :enabledKeyData,              XmlSecPtrList,
          :base64LineSize,              :int,
          :retrievalMethodCtx,          XmlSecTransformCtx,
          :maxRetrievalMethodLevel,     :int,
          :encCtx,                      :pointer,
          :maxEncryptedKeyLevel,        :int,
          :certsVerificationTime,       :time_t,
          :certsVerificationDepth,      :int,
          :pgpReserved,                 :pointer,
          :curRetrievalMethodLevel,     :int,
          :curEncryptedKeyLevel,        :int,
          :keyReq,                      XmlSecKeyReq,
          :reserved0,                   :pointer,
          :reserved1,                   :pointer
      end

      # Would like to use this eventually, but something is wrong below; get segfaults when trying to use it.
      class XmlSecKeyPtr < FFI::Struct
        layout \
           :name,           :string,  # xmlChar *
           :value,          :pointer, # xmlSecKeyDataPtr
           :dataList,       :pointer, # xmlSecPtrListPtr
           :usage,          :pointer, # xmlSecKeyUsage
           :notValidBefore, :pointer, # time_t
           :notValidAfter,  :pointer  # time_t
      end

      class XmlSecDSigCtx < FFI::Struct
        layout \
          :userData,                    :pointer,     # void *
          :flags,                       :uint,
          :flags2,                      :uint,
          :keyInfoReadCtx,              XmlSecKeyInfoCtx.by_value,
          :keyInfoWriteCtx,             XmlSecKeyInfoCtx.by_value,
          :transformCtx,                XmlSecTransformCtx.by_value,
          :enabledReferenceUris,        :uint,        # xmlSecTransformUriType
          :enabledReferenceTransforms,  :pointer,     # xmlSecPtrListPtr
          :referencePreExecuteCallback, :pointer,     # xmlSecTransformCtxPreExecuteCallback
          :defSignMethodId,             :string,      # xmlSecTransformId
          :defC14NMethodId,             :string,      # xmlSecTransformId
          :defDigestMethodId,           :string,      # xmlSecTransformId

          :signKey,                     :pointer,     # xmlSecKeyPtr
          :operation,                   :xmlSecTransformOperation,
          :result,                      :pointer,     # xmlSecBufferPtr
          :status,                      :xmlSecDSigStatus,
          :signMethod,                  :pointer,     # xmlSecTransformPtr
          :c14nMethod,                  :pointer,     # xmlSecTransformPtr
          :preSignMemBufMethod,         :pointer,     # xmlSecTransformPtr
          :signValueNode,               LibXML::XmlNode.by_ref,     # xmlNodePtr
          :id,                          :string,
          :signedInfoReferences,        XmlSecPtrList,
          :manifestReferences,          XmlSecPtrList,
          :reserved0,                   :pointer,
          :reserved1,                   :pointer
      end

      # xmlsec functions
      attach_function :xmlSecInit, [], :int
      attach_function :xmlSecParseMemory, [ :pointer, :uint, :int ], :pointer
      attach_function :xmlSecFindNode, [ :pointer, :string, :string ], LibXML::XmlNode.by_ref
      attach_function :xmlSecFindChild, [ :pointer, :string, :string ], :pointer
      attach_function :xmlSecDSigCtxCreate, [ :pointer ], XmlSecDSigCtx.by_ref
      attach_function :xmlSecDSigCtxVerify, [ XmlSecDSigCtx.by_ref, :pointer ], :int
      attach_function :xmlSecOpenSSLInit, [], :int
      attach_function :xmlSecOpenSSLShutdown, [], :int
      attach_function :xmlSecOpenSSLAppShutdown, [], :int
      attach_function :xmlSecOpenSSLAppInit, [ :pointer ], :int
      attach_function :xmlSecAddIDs, [ :pointer, :pointer, :pointer ], :void
      attach_function :xmlSecDSigCtxDestroy, [ XmlSecDSigCtx.by_ref ], :void

      attach_function :xmlSecKeysMngrCreate, [], :pointer
      attach_function :xmlSecOpenSSLAppDefaultKeysMngrInit, [ :pointer ], :int
      attach_function :xmlSecOpenSSLAppKeyLoad, [ :string, :xmlSecKeyDataFormat, :pointer, :pointer, :pointer ], :pointer
      attach_function :xmlSecOpenSSLAppKeyLoadMemory, [ :pointer, :uint, :xmlSecKeyDataFormat, :pointer, :pointer, :pointer ], :pointer
      attach_function :xmlSecOpenSSLAppKeysMngrCertLoadMemory, [ :pointer, :pointer, :uint, :xmlSecKeyDataFormat, :uint ], :int

      attach_function :xmlSecOpenSSLAppDefaultKeysMngrAdoptKey, [ :pointer, :pointer ], :int
      attach_function :xmlSecKeysMngrDestroy, [ :pointer ], :void

      attach_function :xmlSecEncCtxCreate, [ :pointer ], :pointer
      attach_function :xmlSecEncCtxDecrypt, [ :pointer, :pointer ], :int
      attach_function :xmlSecEncCtxDestroy, [ :pointer ], :void

      attach_function :xmlSecTmplSignatureCreate, [ :pointer, :pointer, :pointer, :string ], :pointer
      attach_function :xmlSecTmplSignatureAddReference, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :pointer

      attach_function :xmlSecTransformExclC14NGetKlass, [], :pointer
      attach_function :xmlSecOpenSSLTransformRsaSha1GetKlass, [], :pointer
      attach_function :xmlSecOpenSSLTransformSha1GetKlass, [], :pointer
      attach_function :xmlSecTransformEnvelopedGetKlass, [], :pointer
      attach_function :xmlSecTmplSignatureEnsureKeyInfo, [ :pointer, :pointer ], :pointer

      attach_function :xmlSecTmplReferenceAddTransform, [ :pointer, :pointer ], :pointer

      attach_function :xmlSecKeySetName, [ :pointer, :string ], :int

      attach_function :xmlSecDSigCtxSign, [ :pointer, :pointer ], :int

      attach_function :xmlSecTmplKeyInfoAddKeyName, [ :pointer, :pointer ], :pointer
      attach_function :xmlSecKeyInfoCtxCreate, [ :pointer ], XmlSecKeyInfoCtx.by_ref
      attach_function :xmlSecKeyInfoCtxDestroy, [ XmlSecKeyInfoCtx.by_ref ], :void
      attach_function :xmlSecKeyInfoNodeRead, [ :pointer, :pointer, :pointer ], :int

      attach_function :xmlSecKeyCreate, [], :pointer
      attach_function :xmlSecKeyDestroy, [ :pointer ], :void

      attach_function :xmlSecBase64Decode, [ :pointer, :pointer, :uint ], :int

      attach_function :xmlSecShutdown, [], :void

      attach_function :xmlSecErrorsDefaultCallbackEnableOutput, [ :bool ], :void

      attach_function :xmlSecErrorsSetCallback, [:pointer], :void

      attach_function :xmlSecDSigCtxDebugDump, [:pointer, :pointer], :void
      attach_function :xmlSecPtrListDebugDump, [:pointer, :pointer], :void
      attach_function :xmlSecPtrListGetSize, [:pointer], :size_t
      attach_function :xmlSecPtrListGetItem, [:pointer, :size_t], :pointer
      attach_function :xmlSecTransformIdsGet, [], XmlSecTransformId.by_ref
      attach_function :xmlSecTransformIdListFindByHref, [:pointer, :string, :uint], XmlSecTransformId.by_ref
      attach_function :xmlSecTransformIdsRegister, [XmlSecTransformId.by_ref], :int

      attach_function :xmlSecOpenSSLAppDefaultKeysMngrInit, [:pointer], :int

      XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS = 0x00000200
      XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS = 0x00004000

      XMLSEC_ERRORS_R_INVALID_DATA = 12
      XMLSEC_ERRORS_R_DATA_NOT_MATCH = 18

      XMLSEC_TRANSFORM_USAGE_ANY = 0xFFFF

      ErrorCallback = FFI::Function.new(:void,
          [ :string, :int, :string, :string,     :string,      :int,   :string ]
      ) do |file,    line, func,    errorObject, errorSubject, reason, msg     |
        XMLSecurity::Exception.handle_xmlsec_error_callback(file, line, func, errorObject, errorSubject, reason, msg)
      end

      def self.xmlSecNodeSignature
        'Signature'
      end

      def self.xmlSecNodeKeyInfo
        'KeyInfo'
      end

      def self.xmlSecNodeX509Certificate
        'X509Certificate'
      end

      def self.xmlSecDSigNs
        'http://www.w3.org/2000/09/xmldsig#'
      end

      def self.xmlSecEncNs
        'http://www.w3.org/2001/04/xmlenc#'
      end

      def self.xmlSecKeyDataTypeTrusted
        0x0100
      end

      def self.xmlSecNodeEncryptedData
        'EncryptedData'
      end

      def self.xmlSecNodeX509Certificate
        'X509Certificate'
      end

      def self.init
        raise "Failed initializing XMLSec" if xmlSecInit < 0
        raise "Failed initializing app crypto" if xmlSecOpenSSLAppInit(nil) < 0
        raise "Failed initializing crypto" if xmlSecOpenSSLInit < 0
        xmlSecErrorsSetCallback(ErrorCallback)
      end

      def self.shutdown
        xmlSecOpenSSLShutdown
        xmlSecOpenSSLAppShutdown
        xmlSecShutdown
      end
    end
  end
end
