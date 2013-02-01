require 'ffi'

module XMLSecurity
  module C
    module XMLSec
      extend FFI::Library
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
          :signValueNode,               :pointer,     # xmlNodePtr
          :id,                          :string,
          :signedInfoReferences,        XmlSecPtrList,
          :manifestReferences,          XmlSecPtrList,
          :reserved0,                   :pointer,
          :reserved1,                   :pointer
      end

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

      def self.init
        raise "Failed initializing XMLSec" if self.xmlSecInit < 0
        raise "Failed initializing app crypto" if self.xmlSecOpenSSLAppInit(nil) < 0
        raise "Failed initializing crypto" if self.xmlSecOpenSSLInit < 0
      end
    end
  end
end
