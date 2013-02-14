module XMLSecurity
  class SignatureVerifier
    extend Common
    set_exception_class SignatureVerificationException

    def self.verify_signature(signed_xml_document, options={})
      doc = C::LibXML.xmlParseMemory(signed_xml_document, signed_xml_document.size)
      _assert_pointer(doc, 'could not parse XML document')

      doc_root = C::LibXML.xmlDocGetRootElement(doc)
      _assert_pointer(doc_root, 'could not get doc root')

      # add the ID attribute as an id. yeah, hacky
      idary = FFI::MemoryPointer.new(:pointer, 2)
      idary[0].put_pointer(0, FFI::MemoryPointer.from_string("ID"))
      idary[1].put_pointer(0, nil)
      C::XMLSec.xmlSecAddIDs(doc, doc_root, idary)

      keys_manager = _init_keys_manager

      digital_signature_context = _assert_pointer(
        C::XMLSec.xmlSecDSigCtxCreate(keys_manager),
        'failed to create signature context'
      )

      key_info_context = _assert_pointer(
        C::XMLSec.xmlSecKeyInfoCtxCreate(keys_manager),
        'failed to create key info context'
      )

      signature_node = _assert_pointer(
        C::XMLSec.xmlSecFindNode(doc_root, C::XMLSec.xmlSecNodeSignature, C::XMLSec.xmlSecDSigNs),
        'signature node not found'
      )

      cert = _extract_cert(signature_node)

      _assert_fingerprint_matches(options[:cert_fingerprint], cert) if options.has_key? :cert_fingerprint

      if options.has_key? :as_of
        digital_signature_context[:keyInfoReadCtx][:certsVerificationTime] = Time.parse(options[:as_of]).to_i
      end

      _assert_success(
        C::XMLSec.xmlSecOpenSSLAppKeysMngrCertLoadMemory(keys_manager, cert, cert.size, :xmlSecKeyDataFormatCertDer, C::XMLSec.xmlSecKeyDataTypeTrusted),
        'failed to add key to keys manager'
      )

      _assert_success(
        C::XMLSec.xmlSecDSigCtxVerify(digital_signature_context, signature_node),
        'error during signature verification'
      )

      SignatureVerificationResult.for_boolean(digital_signature_context[:status] == :xmlSecDSigStatusSucceeded)

    rescue SignatureVerificationException => e
      SignatureVerificationResult.for_exception(e)
    ensure
      C::LibXML.xmlFreeDoc(doc) if defined?(doc) && doc && !doc.null?
      C::XMLSec.xmlSecDSigCtxDestroy(digital_signature_context) if defined?(digital_signature_context) && digital_signature_context && !digital_signature_context.null?
      C::XMLSec.xmlSecKeysMngrDestroy(keys_manager) if defined?(keys_manager) && keys_manager && !keys_manager.null?
      C::XMLSec.xmlSecKeyInfoCtxDestroy(key_info_context) if defined?(key_info_context) && key_info_context && !key_info_context.null?
      C::XMLSec.xmlSecKeyDestroy(key) if defined?(key) && key && !key.null?
    end

    def self._debug_dump_all_transforms
      size = C::XMLSec.xmlSecPtrListGetSize(C::XMLSec.xmlSecTransformIdsGet)

      (0..(size-1)).each do |i|
        item = C::XMLSec.xmlSecPtrListGetItem(C::XMLSec.xmlSecTransformIdsGet, i)
        unless item.null?
          transform = C::XMLSec::XmlSecTransformId.new item
          p transform[:href]
        end
      end
    end

    def self._extract_cert(signature_node)
      certificate_node = _assert_pointer(
        C::XMLSec.xmlSecFindNode(signature_node, C::XMLSec.xmlSecNodeX509Certificate, C::XMLSec.xmlSecDSigNs),
        'certificate node not found'
      )

      cert64ptr = _assert_pointer(
        C::LibXML.xmlNodeGetContent(certificate_node),
        'error while reading certificate node'
      )
      cert64 = cert64ptr.read_string
      C::LibXML.xmlFree(cert64ptr)

      Base64.decode64(cert64)
    end

    def self._assert_fingerprint_matches(expected_fingerprint, cert)
      openssl_cert = OpenSSL::X509::Certificate.new(cert)
      cert_fingerprint = Digest::SHA1.hexdigest(openssl_cert.to_der)
      expected_fingerprint = expected_fingerprint.gsub(":", "").downcase
      unless cert_fingerprint == expected_fingerprint
        raise FingerprintMismatchError.new(expected_fingerprint, cert_fingerprint)
      end
    end
  end
end
