module XMLSecurity
  class DocumentSigner
    extend Common

    def self.sign(xml_document, private_key)
      doc = C::LibXML.xmlParseMemory(xml_document, xml_document.size)
      raise SignatureFailure.new("could not parse XML document") if doc.null?

      canonicalization_method_id = C::XMLSec.xmlSecTransformExclC14NGetKlass
      sign_method_id = C::XMLSec.xmlSecOpenSSLTransformRsaSha1GetKlass

      sign_node = C::XMLSec.xmlSecTmplSignatureCreate(doc, canonicalization_method_id, sign_method_id, nil)

      raise SignatureFailure.new("failed to create signature template") if sign_node.null?
      C::LibXML.xmlAddChild(C::LibXML.xmlDocGetRootElement(doc), sign_node)

      ref_node = C::XMLSec.xmlSecTmplSignatureAddReference(sign_node, C::XMLSec.xmlSecOpenSSLTransformSha1GetKlass, nil, nil, nil)
      raise SignatureFailure.new("failed to add a reference") if ref_node.null?

      envelope_result = C::XMLSec.xmlSecTmplReferenceAddTransform(ref_node, C::XMLSec.xmlSecTransformEnvelopedGetKlass)
      raise SignatureFailure.new("failed to add envelope transform to reference") if envelope_result.null?

      key_info_node = C::XMLSec.xmlSecTmplSignatureEnsureKeyInfo(sign_node, nil)
      raise SignatureFailure.new("failed to add key info") if key_info_node.null?

      digital_signature_context = C::XMLSec.xmlSecDSigCtxCreate(nil)
      raise SignatureFailure.new("failed to create signature context") if digital_signature_context.null?

      digital_signature_context[:signKey] = C::XMLSec.xmlSecOpenSSLAppKeyLoad(private_key, :xmlSecKeyDataFormatPem, nil, nil, nil)
      raise SignatureFailure.new("failed to load private pem ley from #{private_key}") if digital_signature_context[:signKey].null?

      if C::XMLSec.xmlSecKeySetName(digital_signature_context[:signKey], File.basename(private_key)) < 0
        raise SignatureFailure.new("failed to set key name for key of #{private_key}")
      end

      if C::XMLSec.xmlSecTmplKeyInfoAddKeyName(key_info_node, nil).null?
        raise SignatureFailure.new("failed to add key info")
      end

      if C::XMLSec.xmlSecDSigCtxSign(digital_signature_context, sign_node) < 0
        raise SignatureFailure.new("signature failed!")
      end

      _dump_doc(doc)
    ensure
      C::LibXML.xmlFreeDoc(doc) if defined?(doc) && !doc.null?
      C::XMLSec.xmlSecDSigCtxDestroy(digital_signature_context) if defined?(digital_signature_context) && !digital_signature_context.null?
    end
  end
end
