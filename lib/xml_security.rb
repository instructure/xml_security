# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.
#
require 'rubygems'
require 'ffi'

require 'xml_security/c/libc'
require 'xml_security/c/lib_xml'
require 'xml_security/c/xml_sec'

require 'time'
require 'base64'

module XMLSecurity
  NAMESPACES = {
    "xenc" => "http://www.w3.org/2001/04/xmlenc#",
    "ds" => "http://www.w3.org/2000/09/xmldsig#"
  }

  def self.init
    unless initialized?
      C::LibXML.init
      C::XMLSec.init
      @initialized = true
    end
  end

  def self.shutdown
    if initialized?
      C::XMLSec.shutdown
      C::LibXML.shutdown
      @initialized = false
    end
  end

  def self.initialized?
    !!@initialized
  end

  def self.sign(xml_document, private_key)
    init

    doc = C::LibXML.xmlParseMemory(xml_document, xml_document.size)
    raise "could not parse XML document" if doc.null?

    canonicalization_method_id = C::XMLSec.xmlSecTransformExclC14NGetKlass
    sign_method_id = C::XMLSec.xmlSecOpenSSLTransformRsaSha1GetKlass

    sign_node = C::XMLSec.xmlSecTmplSignatureCreate(doc, canonicalization_method_id, sign_method_id, nil)

    raise "failed to create signature template" if sign_node.null?
    C::LibXML.xmlAddChild(C::LibXML.xmlDocGetRootElement(doc), sign_node)

    ref_node = C::XMLSec.xmlSecTmplSignatureAddReference(sign_node, C::XMLSec.xmlSecOpenSSLTransformSha1GetKlass, nil, nil, nil)
    raise "failed to add a reference" if ref_node.null?

    envelope_result = C::XMLSec.xmlSecTmplReferenceAddTransform(ref_node, C::XMLSec.xmlSecTransformEnvelopedGetKlass)
    raise "failed to add envelope transform to reference" if envelope_result.null?

    key_info_node = C::XMLSec.xmlSecTmplSignatureEnsureKeyInfo(sign_node, nil)
    raise "failed to add key info" if key_info_node.null?

    digital_signature_context = C::XMLSec.xmlSecDSigCtxCreate(nil)
    raise "failed to create signature context" if digital_signature_context.null?

    digital_signature_context[:signKey] = C::XMLSec.xmlSecOpenSSLAppKeyLoad(private_key, :xmlSecKeyDataFormatPem, nil, nil, nil)
    raise "failed to load private pem ley from #{private_key}" if digital_signature_context[:signKey].null?

    if C::XMLSec.xmlSecKeySetName(digital_signature_context[:signKey], File.basename(private_key)) < 0
      raise "failed to set key name for key of #{private_key}"
    end

    if C::XMLSec.xmlSecTmplKeyInfoAddKeyName(key_info_node, nil).null?
      raise "failed to add key info"
    end

    if C::XMLSec.xmlSecDSigCtxSign(digital_signature_context, sign_node) < 0
      raise "signature failed!"
    end

    _dump_doc(doc)
  ensure
    C::LibXML.xmlFreeDoc(doc) if defined?(doc) && !doc.null?
    C::XMLSec.xmlSecDSigCtxDestroy(digital_signature_context) if defined?(digital_signature_context) && !digital_signature_context.null?
  end

  def self.verify_signature(signed_xml_document, options={})
    init
    if options.has_key? :cert_fingerprint
      return false unless _fingerprint_matches?(cert_fingerprint, cert)
    end

    doc = C::LibXML.xmlParseMemory(signed_xml_document, signed_xml_document.size)
    raise "could not parse XML document" if doc.null?

    doc_root = C::LibXML.xmlDocGetRootElement(doc)
    raise "could not get doc root" if doc_root.null?

    # add the ID attribute as an id. yeah, hacky
    idary = FFI::MemoryPointer.new(:pointer, 2)
    idary[0].put_pointer(0, FFI::MemoryPointer.from_string("ID"))
    idary[1].put_pointer(0, nil)
    C::XMLSec.xmlSecAddIDs(doc, doc_root, idary)

    keys_manager = _init_keys_manager

    digital_signature_context = C::XMLSec.xmlSecDSigCtxCreate(keys_manager)
    raise "failed to create signature context" if digital_signature_context.null?

    key_info_context = C::XMLSec.xmlSecKeyInfoCtxCreate(keys_manager)
    raise "could not create key info context" if key_info_context.null?

    signature_node = C::XMLSec.xmlSecFindNode(doc_root, C::XMLSec.xmlSecNodeSignature, C::XMLSec.xmlSecDSigNs)
    raise "signature node not found" if signature_node.null?

    certificate_node = C::XMLSec.xmlSecFindNode(signature_node, C::XMLSec.xmlSecNodeX509Certificate, C::XMLSec.xmlSecDSigNs)
    raise "certificate node not found" if certificate_node.null?

    key = C::XMLSec.xmlSecKeyCreate
    raise "error while allocating security key" if key.null?

    cert64ptr = C::LibXML.xmlNodeGetContent(certificate_node)
    raise "error while reading certificate node" if cert64ptr.null?
    cert64 = cert64ptr.read_string
    C::LibXML.xmlFree(cert64ptr)

    cert = Base64.decode64(cert64)

    if options.has_key? :as_of
      digital_signature_context[:keyInfoReadCtx][:certsVerificationTime] = Time.parse(options[:as_of]).to_i
    end

    key_add_result = C::XMLSec.xmlSecOpenSSLAppKeysMngrCertLoadMemory(keys_manager, cert, cert.size, :xmlSecKeyDataFormatCertDer, C::XMLSec.xmlSecKeyDataTypeTrusted)
    raise "failed to add key to keys manager" if key_add_result < 0

    if C::XMLSec.xmlSecDSigCtxVerify(digital_signature_context, signature_node) < 0
      raise "error during signature verification"
    end

    digital_signature_context[:status] == :xmlSecDSigStatusSucceeded
  ensure
    C::LibXML.xmlFreeDoc(doc) if defined?(doc) && doc && !doc.null?
    C::XMLSec.xmlSecDSigCtxDestroy(digital_signature_context) if defined?(digital_signature_context) && digital_signature_context && !digital_signature_context.null?
    C::XMLSec.xmlSecKeysMngrDestroy(keys_manager) if defined?(keys_manager) && keys_manager && !keys_manager.null?
    C::XMLSec.xmlSecKeyInfoCtxDestroy(key_info_context) if defined?(key_info_context) && key_info_context && !key_info_context.null?
    C::XMLSec.xmlSecKeyDestroy(key) if defined?(key) && key && !key.null?
  end

  def self.decrypt(encrypted_xml, private_key)
    init

    keys_manager = _init_keys_manager

    key = C::XMLSec.xmlSecOpenSSLAppKeyLoad(private_key, :xmlSecKeyDataFormatPem, nil, nil, nil)
    raise "failed to load private pem ley from #{private_key}" if key.null?

    key_add_result = C::XMLSec.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(keys_manager, key)
    raise "failed to add key to keys manager" if key_add_result < 0

    doc = C::LibXML.xmlParseMemory(encrypted_xml, encrypted_xml.size)
    raise "could not parse XML document" if doc.null?

    doc_root = C::LibXML.xmlDocGetRootElement(doc)
    raise "could not get root element" if doc_root.null?

    start_node = C::XMLSec.xmlSecFindNode(doc_root, C::XMLSec.xmlSecNodeEncryptedData, C::XMLSec.xmlSecEncNs)
    raise "start node not found" if start_node.null?

    encryption_context = C::XMLSec.xmlSecEncCtxCreate(keys_manager)
    raise "failed to create encryption context" if encryption_context.null?

    encryption_result = C::XMLSec.xmlSecEncCtxDecrypt(encryption_context, start_node)
    raise "decryption failed" if (encryption_result < 0)

    _dump_doc(doc)
  end

  def self.mute(&block)
    C::XMLSec.xmlSecErrorsDefaultCallbackEnableOutput(false)
    block.call
    C::XMLSec.xmlSecErrorsDefaultCallbackEnableOutput(true)
  end

  def self._init_keys_manager
    keys_manager = C::XMLSec.xmlSecKeysMngrCreate
    raise "failed to create keys manager" if keys_manager.null?

    if C::XMLSec.xmlSecOpenSSLAppDefaultKeysMngrInit(keys_manager) < 0
      raise "failed to init and load default openssl keys into keys manager"
    end

    keys_manager
  end

  def self._fingerprint_matches?(expected_fingerprint, cert)
    cert_fingerprint = Digest::SHA1.hexdigest(cert.to_der)
    expected_fingerprint = idp_cert_fingerprint.gsub(":", "").downcase
    return fingerprint == expected_fingerprint
  end

  def self._dump_doc(doc)
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
