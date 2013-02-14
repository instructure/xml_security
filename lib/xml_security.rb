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

require 'xml_security/common'
require 'xml_security/exceptions'
require 'xml_security/signature_verifier'
require 'xml_security/document_signer'
require 'xml_security/document_decrypter'
require 'xml_security/signature_verification_result'

require 'time'
require 'base64'
require 'digest/sha1'
require 'openssl'

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
    DocumentSigner.sign(xml_document, private_key)
  end

  def self.verify_signature(signed_xml_document, options={})
    init
    SignatureVerifier.verify_signature(signed_xml_document, options)
  end

  def self.decrypt(encrypted_xml, private_key)
    init
    DocumentDecrypter.decrypt(encrypted_xml, private_key)
  end

  def self.mute(&block)
    C::XMLSec.xmlSecErrorsDefaultCallbackEnableOutput(false)
    block.call
    C::XMLSec.xmlSecErrorsDefaultCallbackEnableOutput(true)
  end
end
