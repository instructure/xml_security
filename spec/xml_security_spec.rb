require 'spec_helper'

describe XMLSecurity do
  describe '.init' do
    it 'does not blow up' do
      XMLSecurity.init
    end
  end

  describe '.sign' do
    it 'properly signs the provided xml document with the referenced key' do
      input_xml = fixture_path("helloworld.xml")
      expected_output_xml = File.read(fixture_path("helloworld_signed.xml"))

      output_xml = XMLSecurity.sign(File.read(input_xml), TEST_KEY_PATH)

      output_xml.should == expected_output_xml
    end

    it 'does not leak memory' do
      input_xml = File.read(fixture_path("helloworld.xml"))
      expected_output_xml = File.read(fixture_path("helloworld_signed.xml"))

      should_not_leak_more_than(4*1024) do
        1000.times do
          XMLSecurity.sign(input_xml, TEST_KEY_PATH)
        end
      end
    end
  end

  describe '.verify_signature' do
    it 'passes when the signature checks out with the included cert file' do
      signed_xml = File.read(fixture_path("helloworld_signedwithcert.xml"))

      XMLSecurity.verify_signature(signed_xml).should be_success
    end

    it 'works with a properly signed SAML assertion' do
      signed_xml = File.read(fixture_path("signed_assertion.xml"))

      XMLSecurity.verify_signature(signed_xml, :as_of => '2007-08-14 12:01:34 UTC').should be_true
    end

    it 'fails when a tampered message contains a bad digest' do
      signed_xml = File.read(fixture_path("helloworld_baddigest.xml"))
      verification_result = XMLSecurity.verify_signature(signed_xml)
      verification_result.should be_invalid
      verification_result.message.should == 'data and digest do not match'
    end

    it 'fails when a tampered message contains a good digest but a bad signature' do
      signed_xml = File.read(fixture_path("helloworld_badsig.xml"))
      verification_result = XMLSecurity.verify_signature(signed_xml)
      verification_result.should be_invalid
      verification_result.message.should == 'signature do not match'
    end

    it 'does not leak memory' do
      signed_xml = File.read(fixture_path("helloworld_signedwithcert.xml"))

      should_not_leak_more_than(6*1024) do
        1000.times do
          XMLSecurity.verify_signature(signed_xml)
        end
      end
    end

    context 'with a cert_fingerprint provided' do
      it 'passes when the fingerprint matches' do
        signed_xml = File.read(fixture_path("helloworld_signedwithcert.xml"))

        XMLSecurity.verify_signature(signed_xml, :cert_fingerprint => 'F3:01:B1:D2:3A:42:7F:72:50:4A:4F:59:8B:D0:06:C2:94:68:E8:7E').should be_true
      end

      it 'fails when the fingerprint does not match' do
        signed_xml = File.read(fixture_path("helloworld_signedwithcert.xml"))

        XMLSecurity.verify_signature(signed_xml, :cert_fingerprint => 'F3:01:B1:D2:3A:42:7F:72:50:4A:4F:59:8B:D0:06:C2:94:00:01:02').should be_false
      end
    end
  end

  describe '.decrypt' do
    it 'decrypts encrypted elements using the specified key' do
      encrypted_xml = File.read(fixture_path("encrypted_assertion.xml"))

      decrypted_xml = XMLSecurity.decrypt(encrypted_xml, ENCRYPTION_TEST_KEY_PATH)

      decrypted_xml.should include('InResponseTo="e034c5ecd6336dd02d1bf61214e6c76feb84ebe785"')
    end
  end
end
