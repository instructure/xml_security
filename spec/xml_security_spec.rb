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
      input_xml = fixture_path("helloworld.xml")
      expected_output_xml = File.read(fixture_path("helloworld_signed.xml"))

      memory_usage_before = `ps -o rss= -p #{Process.pid}`.to_i

      1000.times do
        XMLSecurity.sign(File.read(input_xml), TEST_KEY_PATH)
      end

      GC.start

      memory_usage_after = `ps -o rss= -p #{Process.pid}`.to_i

      kilobytes_used = memory_usage_after - memory_usage_before
      puts kilobytes_used
      kilobytes_used.should be < 1024
    end
  end

  describe '.verify_signature' do
    it 'passes when the signature checks out with the included cert file' do
      signed_xml = File.read(fixture_path("helloworld_signedwithcert.xml"))

      XMLSecurity.verify_signature(signed_xml).should be_true
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
