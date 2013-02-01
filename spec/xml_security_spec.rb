require 'spec_helper'

describe XMLSecurity do
  describe '.init' do
    it 'does not blow up' do
      XMLSecurity.init
    end
  end

  describe '.sign' do
    it 'properly signs the provided xml document with the referenced key' do
      input_xml = File.read(fixture_path("helloworld.xml"))
      expected_output_xml = File.read(fixture_path("helloworld_signed.xml"))
      key = TEST_KEY

      XMLSecurity.sign(input_xml, key).should == expected_output_xml
    end
  end
end
