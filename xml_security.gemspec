Gem::Specification.new do |s|
  s.name = 'xml_security'
  s.summary = 'Ruby bindings into the XMLSec library using ffi.'
  s.desscription = 'See http://github.com/phinze/xml_security'
  s.homepage = 'http://github.com/phinze/xml_security'
  s.authors = ['Paul Hinze']

  s.version = '0.0.1'

  s.files = FileList["README.md", "lib/**/*.rb"]

  s.add_dependency('ffi')
  s.add_development_dependency 'ruby-debug'
  s.add_development_dependency 'rspec', '1.3.2'
end
