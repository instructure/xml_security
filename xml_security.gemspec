require 'rake'

Gem::Specification.new do |s|
  s.name = 'xml_security'
  s.summary = 'Ruby bindings into the XMLSec library using ffi.'
  s.description = 'See http://github.com/phinze/xml_security'
  s.homepage = 'http://github.com/phinze/xml_security'
  s.authors = ['Paul Hinze']
  s.email = 'paul.t.hinze@gmail.com'

  s.version = '0.0.3'

  s.files = FileList["README.md", "lib/**/*.rb"]

  s.add_dependency('ffi')
end
