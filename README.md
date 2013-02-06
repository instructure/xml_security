# XML may not be fun, but at least we can make it secure!

[![Build Status](https://travis-ci.org/phinze/xml_security.png?branch=master)](https://travis-ci.org/phinze/xml_security)

```xml
<secrets keep-them="safe" with="xml!" />
```

You too can enjoy all the glory of `xmlsec` brought to your ruby runtime!

This library is being built with an eye towards building it in a proper SAML
integration on a Ruby-based platform.

## Working features 

* Basic XML Document Signing
* Basic XML Signature Verification
* Basic XML Document Decryption

## Lots left to do!

* XML Encryption
* Non-happy-path testing.
* Memory leak squashing.
* Testing with a SAML-layer library
* We'll need TONS of cleanup at the Ruby/C API layer. Goal is to connect the dots, then make the constellations beautiful.

## References

* Using FFI for ruby/c interop: https://github.com/ffi/ffi.git
* Wrapping XMLSec: http://www.aleksey.com/xmlsec/
* XMLSec also used libXML2: http://www.xmlsoft.org/

