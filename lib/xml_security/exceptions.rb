module XMLSecurity
  class Exception < ::RuntimeError
    attr_accessor :file, :line, :func, :errorObject, :errorSubject, :reason, :msg

    def self.handle_xmlsec_error_callback(file, line, func, errorObject, errorSubject, reason, msg)
      exception = _exception_class_for_msg(msg).new("#{file}:#{line} (#{func}) - #{errorObject} #{errorSubject} #{reason} #{msg}")
      exception.file = file
      exception.line = line
      exception.func = func
      exception.errorObject = errorObject
      exception.errorSubject = errorSubject
      exception.reason = reason
      exception.msg = msg
      if _should_raise?(exception)
        raise exception
      else
        puts exception.xmlsec_inspect
      end
    end

    def self._should_raise?(exception)
      true # for now
    end

    def self._exception_class_for_msg(msg)
      case msg
      when 'data and digest do not match' then DigestMismatchError
      when 'signature do not match' then SignatureMismatchError
      else Exception
      end
    end

    def xmlsec_inspect
      [
        "file = #{file}",
        "line = #{line}",
        "func = #{func}",
        "errorObject = #{errorObject}",
        "errorSubject = #{errorSubject}",
        "reason = #{reason}",
        "msg = #{msg}"
      ].join("\n")
    end
  end

  class SignatureVerificationException < Exception; end
  class SignatureMismatchError < SignatureVerificationException; end
  class DigestMismatchError < SignatureVerificationException; end

  class FingerprintMismatchError < SignatureVerificationException
    def initialize(expected, actual)
      super("fingerprint mismatch; expected: '#{expected}', got: '#{actual}'")
    end
  end
end
