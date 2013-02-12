module XMLSecurity
  class Exception < ::RuntimeError
    attr_accessor :file, :line, :func, :errorObject, :errorSubject, :reason, :msg

    def self.handle_xmlsec_error_callback(file, line, func, errorObject, errorSubject, reason, msg)
      exception = _exception_class_for_msg(msg).new(msg)
      exception.file = file
      exception.line = line
      exception.func = func
      exception.errorObject = errorObject
      exception.errorSubject = errorSubject
      exception.reason = reason
      exception.msg = msg
      raise exception
    end

    def self._exception_class_for_msg(msg)
      case msg
      when 'data and digest do not match' then DigestMismatchError
      when 'signature do not match' then SignatureMismatchError
      else Exception
      end
    end
  end

  class SignatureVerificationException < Exception; end
  class SignatureMismatchError < SignatureVerificationException; end
  class DigestMismatchError < SignatureVerificationException; end
end
