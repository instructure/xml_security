module XMLSecurity
  class SignatureVerificationResult
    INVALID_REASONS = [
      C::XMLSec::XMLSEC_ERRORS_R_INVALID_DATA,
      C::XMLSec::XMLSEC_ERRORS_R_DATA_NOT_MATCH
    ]

    attr_reader :message

    def self.for_boolean(successful)
      if successful
        new(:success, "signature verification successful")
      else
        new(:invalid, "signature was invalid")
      end
    end

    def self.for_exception(exception)
      if INVALID_REASONS.include? exception.reason
        new(:invalid, exception.message)
      else
        new(:error, exception.message)
      end
    end

    def initialize(status, message)
      @status = status
      @message = message
    end

    def success?
      @status == :success
    end

    def error?
      @status == :error
    end

    def invalid?
      @status == :invalid
    end
  end
end
