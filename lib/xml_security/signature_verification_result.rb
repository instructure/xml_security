module XMLSecurity
  class SignatureVerificationResult
    INVALID_REASONS = [
      C::XMLSec::XMLSEC_ERRORS_R_INVALID_DATA,
      C::XMLSec::XMLSEC_ERRORS_R_DATA_NOT_MATCH
    ]

    INVALID_STATUSES = [
      :invalid,
      :fingerprint_mismatch
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
      if exception.is_a? FingerprintMismatchError
        new(:fingerprint_mismatch, exception.message)
      else
        if INVALID_REASONS.include? exception.reason
          new(:invalid, exception.msg)
        else
          new(:error, exception.message)
        end
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
      INVALID_STATUSES.include? @status
    end

    def fingerprint_mismatch?
      @status == :fingerprint_mismatch
    end

    def digest_mismatch?
      @message == 'data and digest do not match'
    end

    def signature_mismatch?
      @message == 'signature do not match'
    end
  end
end
