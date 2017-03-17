module Restforce
  # Authentication middleware used if jwt_token are set
  class Middleware::Authentication::Bearer < Restforce::Middleware::Authentication
    def params
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        client_id: @options[:client_id],
        assertion: jwt_payload
      }
    end

    def jwt_payload
      "#{header}.#{claim_set}"
    end

    def header
      Base64.encode64('{"alg":"RS256"}').chomp
    end

    def claim_set
      Base64.encode64 ({
        "iss" => @options[:client_id],
        "sub" => @options[:email],
        "aud" => "https://#{@options[:host]}",
        "exp" => Time.now.to_i
      }.to_s).chomp
    end

  end
end
