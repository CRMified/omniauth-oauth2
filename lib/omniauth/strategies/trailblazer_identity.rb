require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class TrailblazerIdentity < OmniAuth::Strategies::OAuth2
      option :name, :trailblazer_identity

      # Default client options - will be overridden in setup_phase if dynamic config exists
      option :client_options, {
        site: ENV["OAUTH_TBID_BASE_URL"],
        authorize_url: "/services/oauth2/authorize",
        token_url: "/services/oauth2/token"
      }

      option :authorize_params, {
        response_type: "code"
      }

      option :access_token_options, {
        mode: :query,
        param_name: "access_token"
      }

      # Define the scopes we want to request
      option :scope, "openid email profile"

      uid { raw_info["user_id"] || raw_info["sub"] }

      info do
        {
          "email" => raw_info["email"],
          "first_name" => raw_info["given_name"],
          "last_name" => raw_info["family_name"],
          "name" => raw_info["name"],
          "nickname" => raw_info["nickname"],
          "urls" => {"profile" => raw_info["profile"]}
        }
      end

      extra do
        {
          "raw_info" => raw_info,
          "instance_url" => access_token.params["instance_url"],
          "issued_at" => access_token.params["issued_at"],
          "signature" => access_token.params["signature"]
        }
      end

      def raw_info
        @raw_info ||= access_token.get("#{site_url}/services/oauth2/userinfo").parsed
      end

      def callback_url
        full_host + script_name + callback_path
      end

      # Override setup_phase to load dynamic configuration from IdentityProvidersApp
      def setup_phase
        if provider_config
          # Override client options with database configuration
          options.client_id = provider_config.client_id
          options.client_secret = provider_config.client_secret
          options.client_options[:site] = provider_config.base_url
          options.client_options[:authorize_url] = "#{provider_config.base_url}/services/oauth2/authorize"
          options.client_options[:token_url] = "#{provider_config.base_url}/services/oauth2/token"

          # Store provider config for later use
          @provider_config = provider_config
        end
        super
      end

      private

      def site_url
        @provider_config&.base_url || ENV["OAUTH_TBID_BASE_URL"]
      end

      def provider_config
        return @provider_config if defined?(@provider_config)

        # Try to find provider config from database if Team model exists
        if defined?(Team) && Team.respond_to?(:default_team)
          @provider_config = Team.default_team&.identity_providers_apps&.active&.find_by(name: "trailblazer_identity")
        else
          @provider_config = nil
        end
      end
    end
  end
end