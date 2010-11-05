# encoding: utf-8
require 'devise/strategies/base'


module Devise #:nodoc:
  module Oauth2Authenticatable #:nodoc:
    module Strategies #:nodoc:

      # Default strategy for signing in a user using Facebook Connect (a Facebook account).
      # Redirects to sign_in page if it's not authenticated
      #
      class Oauth2Authenticatable < ::Devise::Strategies::Base
        
        

        # Without a oauth session authentication cannot proceed.
        #
        def valid?
          
         (valid_params? || valid_cookie?) && mapping.to.respond_to?('authenticate_with_oauth2') 
          
        end

        def fb_cookie
          cookies["fbs_#{Devise.oauth2_client.id}"]
        end

        def fb_cookie_hash
          @fb_cookie_hash ||= begin
            hash = {}
            if fb_cookie.present?
              fb_cookie.split('&').each do |pair|
                key, value = pair.split('=')
                hash[key] = value
              end
            end
            hash
          end
          
        end
        # Authenticate user with OAuth2 
        #
        def authenticate!
          klass = mapping.to
          begin
            Rails.logger.info("in authenticate!")
            # Verify User Auth code and get access token from auth server: will error on failue
            #
            oauth2_user_attributes = {}
            token = nil
            id = nil

            if fb_cookie_hash.empty?
              access_token = Devise::oauth2_client.web_server.get_access_token(
                      params[:code], :redirect_uri => Devise::session_sign_in_url(request,mapping)
                    )

              # retrieve user attributes     

              # Get user details from OAuth2 Service    
              # NOTE: Facebook Graph Specific
              # TODO: break this out into separate model or class to handle 
              # different oauth2 providers
              oauth2_user_attributes = JSON.parse(access_token.get('/me')) 

              id = oauth2_user_attributes['id']
              token = access_token.token
            else
              id = fb_cookie_hash['uid']
              token = fb_cookie_hash['access_token']
            end
            user = klass.authenticate_with_oauth2(id, token)

            if user.present?
              user.on_after_oauth2_connect(oauth2_user_attributes)
              success!(user)
            else
              if klass.oauth2_auto_create_account?
                
                
                
                user = returning(klass.new) do |u|
                  u.store_oauth2_credentials!(
                      :token => token,
                      :uid => id
                    )
                  u.on_before_oauth2_auto_create(oauth2_user_attributes)
                end

                begin
                  
                  
                  user.save(true)
                  user.on_after_oauth2_connect(oauth2_user_attributes)
                  
                  
                  success!(user)
                rescue
                  fail!(:oauth2_invalid)
                end
              else
                fail!(:oauth2_invalid)
              end
            end
          
          rescue => e
            fail!(e.message)
          end
        end
        

        
        
        protected
          def valid_controller?
            # params[:controller] == 'sessions'
            mapping.controllers[:sessions] == params[:controller]
          end

          def valid_params?
            params[:code].present?
          end

          def valid_cookie?
            fb_cookie.present?
          end

      end
    end
  end
end

Warden::Strategies.add(:oauth2_authenticatable, Devise::Oauth2Authenticatable::Strategies::Oauth2Authenticatable)
