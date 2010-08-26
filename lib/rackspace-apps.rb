#! /usr/bin/env ruby

require 'net/http'
require 'date'
require 'date/format'
require 'digest/sha1'
require 'base64'
require 'time'
require 'rubygems'
require 'json'

module Rackspace

class Client
  
  attr :connection, true
  
  def initialize(user_key, secret_hash, opts={})
    options = {
      :server => 'api.emailsrvr.com',
      :version_prefix => '/v0'
    }.merge! opts
    @server = options[:server]
    @version_prefix = options[:version_prefix]
    @user_key = user_key
    @secret_hash = secret_hash
    @connection = false
  end
  
# Response Type Enums

  def xml_format
    'text/xml'
  end
  
  def json_format
    'application/json'
  end

#
# HTTP Request Verbs
#  
  def get(url_string, format)
    uri = full_uri(url_string)
    headers = prepared_headers
    headers['Accept'] = format
    request = Net::HTTP::Get.new(request_uri(uri), headers)
    http_response = make_request request, uri
  end
  
  def delete(url_string)
    uri = full_uri(url_string)
    request = Net::HTTP::Delete.new(request_uri(uri), prepared_headers)
    http_response = make_request request, uri
  end
  
  def put(url_string, fields_hash)
    uri = full_uri(url_string)
    request = Net::HTTP::Put.new(request_uri(uri), prepared_headers)
    request.set_form_data(fields_hash)
    http_response = make_request request, uri
  end
  
  def post(url_string, fields_hash)
    uri = full_uri(url_string)
    request = Net::HTTP::Post.new(request_uri(uri), prepared_headers)
    request.set_form_data(fields_hash)
    http_response = make_request request, uri
  end
  
#
# HTTP Request Helpers
# 
  def make_request request, uri
    connect! unless connected?
    response = @connection.request(request)
  
    case response
     when Net::HTTPOK
       if response.body.length > 0
         return JSON.parse(response.body) 
       else
         return true
       end
     when Net::HTTPForbidden
       if response['x-error-message'] =~ /Exceeded request limits/
         sleep 5
         make_request request, uri 
       else
         raise RuntimeError, "HTTP Forbidden - Are you logged in?"
       end
     else 
       raise RuntimeError, "Can't handle response #{response['x-error-message']}" 
     end
  end
  
  def full_uri(url_string)
    URI.parse('http://' + @server + @version_prefix + url_string)
  end
  
  def request_uri(uri)
    request = uri.path
    if ! uri.query.nil?
      request = request + '?' + uri.query
    end
    request
  end
  
  def prepared_headers
    headers = Hash.new
    headers.merge! headers_auth_creds(@user_key, @secret_hash)
    headers['Accept'] = xml_format
    headers
  end
  
  def headers_auth_creds(apiKey, secretKey)
    userAgent = 'Ruby Test Client'
    timestamp = DateTime.now.strftime('%Y%m%d%H%M%S')
    
    data_to_sign = apiKey + userAgent + timestamp + secretKey
    
    hash = Base64.encode64(Digest::SHA1.digest(data_to_sign))
    signature = apiKey + ":" + timestamp + ":" + hash
    
    headers = Hash['User-Agent' => userAgent, 'X-Api-Signature' => signature]
  end
  
   # Check to see if we have an HTTP/S Connection
  def connected?
    return false unless @connection
    return false unless @connection.started?
    true
  end

  # Connect to the remote system.
  def connect!
    @connection = Net::HTTP.new(@server, 80)
    if @ssl
      @connection.use_ssl = true
      @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    @connection.start
  end
  
end
end
