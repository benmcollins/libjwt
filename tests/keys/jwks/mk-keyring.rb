#!/usr/bin/env ruby

require 'json'

def process_pem_files
  jwk_array = []

  Dir.glob("../*.pem") do |file|
    next if file.include?("invalid")
    jwk_array << JSON.parse(%x{./pem_to_jwk #{file}})
  end

  jwk_array
end

def load_jwk_files
  jwk_array = []

  Dir.glob("*.jwk") do |file|
    begin
      jwk_data = JSON.parse(File.read(file))
      jwk_array << jwk_data
    rescue JSON::ParserError => e
      puts "Error parsing JSON in file #{file}: #{e.message}"
    end
  end

  jwk_array
end

kr = { "keys" => process_pem_files }

File.write("jwk-keyring.json", JSON.pretty_generate(kr))
