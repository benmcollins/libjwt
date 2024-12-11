#!/usr/bin/env ruby

# Copyright (C) 2024 Ben Collins <bcollins@maclara-llc.com>
# This file is part of the JWT C Library
#
# SPDX-License-Identifier:  MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Usage: reads all PEM files from parent directory and calls pem_to_jwk
# to generate a JWK for each, then combines them into a JWKS file.

require 'json'

def process_pem_files
  jwk_array = []
  count = 0
  puts "Processing PEM files..."

  Dir.glob("../*.pem") do |file|
    next if file.include?("invalid")
    jwk_array << JSON.parse(%x{./pem_to_jwk #{file}})
    count += 1
  end

  puts "Converted #{count} PEM files into JWK format"

  jwk_array
end

jwk_list = process_pem_files
ec_count = 0
rsa_count = 0
eddsa_count = 0

jwk_list.each do |jwk|
  case jwk['kty']
  when "EC"
    ec_count += 1
  when "RSA"
    rsa_count += 1
  when "OKP"
    eddsa_count += 1
  end
end

puts "EC:  #{ec_count}"
puts "RSA: #{rsa_count}"
puts "OKP: #{eddsa_count}"

kr = { "keys" => jwk_list }

out = "jwks-keyring.json"
puts "Writing JWKS of all JWK keys to #{out}"
File.write(out, JSON.pretty_generate(kr))
