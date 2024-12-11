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

  Dir.glob("../*.pem") do |file|
    next if file.include?("invalid")
    jwk_array << JSON.parse(%x{./pem_to_jwk #{file}})
  end

  jwk_array
end

kr = { "keys" => process_pem_files }

File.write("jwks-keyring.json", JSON.pretty_generate(kr))
