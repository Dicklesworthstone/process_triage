#!/usr/bin/env ruby
# frozen_string_literal: true

# Test script for validating Homebrew formula
# Usage: ruby test_formula.rb <formula_path>

require 'net/http'
require 'uri'

FORMULA_PATH = ARGV[0] || 'dist/packages/pt.rb'

def log(level, msg)
  puts "[#{level}] #{msg}"
end

def test_syntax(path)
  log('TEST', 'Checking Ruby syntax...')

  result = system("ruby -c #{path} 2>&1")
  unless result
    log('FAIL', 'Ruby syntax check failed')
    return false
  end

  log('PASS', 'Ruby syntax OK')
  true
end

def test_required_fields(path)
  log('TEST', 'Checking required fields...')

  content = File.read(path)

  required = %w[desc homepage version license]
  missing = required.reject { |field| content.include?(field) }

  if missing.any?
    log('FAIL', "Missing required fields: #{missing.join(', ')}")
    return false
  end

  log('PASS', 'All required fields present')
  true
end

def test_urls_format(path)
  log('TEST', 'Checking URL format...')

  content = File.read(path)

  # Extract URLs from formula
  urls = content.scan(/url "([^"]+)"/).flatten

  if urls.empty?
    log('FAIL', 'No URLs found in formula')
    return false
  end

  urls.each do |url|
    unless url.start_with?('https://github.com/')
      log('WARN', "URL not from GitHub: #{url}")
    end

    unless url.include?('/releases/download/')
      log('WARN', "URL not a release download: #{url}")
    end
  end

  log('PASS', "Found #{urls.length} URLs")
  true
end

def test_sha256_format(path)
  log('TEST', 'Checking SHA256 format...')

  content = File.read(path)

  # Extract SHA256 hashes
  hashes = content.scan(/sha256 "([^"]+)"/).flatten

  if hashes.empty?
    log('FAIL', 'No SHA256 hashes found')
    return false
  end

  invalid = hashes.reject { |h| h.match?(/^[a-f0-9]{64}$/) }
  if invalid.any?
    log('FAIL', "Invalid SHA256 format: #{invalid.join(', ')}")
    return false
  end

  log('PASS', "Found #{hashes.length} valid SHA256 hashes")
  true
end

def test_url_reachable(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 5

  request = Net::HTTP::Head.new(uri.request_uri)
  response = http.request(request)

  %w[200 302 301].include?(response.code)
rescue StandardError => e
  log('WARN', "Could not reach URL: #{e.message}")
  false
end

def test_urls_reachable(path)
  log('TEST', 'Checking URL reachability (optional)...')

  content = File.read(path)
  urls = content.scan(/url "([^"]+)"/).flatten

  reachable = 0
  urls.each do |url|
    if test_url_reachable(url)
      reachable += 1
    else
      log('WARN', "URL not reachable: #{url[0..60]}...")
    end
  end

  if reachable.zero?
    log('WARN', 'No URLs reachable (release may not exist yet)')
  else
    log('PASS', "#{reachable}/#{urls.length} URLs reachable")
  end

  true  # Don't fail on unreachable URLs (may be pre-release validation)
end

def run_tests
  unless File.exist?(FORMULA_PATH)
    log('ERROR', "Formula not found: #{FORMULA_PATH}")
    exit 1
  end

  log('INFO', "Testing formula: #{FORMULA_PATH}")
  puts

  results = []
  results << test_syntax(FORMULA_PATH)
  results << test_required_fields(FORMULA_PATH)
  results << test_urls_format(FORMULA_PATH)
  results << test_sha256_format(FORMULA_PATH)
  results << test_urls_reachable(FORMULA_PATH)

  puts
  if results.all?
    log('SUCCESS', 'All tests passed')
    exit 0
  else
    log('FAILURE', 'Some tests failed')
    exit 1
  end
end

run_tests
