local lrucache = require "resty.lrucache"
local kong_meta = require "kong.meta"

local geoip_module = require 'geoip'
local geoip_country = require 'geoip.country'
local geoip_country_filename = '/usr/share/GeoIP/GeoIP.dat'

local ipmatcher = require "resty.ipmatcher"

local kong = kong
local log = kong.log
local ngx_var = ngx.var

local IPMATCHER_COUNT = 512
local IPMATCHER_TTL = 3600
local cache = lrucache.new(IPMATCHER_COUNT)

local GeoRestrictionHandler = {PRIORITY = 991, VERSION = "1.0.0"}

local isempty
do
  local tb_isempty = require "table.isempty"
  isempty = function(t) return t == nil or tb_isempty(t) end
end

local function do_exit(status, message)
  status = status or 403
  message = message or string.format("Country is not allowed, IP: %s", ngx_var.remote_addr)

  log.warn(message)
  return kong.response.error(status, message)
end

local function match_geo(countries, current_country)
  for i, v in ipairs(countries) do
    if v == current_country then return true end
  end
  return false
end

local function get_client_ip()
  local forwarded_for = ngx.req.get_headers()['X-Forwarded-For']
  if forwarded_for then
    local first_ip = forwarded_for:match("([^,]+)")
    if first_ip then
      return first_ip:match("^%s*(.-)%s*$")
    end
  end

  local real_ip = ngx.req.get_headers()['X-Real-IP']
  if real_ip then
    return real_ip
  end

  return ngx_var.remote_addr
end

local function do_restrict(conf)
  local current_ip = get_client_ip()
  if not current_ip then
    log.err("Unable to determine client IP address")
    return do_exit(403, "Unable to determine client IP address")
  end

  log.debug("Client IP: ", current_ip)

  if not isempty(conf.deny_ips) then
    local deny_matcher = cache:get("deny_matcher")
    if not deny_matcher then
      local ok, matcher_or_err = pcall(ipmatcher.new, conf.deny_ips)
      if ok then
        deny_matcher = matcher_or_err
        cache:set("deny_matcher", deny_matcher, IPMATCHER_TTL)
      else
        log.err("Failed to build deny matcher: ", matcher_or_err)
      end
    end

    if deny_matcher and deny_matcher:match(current_ip) then
      return do_exit(conf.status, conf.message or "IP blocked by rule")
    end
  end

  if not isempty(conf.allow_ips) then
    local allow_matcher = cache:get("allow_matcher")
    if not allow_matcher then
      local ok, matcher_or_err = pcall(ipmatcher.new, conf.allow_ips)
      if ok then
        allow_matcher = matcher_or_err
        cache:set("allow_matcher", allow_matcher, IPMATCHER_TTL)
      else
        log.err("Failed to build allow matcher: ", matcher_or_err)
      end
    end

    if allow_matcher and allow_matcher:match(current_ip) then
      log.debug("IP allowed by rule")
      return -- explicitly allowed, skip further checks
    end
  end

  local geoip_db, err = geoip_country.open(geoip_country_filename)
  if not geoip_db then
    log.err("Failed to open GeoIP database: ", err)
    return do_exit(403, "GeoIP database not available")
  end

  local geo_result, err = geoip_db:query_by_addr(current_ip)
  if not geo_result then
    log.warn("GeoIP lookup failed for IP: ", current_ip, " error: ", err)
    return do_exit(403, "Cannot identify the client country")
  end

  local current_country = geo_result.code
  if not current_country then
    log.warn("Country code not found for IP: ", current_ip)
    return do_exit(403, "Cannot identify the client country")
  end

  log.debug("Country: ", current_country)

  local deny_countries = conf.deny
  if not isempty(deny_countries) then
    if match_geo(deny_countries, current_country) then
      return do_exit(conf.status, conf.message or "Country blocked by rule")
    end
  end

  local allow_countries = conf.allow
  if not isempty(allow_countries) then
    local allowed = match_geo(allow_countries, current_country)
    if not allowed then
      return do_exit(conf.status, conf.message or "Country not allowed")
    end
  end
end

function GeoRestrictionHandler:access(conf)
  return do_restrict(conf)
end

function GeoRestrictionHandler:preread(conf)
  return do_restrict(conf)
end

return GeoRestrictionHandler

