local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "geo-restriction"

return {
  name = PLUGIN_NAME,
  fields = {
    {
      protocols = typedefs.protocols {
        default = {"http", "https", "tcp", "tls", "grpc", "grpcs"}
      }
    },
    {
      config = {
        type = "record",
        fields = {
          {
            allow = {
              type = "set",
              elements = { type = "string" }, -- ISO country codes
              required = false
            }
          },
          {
            deny = {
              type = "set",
              elements = { type = "string" },
              required = false
            }
          },
          {
            allow_ips = {
              type = "set",
              elements = { type = "string" }, -- e.g., "192.168.0.1" or "10.0.0.0/24"
              required = false
            }
          },
          {
            deny_ips = {
              type = "set",
              elements = { type = "string" },
              required = false
            }
          },
          {
            status = {
              type = "number",
              default = 403
            }
          },
          {
            message = {
              type = "string",
              default = "Access restricted by Geo-IP policy"
            }
          }
        }
      }
    }
  },
  entity_checks = {
    { at_least_one_of = {
        "config.allow", "config.deny", "config.allow_ips", "config.deny_ips"
    }}
  }
}

