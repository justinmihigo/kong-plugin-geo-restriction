# Installation
http://luarocks.org/modules/newage/kong-plugin-geo-restriction

`luarocks install kong-plugin-geo-restriction`

```
custom_plugins = geo-restriction
```

`Reminder: don't forget to update the custom_plugins directive for each node in your Kong cluster.`

# API

POST :8001/plugins
```
{
	"name": "geo-restriction",
	"config.allow": ["UA", "UK"],
	"config.allow_ips": ["37.73.161.34"],
    "config.deny": ["FR"]
    "config.deny_ips":["145.13.78.5"]
}
```
# If using DBless Kong on a Kubernetes cluster as an Ingress or a Gateway controller

- you can  configure it by creating a KongPlugin and config will accept this values.
```
config:
  allow:
    # countries
    - "US"
  allow_ips:
    # other ips especially the ones that are in your kubernetes network
    - "10.0.0.0/24"
    - "102.39.112.2"
  deny:
    - "FR"
  deny_ips:
    - "139.18.12.34"
