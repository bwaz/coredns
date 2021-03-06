# httpproxy

*httpproxy* proxies DNS request to a proxy using HTTPS (or HTTP/2 - not implemented). Usually this
 involves sending a JSON payload over this transport and translating the response back to DNS. The
 current supported backend is Google, using the URL: https://dns.google.com .

## Syntax

In its most basic form, a simple http proxy uses this syntax:

~~~
httpproxy FROM TO
~~~

* **FROM** is the base domain to match for the request to be proxied.
* **TO** is the destination endpoint to proxy to, accepted values here are `dns.google.com`.

For changing the defaults you can use the expanded syntax:

~~~
proxy FROM TO {
    upstream ADDRESS...
}
~~~

* `upstream` defines upstream resolvers to be used (re-)resolve `dns.google.com` (or other names in the
  future) every 30 seconds. When not specified the combo 8.8.8.8, 8.8.4.4 is used.

## Metrics

If monitoring is enabled (via the *prometheus* directive) then the following metric is exported:

* coredns_httpproxy_request_count_total{zone, proto, family}

## Examples

Proxy all requests within example.org to Google's dns.google.com.

~~~
proxy example.org dns.google.com
~~~

Proxy everything, and re-lookup `dns.google.com` every 30 seconds using the resolvers specified
in /etc/resolv.conf.

~~~
proxy . dns.google.com {
    upstream /etc/resolv.conf
}
~~~

## Debug queries

Debug queries are enabled by default and currently there is no way to turn them off. When CoreDNS
receives a debug queries (i.e. the name is prefixed with `o-o.debug.` a TXT record with Comment from
`dns.google.com` is added. Note this is not always set, but sometimes you'll see:

`dig @localhost -p 1053 mx o-o.debug.example.org`:

~~~ txt
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;o-o.debug.example.org.		IN	MX

;; AUTHORITY SECTION:
example.org.		1799	IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016110711 7200 3600 1209600 3600

;; ADDITIONAL SECTION:
.			0	CH	TXT	"Response from 199.43.133.53"
~~~
