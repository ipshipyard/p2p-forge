package acme

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/aws/aws-sdk-go/aws/session"
	ddbv1 "github.com/aws/aws-sdk-go/service/dynamodb"

	"github.com/ipfs/go-datastore"
	badger4 "github.com/ipfs/go-ds-badger4"
	ddbds "github.com/ipfs/go-ds-dynamodb"
)

const pluginName = "acme"

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	reader, writer, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	c.OnStartup(writer.OnStartup)
	c.OnRestart(writer.OnReload)
	c.OnFinalShutdown(writer.OnFinalShutdown)
	c.OnRestartFailed(writer.OnStartup)

	// Add the read portion of the plugin to CoreDNS, so Servers can use it in their plugin chain.
	// The write portion is not *really* a plugin just a separate webserver running.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return reader
	})

	return nil
}

// parse Parses the configuration from the Corefile
func parse(c *caddy.Controller) (*acmeReader, *acmeWriter, error) {
	/*
			Syntax is:
			acme <domain-name> {
			    [registration-domain <domain> [listen-address=<address>] [external-tls=<bool>]
			    [database-type [...database-args]]
			}

			Databases:
		      - dynamo <table-name>
		      - badger <db-path>
	*/

	var forgeDomain string
	var forgeRegistrationDomain string
	var externalTLS bool
	var httpListenAddr string
	var ds datastore.TTLDatastore

	for c.Next() {
		args := c.RemainingArgs()

		switch len(args) {
		case 0:
			return nil, nil, c.ArgErr()
		case 1:
			forgeDomain = args[0]
		default:
			return nil, nil, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "registration-domain":
				args := c.RemainingArgs()
				if len(args) > 3 || len(args) == 0 {
					return nil, nil, c.ArgErr()
				}

				forgeRegistrationDomain = args[0]
				for i := 1; i < len(args); i++ {
					nextArg := args[i]
					argKV := strings.Split(nextArg, "=")
					if len(argKV) != 2 {
						return nil, nil, c.ArgErr()
					}
					k, v := argKV[0], argKV[1]
					switch k {
					case "listen-address":
						httpListenAddr = v
					case "external-tls":
						externalTLSString := v
						var err error
						externalTLS, err = strconv.ParseBool(externalTLSString)
						if err != nil {
							return nil, nil, c.ArgErr()
						}
					default:
						return nil, nil, c.ArgErr()
					}
				}
			case "database-type":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, nil, c.ArgErr()
				}
				databaseType := args[0]
				args = args[1:]

				switch databaseType {
				case "dynamo":
					if len(args) != 1 {
						return nil, nil, c.ArgErr()
					}

					ddbClient := ddbv1.New(session.Must(session.NewSession()))
					ds = ddbds.New(ddbClient, args[0])
				case "badger":
					if len(args) != 1 {
						return nil, nil, fmt.Errorf("need to pass a path for the Badger configuration")
					}
					dbPath := args[0]
					var err error
					ds, err = badger4.NewDatastore(dbPath, nil)
					if err != nil {
						return nil, nil, err
					}
				default:
					return nil, nil, fmt.Errorf("unknown database type: %s", databaseType)
				}
			default:
				return nil, nil, c.ArgErr()
			}
		}
	}

	writer := &acmeWriter{
		Addr:        httpListenAddr,
		Domain:      forgeRegistrationDomain,
		Datastore:   ds,
		ExternalTLS: externalTLS,
	}
	reader := &acmeReader{
		ForgeDomain: forgeDomain,
		Datastore:   ds,
	}

	return reader, writer, nil
}
