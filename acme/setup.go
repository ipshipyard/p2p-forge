package acme

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/ipfs/go-datastore"

	badger4 "github.com/ipfs/go-ds-badger4"

	"github.com/aws/aws-sdk-go/aws/session"
	ddbv1 "github.com/aws/aws-sdk-go/service/dynamodb"
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

func parse(c *caddy.Controller) (*acmeReader, *acmeWriter, error) {
	var forgeDomain string
	var httpListenAddr string
	var databaseType string

	// Parse the configuration from the Corefile
	c.Next()
	args := c.RemainingArgs()
	if len(args) < 3 {
		return nil, nil, fmt.Errorf("invalid arguments")
	}

	forgeDomain = args[0]
	httpListenAddr = args[1]
	databaseType = args[2]

	var ds datastore.TTLDatastore

	switch databaseType {
	case "dynamo":
		ddbClient := ddbv1.New(session.Must(session.NewSession()))
		ds = ddbds.New(ddbClient, "foo")
	case "badger":
		if len(args) != 4 {
			return nil, nil, fmt.Errorf("need to pass a path for the Badger configuration")
		}
		dbPath := args[3]
		var err error
		ds, err = badger4.NewDatastore(dbPath, nil)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unknown database type: %s", databaseType)
	}

	writer := &acmeWriter{
		Addr:      httpListenAddr,
		Datastore: ds,
	}
	reader := &acmeReader{
		ForgeDomain: forgeDomain,
		Datastore:   ds,
	}

	return reader, writer, nil
}
