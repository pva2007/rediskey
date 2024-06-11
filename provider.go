package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/go-redis/redis"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_ADDRESS", "localhost:6379"),
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_PASSWORD", ""),
			},
			"db": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("0", ""),
			},
			"tls_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_TLS_ENABLED", false),
			},
			"tls_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_TLS_CA_CERT", ""),
			},
			"tls_client_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_TLS_CLIENT_CERT", ""),
			},
			"tls_client_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_TLS_CLIENT_KEY", ""),
			},
			"tls_server_name": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("REDIS_TLS_SERVER_NAME", ""),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"redis_key": resourceRedisKey(),
		},
		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	address := d.Get("address").(string)
	password := d.Get("password").(string)
	db := d.Get("db").(int)
	tlsEnabled := d.Get("tls_enabled").(bool)
	tlsCACert := d.Get("tls_ca_cert").(string)
	tlsClientCert := d.Get("tls_client_cert").(string)
	tlsClientKey := d.Get("tls_client_key").(string)
	tlsServerName := d.Get("tls_server_name").(string)

	var tlsConfig *tls.Config
	if tlsEnabled {
		tlsConfig = &tls.Config{
			ServerName: tlsServerName,
		}

		if tlsCACert != "" {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM([]byte(tlsCACert))
			tlsConfig.RootCAs = caCertPool
		}

		if tlsClientCert != "" && tlsClientKey != "" {
			cert, err := tls.LoadX509KeyPair(tlsClientCert, tlsClientKey)
			if err != nil {
				return nil, fmt.Errorf("error loading TLS client certificate and key: %v", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:      address,
		Password:  password,
		DB:        db,
		TLSConfig: tlsConfig,
	})

	_, err := redisClient.Ping().Result()
	if err != nil {
		return nil, fmt.Errorf("error connecting to Redis: %v", err)
	}

	return redisClient, nil
}

func resourceRedisKey() *schema.Resource {
	return &schema.Resource{
		Create: resourceRedisKeyCreate,
		Read:   resourceRedisKeyRead,
		Update: resourceRedisKeyUpdate,
		Delete: resourceRedisKeyDelete,

		Schema: map[string]*schema.Schema{
			"key": {
				Type:     schema.TypeString,
				Required: true,
			},
			"value": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func resourceRedisKeyCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(*redis.Client)
	key := d.Get("key").(string)
	value := d.Get("value").(string)

	err := client.Set(key, value, 0).Err()
	if err != nil {
		return err
	}

	d.SetId(key)
	return nil
}

func resourceRedisKeyRead(d *schema.ResourceData, m interface{}) error {
	client := m.(*redis.Client)
	key := d.Id()

	// Check if the key exists
	exists, err := client.Exists(key).Result()
	if err != nil {
		return fmt.Errorf("error checking if key exists: %v", err)
	}
	if exists == 0 {
		// Key doesn't exist, so clear the value in state
		d.Set("value", "")
		return nil
	}

	// Key exists, get its value
	value, err := client.Get(key).Result()
	if err != nil {
		return fmt.Errorf("error getting value for key %s: %v", key, err)
	}

	// Update resource state with retrieved value
	d.Set("value", value)
	return nil
}

func resourceRedisKeyUpdate(d *schema.ResourceData, m interface{}) error {
	client := m.(*redis.Client)
	key := d.Id()
	newValue := d.Get("value").(string)

	// Check if the new value is different from the existing value
	if d.HasChange("value") {
		// If there's a change, update the value in Redis
		err := client.Set(key, newValue, 0).Err()
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceRedisKeyDelete(d *schema.ResourceData, m interface{}) error {
	client := m.(*redis.Client)
	key := d.Id()

	// Check if the key exists (optional)
	exists, err := client.Exists(key).Result()
	if err != nil {
		return fmt.Errorf("error checking if key exists: %v", err)
	}

	if exists == 1 {
		// If the key exists, delete it
		if err := client.Del(key).Err(); err != nil {
			return fmt.Errorf("error deleting key %s: %v", key, err)
		}
	}

	// Clear the resource ID from the state regardless of whether the key was deleted
	d.SetId("")

	return nil
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return Provider()
		},
	})
}
