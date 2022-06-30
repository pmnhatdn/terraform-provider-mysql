package mysql

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/hashicorp/go-version"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"
	"golang.org/x/net/proxy"
)

const (
	cleartextPasswords = "cleartext"
	nativePasswords    = "native"
	awsIAMAuth         = "aws_auth"
)

type MySQLConfiguration struct {
	Config          *mysql.Config
	MaxConnLifetime time.Duration
	MaxOpenConns    int
}

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_ENDPOINT", nil),
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if value == "" {
						errors = append(errors, fmt.Errorf("Endpoint must not be an empty string"))
					}

					return
				},
			},

			"username": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_USERNAME", nil),
			},

			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_PASSWORD", nil),
			},

			"proxy": {
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{
					"ALL_PROXY",
					"all_proxy",
				}, nil),
				ValidateFunc: validation.StringMatch(regexp.MustCompile("^socks5h?://.*:\\d+$"), "The proxy URL is not a valid socks url."),
			},

			"tls": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_TLS_CONFIG", "false"),
				ValidateFunc: validation.StringInSlice([]string{
					"true",
					"false",
					"skip-verify",
				}, false),
			},

			"max_conn_lifetime_sec": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			"max_open_conns": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			"authentication_plugin": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      nativePasswords,
				ValidateFunc: validation.StringInSlice([]string{cleartextPasswords, nativePasswords, awsIAMAuth}, true),
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"mysql_database":      resourceDatabase(),
			"mysql_grant":         resourceGrant(),
			"mysql_role":          resourceRole(),
			"mysql_user":          resourceUser(),
			"mysql_user_password": resourceUserPassword(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func registerRDSMysqlCert(c *http.Client, tlsName string) (interface{}, error) {
	resp, err := c.Get("https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem")
	if err != nil {
		return nil, err
	}

	// defer fileutil.CloseLoggingAnyError(resp.Body)
	pem, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("couldn't append certs from pem")
	}

	err = mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: rootCertPool, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func generateRDSAuthToken(host string, username string) (string, error) {
	creds := credentials.NewSharedCredentials("", "default")
	region := "ap-northeast-1"

	token, err := rdsutils.BuildAuthToken(host, region, username, creds)

	if err != nil {
		return "", err
	}

	return token, nil
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	endpoint := d.Get("endpoint").(string)

	proto := "tcp"
	if len(endpoint) > 0 && endpoint[0] == '/' {
		proto = "unix"
	}

	var err error
	username := d.Get("username").(string)
	conf := mysql.Config{
		User: username,
		Net:  proto,
		Addr: endpoint,
	}

	authenticationPlugin := d.Get("authentication_plugin").(string)
	if authenticationPlugin == awsIAMAuth {
		tlsName := "aws_rds"
		_, err = registerRDSMysqlCert(http.DefaultClient, tlsName)
		if err != nil {
			return nil, err
		}
		conf.TLSConfig = tlsName

		conf.Passwd, err = generateRDSAuthToken(endpoint, username)
		if err != nil {
			return nil, err
		}

		conf.AllowNativePasswords = true
		conf.AllowCleartextPasswords = true
	} else {
		conf.TLSConfig = d.Get("tls").(string)
		conf.Passwd = d.Get("password").(string)
		conf.AllowNativePasswords = (authenticationPlugin == nativePasswords)
		conf.AllowCleartextPasswords = (authenticationPlugin == cleartextPasswords)
	}

	var dialer proxy.Dialer
	dialer, err = makeDialer(d)
	if err != nil {
		return nil, err
	}

	mysql.RegisterDial("tcp", func(network string) (net.Conn, error) {
		return dialer.Dial("tcp", network)
	})

	return &MySQLConfiguration{
		Config:          &conf,
		MaxConnLifetime: time.Duration(d.Get("max_conn_lifetime_sec").(int)) * time.Second,
		MaxOpenConns:    d.Get("max_open_conns").(int),
	}, nil
}

var identQuoteReplacer = strings.NewReplacer("`", "``")

func makeDialer(d *schema.ResourceData) (proxy.Dialer, error) {
	proxyFromEnv := proxy.FromEnvironment()
	proxyArg := d.Get("proxy").(string)

	if len(proxyArg) > 0 {
		proxyURL, err := url.Parse(proxyArg)
		if err != nil {
			return nil, err
		}
		proxy, err := proxy.FromURL(proxyURL, proxyFromEnv)
		if err != nil {
			return nil, err
		}

		return proxy, nil
	}

	return proxyFromEnv, nil
}

func quoteIdentifier(in string) string {
	return fmt.Sprintf("`%s`", identQuoteReplacer.Replace(in))
}

func serverVersion(db *sql.DB) (*version.Version, error) {
	var versionString string
	err := db.QueryRow("SELECT @@GLOBAL.innodb_version").Scan(&versionString)
	if err != nil {
		return nil, err
	}

	return version.NewVersion(versionString)
}

func serverVersionString(db *sql.DB) (string, error) {
	var versionString string
	err := db.QueryRow("SELECT @@GLOBAL.version").Scan(&versionString)
	if err != nil {
		return "", err
	}

	return versionString, nil
}

func connectToMySQL(conf *MySQLConfiguration) (*sql.DB, error) {

	dsn := conf.Config.FormatDSN()
	var db *sql.DB
	var err error

	// When provisioning a database server there can often be a lag between
	// when Terraform thinks it's available and when it is actually available.
	// This is particularly acute when provisioning a server and then immediately
	// trying to provision a database on it.
	retryError := resource.Retry(5*time.Minute, func() *resource.RetryError {
		db, err = sql.Open("mysql", dsn)
		if err != nil {
			return resource.RetryableError(err)
		}

		err = db.Ping()
		if err != nil {
			return resource.RetryableError(err)
		}

		return nil
	})

	if retryError != nil {
		return nil, fmt.Errorf("Could not connect to server: %s", retryError)
	}
	db.SetConnMaxLifetime(conf.MaxConnLifetime)
	db.SetMaxOpenConns(conf.MaxOpenConns)
	return db, nil
}
