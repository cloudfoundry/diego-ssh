package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"code.cloudfoundry.org/lager"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	*d = Duration(dur)
	return nil
}

func (d *Duration) MarshalJSON() ([]byte, error) {
	t := time.Duration(*d)
	return []byte(fmt.Sprintf(`"%s"`, t.String())), nil
}

type SSHProxyConfig struct {
	Address                   string   `json:"address"`
	HealthCheckAddress        string   `json:"health_check_address"`
	HostKey                   string   `json:"host_key"`
	BBSAddress                string   `json:"bbs_address"`
	CCAPIURL                  string   `json:"cc_api_url"`
	UAATokenURL               string   `json:"uaa_token_url"`
	UAAPassword               string   `json:"uaa_password"`
	UAAUsername               string   `json:"uaa_username"`
	SkipCertVerify            bool     `json:"skip_cert_verify"`
	DropsondePort             int      `json:"dropsonde_port"`
	EnableCFAuth              bool     `json:"enable_cf_auth"`
	EnableDiegoAuth           bool     `json:"enable_diego_auth"`
	DiegoCredentials          string   `json:"diego_credentials"`
	BBSCACert                 string   `json:"bbs_ca_cert"`
	BBSClientCert             string   `json:"bbs_client_cert"`
	BBSClientKey              string   `json:"bbs_client_key"`
	BBSClientSessionCacheSize int      `json:"bbs_client_session_cache_size"`
	BBSMaxIdleConnsPerHost    int      `json:"bbs_max_idle_conns_per_host"`
	ConsulCluster             string   `json:"consul_cluster"`
	AllowedCiphers            string   `json:"allowed_ciphers"`
	AllowedMACs               string   `json:"allowed_macs"`
	AllowedKeyExchanges       string   `json:"allowed_key_exchanges"`
	CommunicationTimeout      Duration `json:"communication_timeout"`
}

var DefaultSSHProxyConfig = SSHProxyConfig{
	Address:              ":2222",
	HealthCheckAddress:   ":2223",
	CommunicationTimeout: Duration(10 * time.Second),
	DropsondePort:        3457,
}

func NewSSHProxyConfig(logger lager.Logger, configPath string) (*SSHProxyConfig, error) {
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(configFile)

	proxyConfig := SSHProxyConfig{}
	err = decoder.Decode(&proxyConfig)
	if err != nil {
		return nil, err
	}

	if proxyConfig.Address == "" {
		proxyConfig.Address = DefaultSSHProxyConfig.Address
	}

	if proxyConfig.HealthCheckAddress == "" {
		proxyConfig.HealthCheckAddress = DefaultSSHProxyConfig.HealthCheckAddress
	}

	if proxyConfig.CommunicationTimeout == 0 {
		proxyConfig.CommunicationTimeout = DefaultSSHProxyConfig.CommunicationTimeout
	}

	if proxyConfig.DropsondePort == 0 {
		proxyConfig.DropsondePort = DefaultSSHProxyConfig.DropsondePort
	}

	return &proxyConfig, nil
}
