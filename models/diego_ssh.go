package models

const DIEGO_SSH = "diego-ssh"

type SSHRoute struct {
	ContainerPort   uint16 `json:"container_port"`
	HostFingerprint string `json:"host_fingerprint,omitempty"`
	User            string `json:"user,omitempty"`
	Password        string `json:"password,omitempty"`
	PrivateKey      string `json:"private_key,omitempty"`
}
