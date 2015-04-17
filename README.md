# diego-ssh

Diego-ssh is an implmentation of an ssh proxy server and a lightweight
ssh daemon. When deployed and configured correctly, they provide a simple and
scalable way access containers associated with LRP instances.

## Proxy

The proxy server hosts the user-accessible ssh endpoint and is responsble for
authentication, policy enforcment, and access controls in the context of Cloud
Foundry. After succesfully authenticating with the proxy, the proxy will
attempt to locate the target container and create an ssh session to the
container. Once both sessions have been established, the proxy will manage the
communication between the user's ssh client and the container's ssh daemon.

Container must run an ssh daemon on port 2222 inside the container and map
that port to the host.

### Authentication

Clients authenticate with the proxy using a specially formed user name that
describes the authentication domain and target container and a password that
contains the appropriate credentials for the domain.

For Diego, the user is of the form `diego:`_process-guid_/_index_ and the
password must hold the receptor credentials in the form _user_:_password_.

Client example:

```
ssh -p 2222 'diego:my-process-guid/1'@ssh.10.244.0.34.xip.io
```

The user and password used by the proxy are extracted from the diegoAPIURL
that is specified on the command line. If the user info field is empty, the
password will be empty as well.

## SSH Daemon

The ssh daemon is a lightweight implementation that is built around go's ssh
library. It supports command execution, interactive shells, and local port
forwarding. The daemon is self-contained and has no dependencies on the
container root filesystem.

The daemon is expected to be made available on a file server and Diego LRPs
that want to use it can include a download action to acquire the binary and a
run action to start it.

##### Example LRP
```json
{
  "process_guid": "ssh-process-guid",
  "domain": "ssh-experiments",
  "rootfs": "preloaded:lucid64",
  "instances": 1,
  "start_timeout": 30,
  "setup": {
    "download": {
      "artifact": "diego-sshd",
      "from": "http://file-server.service.consul:8080/v1/static/diego-sshd/diego-sshd.tgz",
      "to": "/tmp",
      "cache_key": "diego-sshd"
    }
  },
  "action": {
    "run": {
      "path": "/tmp/diego-sshd",
      "args": [
          "-address=0.0.0.0:2222",
          "-authorizedKey=ssh-rsa ..."
      ],
      "env": [],
      "resource_limits": {}
    }
  },
  "ports": [ 2222 ]
}
```

##### Dependencies
If you wish to use `scp` to copy files in and out of the containers, the
container root file system must include `/usr/bin/scp`. The Cloud Foundry root
file systems [cflinuxfs2][cflinuxfs2] and [lucid64][lucid64] already contain
the binaries but custom root file systems or docker images may not.

scp example:
```
scp -oUser='diego:ssh-process-guid/0' -P 2222 my-local-file.json ssh.10.244.0.34.xip.io:my-remote-file.json
```

[lucid64]: https://github.com/cloudfoundry/stacks/tree/master/lucid64
[cflinuxfs2]: https://github.com/cloudfoundry/stacks/tree/master/cflinuxfs2

