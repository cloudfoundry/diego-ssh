#!/bin/bash

set -x

go get github.com/Sirupsen/logrus

GOOS=linux GOARCH=386 go build -o ssh-plugin-linux-386 plugin.go
GOOS=linux GOARCH=amd64 go build -o ssh-plugin-linux-amd64 plugin.go
GOOS=windows GOARCH=386 go build -o ssh-plugin-win32.exe plugin.go
GOOS=windows GOARCH=amd64 go build -o ssh-plugin-win64.exe plugin.go
go build -o ssh-plugin-darwin-amd64 plugin.go

shasum -a1 ssh-plugin-*
