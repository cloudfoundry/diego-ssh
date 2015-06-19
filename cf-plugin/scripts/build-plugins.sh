#!/bin/bash

set -x

go get github.com/Sirupsen/logrus

GOOS=linux GOARCH=386 go build -o ssh-plugin-linux-386 .
GOOS=linux GOARCH=amd64 go build -o ssh-plugin-linux-amd64 .
GOOS=windows GOARCH=386 go build -o ssh-plugin-win32.exe .
GOOS=windows GOARCH=amd64 go build -o ssh-plugin-win64.exe .
go build -o ssh-plugin-darwin-amd64 .

shasum -a1 ssh-plugin-*
