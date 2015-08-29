// +build windows

package main

import "github.com/cloudfoundry-incubator/diego-ssh/handlers"

func newChannelHandlers() map[string]handlers.NewChannelHandler {
	return map[string]handlers.NewChannelHandler{}
}
