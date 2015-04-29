package authenticators

import "errors"

var SSHDisabledErr = errors.New("SSH Disabled")
var NotDiegoErr = errors.New("Diego Not Enabled")
var FetchAppFailedErr = errors.New("Fetching App Failed")
var InvalidRequestErr = errors.New("CloudController URL Invalid")
var InvalidCCResponse = errors.New("CloudController Response Invalid")
var InvalidDomainErr error = errors.New("Invalid authentication domain")
var InvalidCredentialsErr error = errors.New("Invalid credentials")
var RouteNotFoundErr error = errors.New("SSH routing info not found")
