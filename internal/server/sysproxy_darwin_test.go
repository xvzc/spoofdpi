//go:build darwin

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSysProxyJobs_ServiceNameIsOneArgument(t *testing.T) {
	const pacURL = "http://127.0.0.1:8081/proxy.pac"
	for _, service := range []string{"USB 10/100/1000 LAN", "Bob's Wi-Fi"} {
		t.Run(service, func(t *testing.T) {
			jobs := sysProxyJobs(service, pacURL)

			assert.Equal(t, []NetworkJob{
				{
					Description: "set auto proxy URL",
					Apply: CommandAction{
						"networksetup", "-setautoproxyurl", service, pacURL,
					},
					Reset: CommandAction{
						"networksetup", "-setautoproxystate", service, "off",
					},
				},
				{
					Description: "enable proxy auto discovery",
					Apply: CommandAction{
						"networksetup", "-setproxyautodiscovery", service, "on",
					},
					Reset: CommandAction{
						"networksetup", "-setproxyautodiscovery", service, "off",
					},
				},
			}, jobs)
		})
	}
}
