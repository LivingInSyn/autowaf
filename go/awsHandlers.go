package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go/service/wafv2"
)

// IPSetLister is a function pointer to get IP sets from AWS WAFv2
type IPSetLister func(input *wafv2.ListIPSetsInput) (*wafv2.ListIPSetsOutput, error)

// IPSetUpdater is a function pointer to the wafv2.UpdateIPSet or a mock of it
type IPSetUpdater func(input *wafv2.UpdateIPSetInput) (*wafv2.UpdateIPSetOutput, error)

// IPSetGetter gets a specific IP set from aws or a mack of it
type IPSetGetter func(input *wafv2.GetIPSetInput) (*wafv2.GetIPSetOutput, error)

// ErrIPNotFound is returned when an IP is not found in the set
var ErrIPNotFound = errors.New("IP Not found in set")

// GetIPSet returns a wafv2 ipset from AWS WAFv2
func GetIPSet(ipSetLister IPSetLister, envconf *EnvConfig) (*wafv2.IPSetSummary, error) {
	scope := "REGIONAL"
	lIPInput := wafv2.ListIPSetsInput{
		Scope: &scope,
	}
	ipsets, err := ipSetLister(&lIPInput)
	if err != nil {
		log.Error().Str("Error", err.Error()).Msg("Error getting IP sets from WAF")
		return nil, errors.New("Error getting IP sets from WAF")
	}
	for _, ipset := range ipsets.IPSets {
		// log.Debug().
		// 	Str("ipset name", *ipset.Name).
		// 	Str("conf name", envconf.BlockListName).
		// 	Msg("Blocklist names to compare")
		if *ipset.Name == envconf.BlockListName {
			log.Printf("Found blocklist with name: %s", envconf.BlockListName)
			return ipset, nil
		}
	}
	return nil, errors.New("Couldn't find the blocklist")
}

// UpdateIPSet updates the designated IP set on the WAF with the iplist
func UpdateIPSet(iplist []*string, updater IPSetUpdater, ipset *wafv2.IPSetSummary) error {
	scope := "REGIONAL"
	updateInput := wafv2.UpdateIPSetInput{
		Addresses: iplist,
		Id:        ipset.Id,
		LockToken: ipset.LockToken,
		Name:      ipset.Name,
		Scope:     &scope,
	}
	_, err := updater(&updateInput)
	if err != nil {
		log.Error().Str("Error", err.Error()).Msg("Error updating ipset")
		return err
	}
	return nil
}

// RemoveIPfromIPSet will pull the current IP set, remove ip from it and update that ipset
func RemoveIPfromIPSet(ipSetLister IPSetLister, ipSetGetter IPSetGetter,
	ipIPSetUpdater IPSetUpdater, envConfig *EnvConfig, ip *string) error {
	// ListIPSets
	// GetIPSet
	// UpdateIPSet
	if *ip == "" {
		return errors.New("IP cannot be blank")
	}
	parsedIP := net.ParseIP(*ip)
	if parsedIP == nil {
		return errors.New("Failed to parse IP")
	}
	ipset, err := GetIPSet(ipSetLister, envConfig)
	if err != nil {
		log.Error().Str("IP", *ip).Str("Error", err.Error()).
			Msg("Error getting IP set in RemoveIP")
		return err
	}
	// get the IP set
	scope := "REGIONAL"
	gipInput := wafv2.GetIPSetInput{
		Id:    ipset.Id,
		Name:  ipset.Name,
		Scope: &scope,
	}
	ipsetOutput, err := ipSetGetter(&gipInput)
	if err != nil {
		log.Error().Str("IP", *ip).Str("Error", err.Error()).Msg("Error getting full IP set")
		return err
	}
	ipIndex := -1

	for idx, currentIP := range ipsetOutput.IPSet.Addresses {
		if *currentIP == fmt.Sprintf("%s/32", *ip) {
			ipIndex = idx
			break
		}
	}
	if ipIndex == -1 {
		log.Info().Str("IP", *ip).Msg("Tried to remove IP that wasn't in blocklist")
		return ErrIPNotFound
	}
	// remove element and truncate list
	ipsetOutput.IPSet.Addresses[ipIndex] = ipsetOutput.IPSet.Addresses[len(ipsetOutput.IPSet.Addresses)-1]
	ipsetOutput.IPSet.Addresses[len(ipsetOutput.IPSet.Addresses)-1] = nil
	ipsetOutput.IPSet.Addresses = ipsetOutput.IPSet.Addresses[:len(ipsetOutput.IPSet.Addresses)-1]
	// update the IP set with the addresses removed
	updateInput := wafv2.UpdateIPSetInput{
		Addresses: ipsetOutput.IPSet.Addresses,
		Id:        ipset.Id,
		LockToken: ipsetOutput.LockToken,
		Name:      ipset.Name,
		Scope:     &scope,
	}
	_, err = ipIPSetUpdater(&updateInput)
	if err != nil {
		log.Error().Str("IP", *ip).Str("Error", err.Error()).Msg("Error updating ipset after removing IP")
		return err
	}
	log.Info().Str("IP", *ip).Msg("Removed IP from blocklist")
	return nil
}
