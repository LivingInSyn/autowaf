package main

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/service/wafv2"
)

var MockGetError string = "Mock Error on GET"

func MockIPSetLister(input *wafv2.ListIPSetsInput) (*wafv2.ListIPSetsOutput, error) {
	tval := "test"
	ipset := wafv2.IPSetSummary{
		ARN:         &tval,
		Description: &tval,
		Id:          &tval,
		LockToken:   &tval,
		Name:        &tval,
	}
	summaries := []*wafv2.IPSetSummary{&ipset}
	lio := wafv2.ListIPSetsOutput{
		IPSets:     summaries,
		NextMarker: nil,
	}
	return &lio, nil
}
func MockIPSetListerFail(input *wafv2.ListIPSetsInput) (*wafv2.ListIPSetsOutput, error) {
	return nil, errors.New(MockGetError)
}
func MockUpdateSet(input *wafv2.UpdateIPSetInput) (*wafv2.UpdateIPSetOutput, error) {
	lt := "abc123"
	output := wafv2.UpdateIPSetOutput{
		NextLockToken: &lt,
	}
	return &output, nil
}
func MockUpdateSetFail(input *wafv2.UpdateIPSetInput) (*wafv2.UpdateIPSetOutput, error) {
	return nil, errors.New("Some failure")
}
func MockIPSetGetter(input *wafv2.GetIPSetInput) (*wafv2.GetIPSetOutput, error) {
	tval := "test"
	vval := "4"
	ip1 := "192.168.1.1/32"
	ip2 := "192.168.1.2/32"
	ips := []*string{&ip1, &ip2}
	ipset := wafv2.IPSet{
		ARN:              &tval,
		Addresses:        ips,
		Description:      &tval,
		IPAddressVersion: &vval,
		Id:               &tval,
		Name:             &tval,
	}
	op := wafv2.GetIPSetOutput{
		IPSet:     &ipset,
		LockToken: &tval,
	}
	return &op, nil
}
func MockIPSetGetterFail(input *wafv2.GetIPSetInput) (*wafv2.GetIPSetOutput, error) {
	return nil, errors.New(MockGetError)
}

func TestGetIPSetGood(t *testing.T) {
	// create an env config
	env := EnvConfig{
		BlockListName: "test",
	}
	// create return vals
	s, e := GetIPSet(MockIPSetLister, &env)
	if e != nil {
		t.Fail()
	}
	if *s.Id != env.BlockListName {
		t.Fail()
	}
}

func TestGetIPSetNoMatchList(t *testing.T) {
	// create an env config
	env := EnvConfig{
		BlockListName: "sad",
	}
	// create return vals
	_, e := GetIPSet(MockIPSetLister, &env)
	// verify that we got an error
	if e == nil {
		t.Fail()
	}
	if e.Error() != "Couldn't find the blocklist" {
		t.Fail()
	}
}

func TestGetIPSetErrorGet(t *testing.T) {
	env := EnvConfig{
		BlockListName: "sad",
	}
	// create return vals
	_, e := GetIPSet(MockIPSetListerFail, &env)
	// verify that we got an error
	if e == nil {
		t.Fail()
	}
	if e.Error() != "Error getting IP sets from WAF" {
		t.Fail()
	}
}

func TestUpdateIPSet(t *testing.T) {
	tval := "test"
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	ips := []*string{&ip1, &ip2}
	ipset := wafv2.IPSetSummary{
		ARN:         &tval,
		Description: &tval,
		Id:          &tval,
		LockToken:   &tval,
		Name:        &tval,
	}
	summaries := []*wafv2.IPSetSummary{&ipset}
	e := UpdateIPSet(ips, MockUpdateSet, summaries[0])
	if e != nil {
		t.Logf("Non-nill error, %s", e)
		t.Fail()
	}
}

func TestUpdateIPSetError(t *testing.T) {
	tval := "test"
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"
	ips := []*string{&ip1, &ip2}
	ipset := wafv2.IPSetSummary{
		ARN:         &tval,
		Description: &tval,
		Id:          &tval,
		LockToken:   &tval,
		Name:        &tval,
	}
	summaries := []*wafv2.IPSetSummary{&ipset}
	e := UpdateIPSet(ips, MockUpdateSetFail, summaries[0])
	if e == nil {
		t.Log("Nil error (shouldn't be)")
		t.Fail()
	}
}

func TestRemoveIPfromIPSet(t *testing.T) {
	ipToRemove := "192.168.1.1"
	env := EnvConfig{
		BlockListName: "test",
	}
	err := RemoveIPfromIPSet(MockIPSetLister, MockIPSetGetter,
		MockUpdateSet, &env, &ipToRemove)
	if err != nil {
		t.Logf("Shouldn't have gotten an error. Err: %s", err.Error())
		t.Fail()
	}
}

func TestRemoveIPfromIPSetFailNoIP(t *testing.T) {
	ipToRemove := "192.168.1.5"
	env := EnvConfig{
		BlockListName: "test",
	}
	err := RemoveIPfromIPSet(MockIPSetLister, MockIPSetGetter,
		MockUpdateSet, &env, &ipToRemove)
	if err != ErrIPNotFound {
		t.Logf("Should have gotten an IP Not Found error. Err: %s", err.Error())
		t.Fail()
	}
}
