package smbcol_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/engine"
	smbcol "github.com/SiriusScan/ping++/pkg/protocol/smb"
)

func TestSMBCollectorMetadata(t *testing.T) {
	c, err := smbcol.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	md := c.Metadata()
	if md.ID != "collect.smb" {
		t.Fatalf("id=%q", md.ID)
	}
	if md.Stage != engine.StageCollect {
		t.Fatalf("stage=%q", md.Stage)
	}
}
