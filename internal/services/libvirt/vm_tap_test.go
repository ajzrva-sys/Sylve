// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package libvirt

import "testing"

func TestVMTapName(t *testing.T) {
	cases := []struct {
		rid        uint
		networkID  uint
		want       string
		wantMaxLen int
	}{
		{1, 1, "svm1n1", 16},
		{100, 1, "svm100n1", 16},
		{99999, 12, "svm99999n12", 16},
	}
	for _, tc := range cases {
		got := VMTapName(tc.rid, tc.networkID)
		if got != tc.want {
			t.Errorf("VMTapName(%d, %d) = %q, want %q", tc.rid, tc.networkID, got, tc.want)
		}
		if len(got) > tc.wantMaxLen {
			t.Errorf("VMTapName(%d, %d) = %q exceeds IFNAMSIZ %d", tc.rid, tc.networkID, got, tc.wantMaxLen)
		}
	}
}
