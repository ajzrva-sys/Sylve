// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package libvirt

import (
	"fmt"
)

// VMTapName returns the stable ifconfig name for a VM NIC tap interface.
// IFNAMSIZ is 16; "svm100n12" fits. Names are derived at render time and
// never stored in the database.
func VMTapName(rid uint, networkID uint) string {
	return fmt.Sprintf("svm%dn%d", rid, networkID)
}
