package fixture

import "time"

func unixZero() time.Time { return time.Unix(0, 0).UTC() }
