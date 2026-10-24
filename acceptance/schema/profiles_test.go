package schema

import (
	"slices"
	"testing"
)

func TestSupportedProducersMatchTheActiveAcceptanceOrder(t *testing.T) {
	if !slices.Equal(Producers, []int{26, 27}) {
		t.Fatal("active producer order changed", Producers)
	}
	for _, major := range Producers {
		if !IsSupportedProducer(major) {
			t.Fatal("active producer was not recognized", major)
		}
	}
	for _, major := range []int{-1, 0, 15, 25, 28} {
		if IsSupportedProducer(major) {
			t.Fatal("unsupported producer admitted to active acceptance", major)
		}
	}
}
