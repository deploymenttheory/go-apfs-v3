package apfs_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Invalid membership and shared-space decisions must fail before payload hashing.
func TestContainerAdmission(t *testing.T) {
	s, single, _ := buildInput(t)
	reads := 0
	r := buildReader{Reader: s, data: func() (filesystem.Value, error) {
		reads++
		return buildValue{Reader: bytes.NewReader([]byte("original payload")), readError: errors.New("unexpected payload hash")}, nil
	}}
	for _, tc := range []struct {
		name   string
		change func(*[]apfs.VolumeSpec, *apfs.ContainerBuildOptions)
		want   error
	}{
		{"no-volumes", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { *v = nil }, fs.ErrInvalid},
		{"too-many-volumes", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { *v = make([]apfs.VolumeSpec, 101) }, fs.ErrInvalid},
		{"out-of-range-member", func(_ *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Groups[0].Data = 2 }, fs.ErrInvalid},
		{"same-member", func(_ *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Groups[0].Data = 0 }, fs.ErrInvalid},
		{"repeated-member", func(_ *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Groups = append(o.Groups, o.Groups[0]) }, fs.ErrInvalid},
		{"unpaired-system", func(_ *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Groups = nil }, fs.ErrInvalid},
		{"wrong-role", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { (*v)[1].Role = apfs.VolumeRoleSystem }, fs.ErrInvalid},
		{"mixed-group-case", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { (*v)[1].CaseSensitive = true }, fs.ErrInvalid},
		{"duplicate-volume-uuid", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { (*v)[0].UUID[0] = 1; (*v)[1].UUID[0] = 1 }, filesystem.ErrConflict},
		{"unsupported-role", func(v *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Groups = nil; (*v)[0].Role = 4 }, filesystem.ErrUnsupported},
		{"negative-reserve", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { (*v)[1].Reserve = -1 }, fs.ErrInvalid},
		{"reserve-exceeds-quota", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) {
			(*v)[1].Reserve = 8192
			(*v)[1].Quota = 4096
		}, fs.ErrInvalid},
		{"quota-too-small", func(v *[]apfs.VolumeSpec, _ *apfs.ContainerBuildOptions) { (*v)[1].Quota = 4096 }, filesystem.ErrLimit},
		{"insufficient-volume-slots", func(_ *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Capacity = 512 << 20 }, filesystem.ErrLimit},
		{"overcommitted-reserves", func(v *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) {
			o.Capacity = 1 << 30
			(*v)[0].Reserve = 768 << 20
			(*v)[1].Reserve = 768 << 20
		}, filesystem.ErrLimit},
		{"capacity-limit", func(_ *[]apfs.VolumeSpec, o *apfs.ContainerBuildOptions) { o.Capacity = 1<<40 + 1 }, fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			volumes := []apfs.VolumeSpec{{Reader: r, Name: "System", Role: apfs.VolumeRoleSystem}, {Reader: r, Name: "Data", Role: apfs.VolumeRoleData}}
			o := apfs.ContainerBuildOptions{Time: single.Time, Groups: []apfs.VolumeGroupSpec{{System: 0, Data: 1}}}
			tc.change(&volumes, &o)
			if _, err := apfs.PlanContainer(context.Background(), volumes, o); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if reads == 0 {
		t.Fatal("controls did not reach payload measurement")
	}
}

func TestContainerAutomaticCapacityIncludesReservations(t *testing.T) {
	s, o, _ := buildInput(t)
	volumes := []apfs.VolumeSpec{{Reader: s, Name: "Reserved", Reserve: 200 << 30}, {Reader: s, Name: "Other"}}
	plan, err := apfs.PlanContainer(context.Background(), volumes, apfs.ContainerBuildOptions{Time: o.Time})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Size() <= 200<<30 || plan.Size() > 201<<30 {
		t.Fatal("automatic reserve sizing", plan.Size())
	}
	volumes[0].Reserve = 0
	plan, err = apfs.PlanContainer(context.Background(), volumes, apfs.ContainerBuildOptions{Time: o.Time, Capacity: 512<<20 + 1})
	if err != nil || plan.Size() != 512<<20+4096 {
		t.Fatal("rounded two-volume boundary", plan, err)
	}
}

func TestSingleVolumeUsesContainerPlan(t *testing.T) {
	s, o, _ := buildInput(t)
	ctx := context.Background()
	single, err := apfs.Plan(ctx, s, o)
	if err != nil {
		t.Fatal(err)
	}
	container, err := apfs.PlanContainer(ctx, []apfs.VolumeSpec{{Reader: s, Name: o.Name}}, apfs.ContainerBuildOptions{Time: o.Time})
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	if err = single.Write(ctx, &a); err != nil {
		t.Fatal(err)
	}
	if err = container.Write(ctx, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("single-volume wrapper differs from container engine")
	}
}
