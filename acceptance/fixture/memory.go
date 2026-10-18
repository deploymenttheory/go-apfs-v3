package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// MemoryVolume is an in-memory Volume for tests and dry runs. It models
// what the interpreter and observer depend on: a tree of nodes with
// inodes, link counts, modes, flags, attributes, forks, timestamps and a
// capacity that produces ENOSPC.
type MemoryVolume struct {
	mu       sync.Mutex
	nodes    map[string]*memNode // path -> node (hard links share a node)
	nextIno  uint64
	Capacity int64 // bytes; 0 means unlimited
	used     int64
	now      int64
}

type memNode struct {
	ino    uint64
	kind   string
	mode   uint32
	uid    uint32
	gid    uint32
	flags  uint32
	data   []byte
	target string
	xattrs map[string][]byte
	birth  int64
	modify int64
	change int64
	access int64
	links  int
}

// NewMemoryVolume returns a volume with the mount point root present.
func NewMemoryVolume(root string) *MemoryVolume {
	v := &MemoryVolume{nodes: map[string]*memNode{}, nextIno: 16, now: time.Now().UnixNano()}
	v.nodes[path.Clean(root)] = &memNode{ino: 2, kind: "dir", mode: 0o755, links: 1, xattrs: map[string][]byte{}, birth: v.now, modify: v.now, change: v.now, access: v.now}
	return v
}

func (v *MemoryVolume) tick() int64 { v.now += 1000; return v.now }

func (v *MemoryVolume) get(p string) (*memNode, error) {
	n, ok := v.nodes[path.Clean(p)]
	if !ok {
		return nil, syscall.ENOENT
	}
	return n, nil
}

func (v *MemoryVolume) parent(p string) (*memNode, error) {
	n, err := v.get(path.Dir(path.Clean(p)))
	if err != nil {
		return nil, err
	}
	if n.kind != "dir" {
		return nil, syscall.ENOTDIR
	}
	return n, nil
}

func (v *MemoryVolume) newNode(kind string, mode uint32) *memNode {
	v.nextIno++
	t := v.tick()
	return &memNode{ino: v.nextIno, kind: kind, mode: mode, xattrs: map[string][]byte{}, birth: t, modify: t, change: t, access: t, links: 1}
}

func (v *MemoryVolume) charge(delta int64) error {
	if v.Capacity > 0 && v.used+delta > v.Capacity {
		return syscall.ENOSPC
	}
	v.used += delta
	return nil
}

// forkPath splits a ..namedfork/rsrc suffix.
func forkPath(p string) (string, bool) {
	if strings.HasSuffix(p, "/..namedfork/rsrc") {
		return strings.TrimSuffix(p, "/..namedfork/rsrc"), true
	}
	return p, false
}

func (v *MemoryVolume) WriteFile(p string, data []byte, exclusive bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	base, rsrc := forkPath(p)
	if rsrc {
		n, err := v.get(base)
		if err != nil {
			return err
		}
		if n.kind == "dir" {
			return syscall.EPERM
		}
		if n.kind == "symlink" {
			return syscall.ENOENT
		}
		if len(data) == 0 {
			delete(n.xattrs, "com.apple.ResourceFork")
		} else {
			n.xattrs["com.apple.ResourceFork"] = append([]byte(nil), data...)
		}
		n.change = v.tick()
		return nil
	}
	if n, err := v.get(p); err == nil {
		if exclusive {
			return syscall.EEXIST
		}
		if n.kind == "dir" {
			return syscall.EISDIR
		}
		if err := v.charge(int64(len(data)) - int64(len(n.data))); err != nil {
			return err
		}
		n.data = append([]byte(nil), data...)
		n.flags &^= 0x20
		delete(n.xattrs, "com.apple.decmpfs")
		n.modify, n.change = v.tick(), v.now
		return nil
	}
	if _, err := v.parent(p); err != nil {
		return err
	}
	if len(path.Base(p)) > 255 {
		return syscall.ENAMETOOLONG
	}
	if err := v.charge(int64(len(data))); err != nil {
		return err
	}
	n := v.newNode("file", 0o644)
	n.data = append([]byte(nil), data...)
	v.nodes[path.Clean(p)] = n
	return nil
}

func (v *MemoryVolume) AppendFile(p string, data []byte) error {
	v.mu.Lock()
	n, err := v.get(p)
	v.mu.Unlock()
	if err != nil {
		return v.WriteFile(p, data, false)
	}
	return v.Pwrite(p, int64(len(n.data)), data)
}

func (v *MemoryVolume) Pwrite(p string, offset int64, data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	end := offset + int64(len(data))
	if end > int64(len(n.data)) {
		if err := v.charge(end - int64(len(n.data))); err != nil {
			return err
		}
		n.data = append(n.data, make([]byte, end-int64(len(n.data)))...)
	}
	copy(n.data[offset:], data)
	n.modify, n.change = v.tick(), v.now
	return nil
}

func (v *MemoryVolume) Truncate(p string, size int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	if size < int64(len(n.data)) {
		v.used -= int64(len(n.data)) - size
		n.data = n.data[:size]
	} else {
		n.data = append(n.data, make([]byte, size-int64(len(n.data)))...)
	}
	n.modify, n.change = v.tick(), v.now
	return nil
}

func (v *MemoryVolume) Mkdir(p string, mode uint32) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.get(p); err == nil {
		return syscall.EEXIST
	}
	if _, err := v.parent(p); err != nil {
		return err
	}
	v.nodes[path.Clean(p)] = v.newNode("dir", mode)
	return nil
}

func (v *MemoryVolume) Symlink(target, p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.get(p); err == nil {
		return syscall.EEXIST
	}
	if _, err := v.parent(p); err != nil {
		return err
	}
	n := v.newNode("symlink", 0o755)
	n.target = target
	v.nodes[path.Clean(p)] = n
	return nil
}

func (v *MemoryVolume) Link(oldPath, newPath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(oldPath)
	if err != nil {
		return err
	}
	if n.kind == "dir" {
		return syscall.EPERM
	}
	if _, err := v.get(newPath); err == nil {
		return syscall.EEXIST
	}
	if _, err := v.parent(newPath); err != nil {
		return err
	}
	n.links++
	n.change = v.tick()
	v.nodes[path.Clean(newPath)] = n
	return nil
}

func (v *MemoryVolume) Rename(oldPath, newPath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	oldPath, newPath = path.Clean(oldPath), path.Clean(newPath)
	n, err := v.get(oldPath)
	if err != nil {
		return err
	}
	if strings.HasPrefix(newPath, oldPath+"/") {
		return syscall.EINVAL
	}
	if existing, err := v.get(newPath); err == nil {
		if existing == n {
			return nil
		}
		if existing.kind == "dir" && n.kind != "dir" {
			return syscall.EISDIR
		}
		if existing.kind != "dir" && n.kind == "dir" {
			return syscall.ENOTDIR
		}
		if existing.kind == "dir" && v.hasChildren(newPath) {
			return syscall.ENOTEMPTY
		}
		v.dropLink(newPath)
	} else if _, err := v.parent(newPath); err != nil {
		return err
	}
	moved := map[string]*memNode{}
	for p, node := range v.nodes {
		if p == oldPath || strings.HasPrefix(p, oldPath+"/") {
			moved[newPath+strings.TrimPrefix(p, oldPath)] = node
			delete(v.nodes, p)
		}
	}
	for p, node := range moved {
		v.nodes[p] = node
	}
	n.change = v.tick()
	return nil
}

func (v *MemoryVolume) hasChildren(dir string) bool {
	for p := range v.nodes {
		if strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}

func (v *MemoryVolume) dropLink(p string) {
	n := v.nodes[p]
	delete(v.nodes, p)
	n.links--
	if n.links == 0 {
		v.used -= int64(len(n.data))
	}
}

func (v *MemoryVolume) Remove(p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	if n.kind == "dir" {
		return syscall.EPERM
	}
	v.dropLink(path.Clean(p))
	return nil
}

func (v *MemoryVolume) Rmdir(p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	if n.kind != "dir" {
		return syscall.ENOTDIR
	}
	if v.hasChildren(path.Clean(p)) {
		return syscall.ENOTEMPTY
	}
	delete(v.nodes, path.Clean(p))
	return nil
}

func (v *MemoryVolume) Lchmod(p string, mode uint32) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	n.mode = mode & 0o7777
	n.change = v.tick()
	return nil
}

func (v *MemoryVolume) Chflags(p string, flags uint32) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	n.flags = flags
	n.change = v.tick()
	return nil
}

func (v *MemoryVolume) Setxattr(p, name string, data []byte, option string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	if len(name) > 127 {
		return syscall.ENAMETOOLONG
	}
	_, exists := n.xattrs[name]
	switch {
	case option == "create" && exists:
		return syscall.EEXIST
	case option == "replace" && !exists:
		return syscall.Errno(93)
	}
	if name == "com.apple.FinderInfo" && len(data) != 32 {
		return syscall.ERANGE
	}
	n.xattrs[name] = append([]byte(nil), data...)
	n.change = v.tick()
	return nil
}

func (v *MemoryVolume) Removexattr(p, name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	if _, ok := n.xattrs[name]; !ok {
		return syscall.Errno(93)
	}
	delete(n.xattrs, name)
	n.change = v.tick()
	return nil
}

func (v *MemoryVolume) Settimes(p string, birth, modify, access int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return err
	}
	if birth != 0 {
		n.birth = birth
	}
	if modify != 0 {
		n.modify = modify
	}
	if access != 0 {
		n.access = access
	}
	n.change = v.tick()
	return nil
}

func (v *MemoryVolume) Fullfsync(p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.get(p)
	return err
}

func (v *MemoryVolume) Clone(src, dst string) error {
	v.mu.Lock()
	n, err := v.get(src)
	v.mu.Unlock()
	if err != nil {
		return err
	}
	if err := v.WriteFile(dst, n.data, true); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	c := v.nodes[path.Clean(dst)]
	for k, val := range n.xattrs {
		c.xattrs[k] = append([]byte(nil), val...)
	}
	c.mode, c.flags = n.mode, n.flags
	return nil
}

func (v *MemoryVolume) FreeBytes(string) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.Capacity == 0 {
		return 1 << 40, nil
	}
	return v.Capacity - v.used, nil
}

func (v *MemoryVolume) Lstat(p string) (Stat, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return Stat{}, err
	}
	size := int64(len(n.data))
	if n.kind == "symlink" {
		size = int64(len(n.target))
	}
	return Stat{Kind: n.kind, Ino: n.ino, Nlink: uint32(n.links), Mode: n.mode, UID: n.uid, GID: n.gid, Flags: n.flags, Size: size, Allocated: (size + 4095) / 4096 * 4096, Birth: n.birth, Modify: n.modify, Change: n.change, Access: n.access}, nil
}

func (v *MemoryVolume) Readdir(p string) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	if n.kind != "dir" {
		return nil, syscall.ENOTDIR
	}
	prefix := path.Clean(p) + "/"
	var names []string
	for q := range v.nodes {
		if strings.HasPrefix(q, prefix) && !strings.Contains(strings.TrimPrefix(q, prefix), "/") {
			names = append(names, strings.TrimPrefix(q, prefix))
		}
	}
	sort.Strings(names)
	return names, nil
}

func (v *MemoryVolume) Readlink(p string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	if n.kind != "symlink" {
		return nil, syscall.EINVAL
	}
	return []byte(n.target), nil
}

func (v *MemoryVolume) Listxattr(p string, showCompression bool) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	var names []string
	for name := range n.xattrs {
		if !showCompression && n.flags&0x20 != 0 && (name == "com.apple.decmpfs" || name == "com.apple.ResourceFork") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (v *MemoryVolume) Getxattr(p, name string, showCompression bool) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	data, ok := n.xattrs[name]
	if !ok || (!showCompression && n.flags&0x20 != 0 && (name == "com.apple.decmpfs" || name == "com.apple.ResourceFork")) {
		return nil, syscall.Errno(93)
	}
	return append([]byte(nil), data...), nil
}

func (v *MemoryVolume) Hash(p string) (string, int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	base, rsrc := forkPath(p)
	n, err := v.get(base)
	if err != nil {
		return "", 0, err
	}
	data := n.data
	if rsrc {
		data = n.xattrs["com.apple.ResourceFork"]
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data)), nil
}

func (v *MemoryVolume) Pread(p string, offset int64, length int) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	if offset >= int64(len(n.data)) {
		return nil, nil
	}
	end := offset + int64(length)
	if end > int64(len(n.data)) {
		end = int64(len(n.data))
	}
	return append([]byte(nil), n.data[offset:end]...), nil
}

func (v *MemoryVolume) Extents(p, fork string) ([][3]int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	size := int64(len(n.data))
	if fork == "rsrc" {
		size = int64(len(n.xattrs["com.apple.ResourceFork"]))
	}
	if size == 0 {
		return nil, nil
	}
	var runs [][3]int64
	for off := int64(0); off < size; off += 1 << 20 {
		length := size - off
		if length > 1<<20 {
			length = 1 << 20
		}
		runs = append(runs, [3]int64{off, int64(n.ino)<<20 + off, length})
	}
	return runs, nil
}

func (v *MemoryVolume) Holes(string) ([][2]int64, error) { return nil, nil }

func (v *MemoryVolume) ACL(p string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.get(p)
	if err != nil {
		return nil, err
	}
	return n.xattrs["memory.acl"], nil
}

func (v *MemoryVolume) SnapshotLister(string) (SnapshotLister, error) { return noSnapshots{}, nil }

type noSnapshots struct{}

func (noSnapshots) List() ([]string, error) { return nil, nil }
func (noSnapshots) Close() error            { return nil }

// Dump lists every path for test assertions.
func (v *MemoryVolume) Dump() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var paths []string
	for p := range v.nodes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b strings.Builder
	for _, p := range paths {
		n := v.nodes[p]
		fmt.Fprintf(&b, "%s %s ino=%d links=%d mode=%o size=%d\n", n.kind, p, n.ino, n.links, n.mode, len(n.data))
	}
	return b.String()
}

// MkdirAll creates a directory and its parents; it exists for test fakes
// that need host-side scratch paths inside the memory tree.
func (v *MemoryVolume) MkdirAll(p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	clean := path.Clean(p)
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	cur := "/"
	for _, part := range parts {
		cur = path.Join(cur, part)
		if _, ok := v.nodes[cur]; !ok {
			v.nodes[cur] = v.newNode("dir", 0o755)
		}
	}
	return nil
}

// snapshotNode is the serialised form of a memory node for test fakes.
type snapshotNode struct {
	Path   string            `json:"path"`
	Ino    uint64            `json:"ino"`
	Kind   string            `json:"kind"`
	Mode   uint32            `json:"mode"`
	UID    uint32            `json:"uid"`
	GID    uint32            `json:"gid"`
	Flags  uint32            `json:"flags"`
	Data   []byte            `json:"data"`
	Target string            `json:"target"`
	Xattrs map[string][]byte `json:"xattrs"`
	Birth  int64             `json:"birth"`
	Modify int64             `json:"modify"`
	Change int64             `json:"change"`
	Access int64             `json:"access"`
}

// Snapshot serialises the subtree under root with paths relative to root.
// Hard links are preserved through shared inode numbers.
func (v *MemoryVolume) Snapshot(root string) []snapshotNode {
	v.mu.Lock()
	defer v.mu.Unlock()
	root = path.Clean(root)
	var out []snapshotNode
	for p, n := range v.nodes {
		if p == root || !strings.HasPrefix(p, root+"/") {
			continue
		}
		out = append(out, snapshotNode{Path: strings.TrimPrefix(p, root+"/"), Ino: n.ino, Kind: n.kind, Mode: n.mode, UID: n.uid, GID: n.gid, Flags: n.flags, Data: n.data, Target: n.target, Xattrs: n.xattrs, Birth: n.birth, Modify: n.modify, Change: n.change, Access: n.access})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Restore replaces the subtree under root with a snapshot.
func (v *MemoryVolume) Restore(root string, nodes []snapshotNode) {
	v.mu.Lock()
	defer v.mu.Unlock()
	root = path.Clean(root)
	for p := range v.nodes {
		if strings.HasPrefix(p, root+"/") {
			delete(v.nodes, p)
		}
	}
	byIno := map[uint64]*memNode{}
	for _, s := range nodes {
		n := byIno[s.Ino]
		if n == nil {
			n = &memNode{ino: s.Ino, kind: s.Kind, mode: s.Mode, uid: s.UID, gid: s.GID, flags: s.Flags, data: append([]byte(nil), s.Data...), target: s.Target, xattrs: map[string][]byte{}, birth: s.Birth, modify: s.Modify, change: s.Change, access: s.Access}
			for k, val := range s.Xattrs {
				n.xattrs[k] = append([]byte(nil), val...)
			}
			byIno[s.Ino] = n
		}
		n.links++
		v.nodes[path.Join(root, s.Path)] = n
		if s.Ino >= v.nextIno {
			v.nextIno = s.Ino + 1
		}
	}
}
