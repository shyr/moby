package graphdriver

// NOTE: This file is copied from amir73il's "Implement XFS quota for overlay2" pull requests and improve it.
//       amir73il's PR : https://github.com/docker/docker/pull/24771

/*
#include <stdlib.h>
#include <dirent.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
#ifndef _LINUX_FS_H
struct fsxattr {
	__u32		fsx_xflags;
	__u32		fsx_extsize;
	__u32		fsx_nextents;
	__u32		fsx_projid;
	unsigned char	fsx_pad[12];
};
#endif
#define FS_XFLAG_PROJINHERIT	0x00000200
#define FS_IOC_FSGETXATTR		_IOR ('X', 31, struct fsxattr)
#define FS_IOC_FSSETXATTR		_IOW ('X', 32, struct fsxattr)

#define PRJQUOTA	2
#define XFS_PROJ_QUOTA	2
#define Q_XSETPQLIM QCMD(Q_XSETQLIM, PRJQUOTA)
#define Q_XGETPQUOTA QCMD(Q_XGETQUOTA, PRJQUOTA)
*/
import "C"
import (
	"fmt"
	"unsafe"
	"syscall"
	"os"
	"path"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Quota struct {
	Size uint64
}

type QuotaCtl struct {
	backingFsDev    string
	nextProjectID 	uint32
	quotas 		map[string]uint32
}

func NewQuotaCtl(basePath string) (*QuotaCtl, error) {
	//
	// get max project id for next use
	//
	maxProjectID, err := getMaxProjectId(basePath)
	if err != nil {
		return nil, err
	}
	//
	// create backing filesystem device
	//
	backingFsDev, err := makeBackingFsDev(basePath)
	if err != nil {
		return nil, err
	}
	//
	// create
	//
	return &QuotaCtl{
		backingFsDev: backingFsDev,
		nextProjectID: maxProjectID,
		quotas: make(map[string]uint32),
	}, nil
}

func (q *QuotaCtl) SetQuota(targetPath string, quota Quota) error {

	var fsx C.struct_fsxattr

	projectID, ok := q.quotas[targetPath]
	if !ok {
		projectID = q.nextProjectID

		dir, err := openDir(targetPath)
		if err != nil {
			return err
		}
		defer closeDir(dir)

		//
		// assign project id to new container directory
		//
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSGETXATTR,
			uintptr(unsafe.Pointer(&fsx)))
		if errno != 0 {
			return fmt.Errorf("Failed to get projid for %s: %v", targetPath, errno.Error())
		}
		fsx.fsx_projid = C.__u32(projectID)
		fsx.fsx_xflags |= C.FS_XFLAG_PROJINHERIT
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSSETXATTR,
			uintptr(unsafe.Pointer(&fsx)))
		if errno != 0 {
			return fmt.Errorf("Failed to set projid for %s: %v", targetPath, errno.Error())
		}

		q.quotas[targetPath] = projectID
		q.nextProjectID++
	}

	//
	// set the quota limit for the container's project id
	//
	var d C.fs_disk_quota_t
	d.d_version = C.FS_DQUOT_VERSION
	d.d_id = fsx.fsx_projid
	d.d_flags = C.XFS_PROJ_QUOTA

	d.d_fieldmask = C.FS_DQ_BHARD
	d.d_blk_hardlimit = C.__u64(quota.Size / 512)

	var cs = C.CString(q.backingFsDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := syscall.Syscall6(syscall.SYS_QUOTACTL, C.Q_XSETPQLIM,
		uintptr(unsafe.Pointer(cs)), uintptr(fsx.fsx_projid),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("Failed to set quota limit for projid %d on %s: %v",
			projectID, q.backingFsDev, errno.Error())
	}

	d.d_fieldmask = C.FS_DQ_BSOFT
	d.d_blk_softlimit = C.__u64(quota.Size / 512)

	_, _, errno = syscall.Syscall6(syscall.SYS_QUOTACTL, C.Q_XSETPQLIM,
		uintptr(unsafe.Pointer(cs)), uintptr(fsx.fsx_projid),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("Failed to set quota limit for projid %d on %s: %v",
			projectID, q.backingFsDev, errno.Error())
	}

	return nil
}

func (q *QuotaCtl) GetQuota(targetPath string, quota *Quota) error {

	projectID, ok := q.quotas[targetPath]
	if !ok {
		return fmt.Errorf("quota not found for path : %s", targetPath)
	}

	//
	// get the quota limit for the container's project id
	//
	var d C.fs_disk_quota_t

	var cs = C.CString(q.backingFsDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := syscall.Syscall6(syscall.SYS_QUOTACTL, C.Q_XGETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(C.__u32(projectID)),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("Failed to get quota limit for projid %d on %s: %v",
			projectID, q.backingFsDev, errno.Error())
	}
	quota.Size = uint64(d.d_blk_hardlimit) * 512

	return nil
}

func getMaxProjectId(path string) (uint32, error) {

	var projectID uint32 = 1
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return 0, fmt.Errorf("read directory failed : %s", path)
	}
	for _, file := range files {
		if !file.IsDir() {
			continue;
		}
		dir, err := openDir(filepath.Join(path, file.Name()))
		if err != nil {
			fmt.Errorf("open dir failed %s", filepath.Join(path, file.Name()))
			return 0, err
		}
		defer closeDir(dir)
		var fsx C.struct_fsxattr
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSGETXATTR,
			uintptr(unsafe.Pointer(&fsx)))
		if errno != 0 {
			continue
		}
		if projectID <= uint32(fsx.fsx_projid) {
			projectID = uint32(fsx.fsx_projid) + 1
		}
	}
	return projectID, nil
}

func free(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func openDir(path string) (*C.DIR, error) {
	Cpath := C.CString(path)
	defer free(Cpath)

	dir := C.opendir(Cpath)
	if dir == nil {
		return nil, fmt.Errorf("Can't open dir")
	}
	return dir, nil
}

func closeDir(dir *C.DIR) {
	if dir != nil {
		C.closedir(dir)
	}
}

func getDirFd(dir *C.DIR) uintptr {
	return uintptr(C.dirfd(dir))
}

// get the backing block device of the driver home directory
// and create a block device node under the home directory
// to be used by quotactl commands
func makeBackingFsDev(home string) (string, error) {
	fileinfo, err := os.Stat(home)
	if err != nil {
		return "", err
	}

	backingFsDev := path.Join(home, "backingFsDev")
	syscall.Unlink(backingFsDev)
	stat := fileinfo.Sys().(*syscall.Stat_t)
	if err := syscall.Mknod(backingFsDev, syscall.S_IFBLK|0600, int(stat.Dev)); err != nil {
		return "", fmt.Errorf("Failed to mknod %s: %v", backingFsDev, err)
	}

	return backingFsDev, nil
}

var numberPattern *regexp.Regexp = regexp.MustCompilePOSIX("^[0-9]+$")
var bytesPattern *regexp.Regexp = regexp.MustCompilePOSIX("^[0-9]+[bBkKmMgGtT]{1}$")

const (
	BYTE     = 1.0
	KILOBYTE = 1024 * BYTE
	MEGABYTE = 1024 * KILOBYTE
	GIGABYTE = 1024 * MEGABYTE
	TERABYTE = 1024 * GIGABYTE
)

func BytesStringToUint64(s string) (uint64, error) {
	str := strings.TrimSpace(s)
	if numberPattern.Match([]byte(str)) {
		return strconv.ParseUint(s, 0, 64)
	}
	if bytesPattern.Match([]byte(str)) {
		num, err := strconv.ParseUint(str[0:len(str) - 1], 0, 64)
		if err != nil {
			return 0, err
		}
		switch strings.ToUpper(string(str[len(str)-1:])) {
		case "T" :
			return num * TERABYTE, nil
		case "G" :
			return num * GIGABYTE, nil
		case "M" :
			return num * MEGABYTE, nil
		case "K" :
			return num * KILOBYTE, nil
		case "B" :
			return num, nil
		}

	}
	return 0, fmt.Errorf("string bytes pattern error : %s", s)
}
