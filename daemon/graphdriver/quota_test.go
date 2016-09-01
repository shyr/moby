package graphdriver

import (
	"testing"
	"os"
	"os/exec"
	"fmt"
	"path"
)

var testPath = "/docker_xfs_quota_test"

func init() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Errorf("os.Getwd error : %v", err)
		wd = testPath
	}
	testPath = path.Join(wd, "test")
	os.RemoveAll(testPath)
	os.MkdirAll(testPath, 0777)
	os.MkdirAll(path.Join(testPath, "first"), 0777)
	os.MkdirAll(path.Join(testPath, "second"), 0777)
}

func cleanup() {
	os.RemoveAll(testPath)
}

func TestSetGetQuota(t *testing.T) {

	defer cleanup()

	ctl, err := NewQuotaCtl(testPath)
	if err != nil {
		t.Errorf("create quotactl error : %v", err)
	}

	var first Quota
	first.Size, err = BytesStringToUint64("1M")
	if err != nil {
		t.Errorf("create quota error")
	}

	err = ctl.SetQuota(path.Join(testPath, "first"), first)
	if err != nil {
		t.Errorf("set first quota failed : %v", err)
	}

	var second Quota

	err = ctl.GetQuota(path.Join(testPath, "first"), &second)
	if err != nil {
		t.Errorf("get first quota failed : %v", err)
	}

	if second.Size != (1024 * 1024) {
		t.Errorf("set/get quota size mismatched %d:%d", first.Size, second.Size)
	}

	err = ctl.SetQuota(path.Join(testPath, "second"), second)
	if err != nil {
		t.Errorf("set second quota failed : %v", err)
	}

	// check create file success
	out, err := exec.Command("dd", "if=/dev/zero", "of=" + path.Join(testPath, "first") + "/file", "bs=1024", "count=1000").CombinedOutput()
	if err != nil {
		t.Errorf("execute dd command error : %s", out)
	}

	// check create file failed because quota
	out, err = exec.Command("dd", "if=/dev/zero", "of=" + path.Join(testPath, "first") + "/file", "bs=1024", "count=1025").CombinedOutput()
	if err == nil {
		t.Errorf("FAILED - dd command can write more than quota limits")
	}

	maxProjectID, err := getMaxProjectId(testPath)
	if err != nil {
		t.Errorf("get max project id failed : %v", err)
	}
	if maxProjectID != 3 {
		t.Errorf("get max project id returns invalid %d:%d", maxProjectID, ctl.nextProjectID)
	}

}

func TestBytesStringToUint64(t *testing.T) {
	result, err := BytesStringToUint64("1024")
	if err != nil || result != 1024 {
		t.Errorf("byte to string error 1024")
	}
	result, err = BytesStringToUint64("1024k")
	if err != nil || result != 1024 * 1024 {
		t.Errorf("byte to string error 1024k")
	}
	result, err = BytesStringToUint64("1024m")
	if err != nil || result != 1024 * 1024 * 1024 {
		t.Errorf("byte to string error 1024m")
	}
	result, err = BytesStringToUint64("1024g")
	if err != nil || result != 1024 * 1024 * 1024 * 1024 {
		t.Errorf("byte to string error 1024g")
	}
	result, err = BytesStringToUint64("1024t")
	if err != nil || result != 1024 * 1024 * 1024 * 1024 * 1024 {
		t.Errorf("byte to string error 1024t")
	}
}