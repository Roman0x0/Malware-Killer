package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
	psapi    = syscall.NewLazyDLL("Psapi.dll")

	procOpenProcess        = kernel32.MustFindProc("OpenProcess")
	procReadProcessMemory  = kernel32.MustFindProc("ReadProcessMemory")
	procEnumProcessModules = psapi.NewProc("EnumProcessModulesEx")
)

const PROCESS_ALL_ACCESS = 0x1F0FFF

func OpenProcess(pid int) uintptr {
	handle, _, _ := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(1), uintptr(pid))
	return handle
}

func READ(hProcess uintptr, address, size uintptr) []byte {
	var data = make([]byte, size)
	var length uint32

	procReadProcessMemory.Call(hProcess, address,
		uintptr(unsafe.Pointer(&data[0])),
		size, uintptr(unsafe.Pointer(&length)))

	return data
}

func getBaseAddress(handle uintptr) uintptr {
	modules := [1024]uint64{}
	var needed uintptr
	procEnumProcessModules.Call(
		handle,
		uintptr(unsafe.Pointer(&modules)),
		uintptr(1024),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(0x03),
	)
	for i := uintptr(0); i < needed/unsafe.Sizeof(modules[0]); i++ {
		if i == 0 {
			return uintptr(modules[i])
		}
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ScanForMalware(p *process.Process) (resultScan string) {

	malwareRisk := 0

	processName, _ := p.Name()
	processNameFormatted := strings.Split(processName, ".exe")[0]
	processPath, _ := p.Exe()

	if strings.Contains(processName, ".vshost.exe") {
		return "clean"
	}

	if processPath == "" {
		return "clean"
	}
	if processPath == os.Args[0] {
		return "clean"
	}

	// Read bytes from memory of process
	processHandle := OpenProcess(int(p.Pid))
	baseAddress := getBaseAddress(processHandle)

	result := READ(processHandle, baseAddress, 100000)
	reader := bytes.NewReader(result)

	fMem, err := pe.NewFile(reader)
	if err != nil {
		return "clean"
	}
	defer fMem.Close()

	fOrig, err := pe.Open(processPath)
	if err != nil {
		return "clean"
	}
	defer fOrig.Close()

	minimumNumberOfSections := min(len(fMem.Sections), len(fOrig.Sections))

	// Scan each section of PE file and compare it to the original section
	// Usually injection methods like RunPE / Process Hollowing change the sections
	for i := 0; i < minimumNumberOfSections; i++ {
		memSection := fMem.Sections[i]
		origSection := fOrig.Sections[i]

		if memSection.Name != origSection.Name {
			malwareRisk++
		}

		if memSection.VirtualSize != origSection.VirtualSize {
			malwareRisk++
		}

		if memSection.VirtualAddress != origSection.VirtualAddress {
			malwareRisk++
		}

		if memSection.Size != origSection.Size {
			malwareRisk++
		}

		if memSection.Offset != origSection.Offset {
			malwareRisk++
		}

		if memSection.PointerToRelocations != origSection.PointerToRelocations {
			malwareRisk++
		}

		if memSection.PointerToLineNumbers != origSection.PointerToLineNumbers {
			malwareRisk++
		}

		if memSection.NumberOfRelocations != origSection.NumberOfRelocations {
			malwareRisk++
		}

		if memSection.NumberOfLineNumbers != origSection.NumberOfLineNumbers {
			malwareRisk++
		}

		if memSection.Characteristics != origSection.Characteristics {
			malwareRisk++
		}

	}

	// If malware risk is above 5 then its most likely malware
	// If it is then it deletes registry entrys (persistence)
	if malwareRisk >= 5 {

		DeleteRegistry(`Software\Microsoft\Windows\CurrentVersion\Run`, processNameFormatted)
		DeleteRegistry(`Software\Microsoft\Windows\CurrentVersion\RunOnce`, processNameFormatted)

		return "malicious"
	}
	return "clean"
}

// Section for miners
//
// common ports used by miners
var portList = []int{
	9999,
	14444,
	14433,
	6666,
	16666,
	6633,
	16633,
	4444,
	14444,
	3333,
	13333,
	7777,
	5555,
	9980,
	9000,
}

// common pools used by miners
var commonPools = []string{
	"ethermine.org",
	"2miners.com",
	"supportxmr.com",
	"nanopool.org",
}

var activeConnections []Connections

type Connections struct {
	ProcessID  int32
	RemotePort int
}

// gets all actie TCP connections on the system and adds them into an array
func GetActiveConnections() {
	out, err := exec.Command("netstat.exe", "-a", "-n", "-o").Output()
	if err != nil {
		panic(err)
	}

	result := string(out)
	rows := strings.Split(result, "\r\n")
	for _, row := range rows {
		if row == "" {
			continue
		}

		if strings.Contains(row, "0.0.0.0") || strings.Contains(row, "127.0.0.1") || strings.Contains(row, "[::") {
			continue
		}

		a := regexp.MustCompile(`\\s+`)
		tokens := a.Split(row, -1)

		if len(tokens) > 4 && tokens[1] == "TCP" {
			ipAddr := strings.Split(tokens[3], ":")
			remotePort, _ := strconv.Atoi(ipAddr[1])
			pid, _ := strconv.Atoi(tokens[5])

			connection := Connections{
				ProcessID:  int32(pid),
				RemotePort: remotePort,
			}

			activeConnections = append(activeConnections, connection)
		}
	}
}

func ElementExist(s []Connections, port int) bool {
	for _, v := range s {
		if v.RemotePort == port {
			return true
		}
	}
	return false
}

func ElementExistsPort(s []int, port int) bool {
	for _, v := range s {
		if v == port {
			return true
		}
	}
	return false
}

// Scans for miners running on the system
func ScanForMiners(p *process.Process) (resultScan string) { //func ScanForMiners(p *process.Process, ourpid int32) (resultScan string)  TO SKIP A PROCESS BY PID

	// miner risk used to determine how likely it is that a miner was found, can be adjusted to your liking
	minerRisk := 0

	processName, _ := p.Name()
	processNameFormatted := strings.Split(processName, ".exe")[0]
	processArgs, _ := p.Cmdline()

	/*if p.Pid == ourpid {
		return
	}*/

	// Step 1.
	// Check if any active TCP connection
	for _, activeConnection := range activeConnections {
		if p.Pid == activeConnection.ProcessID && ElementExistsPort(portList, activeConnection.RemotePort) {
			if processArgs != "" {
				minerRisk += 2
			}
		}
	}

	// Step 2.
	// Check the processes command line arguments (usually contain configuration)
	if processArgs != "" {

		if strings.Contains(processArgs, "-o") && strings.Contains(processArgs, "-u") {
			minerRisk++
		}

		if strings.Contains(processArgs, "-p") && strings.Contains(processArgs, "-u") {
			minerRisk++
		}

		if strings.Contains(processArgs, "--pool") && strings.Contains(processArgs, "--user") {
			minerRisk++
		}

		if strings.Contains(processArgs, "--algo") {
			minerRisk++
		}

		if strings.Contains(processArgs, "--algo") {
			minerRisk++
		}

		for _, pool := range commonPools {
			if strings.Contains(processArgs, pool) {
				minerRisk++
			}
		}

		// Step 2.1
		for _, port := range portList {
			// check if port is also in active ports
			portActive := ElementExist(activeConnections, port)

			if portActive && strings.Contains(processArgs, strconv.Itoa(port)) {
				minerRisk += 2
			} else {
				if strings.Contains(processArgs, strconv.Itoa(port)) {
					minerRisk++
				}
			}
		}
	}

	// Step 3.
	// If the miner risk is above 4 it deletes registry keys for reboot (persistence) and its most likely a miner
	if minerRisk >= 4 {

		DeleteRegistry(`Software\Microsoft\Windows\CurrentVersion\Run`, processNameFormatted)
		DeleteRegistry(`Software\Microsoft\Windows\CurrentVersion\RunOnce`, processNameFormatted)

		return "malicious"
	}

	return "clean"
}

//
// Removing from registry
//

func DeleteRegistry(regPath, value string) {
	key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.ALL_ACCESS)
	if err != nil {
		return
	}

	valueNames, err := key.ReadValueNames(1000)
	if err != nil && err != io.EOF {
		return
	}

	for _, valueName := range valueNames {

		if valueName == value {
			err = key.DeleteValue(valueName)
			if err != nil && err != io.EOF {
				return
			}
		}

	}
}

func main() {

	// Can be used to exclude specific programs by PID
	/*argLength := len(os.Args[1:])
	if argLength == 0 {
		return
	}

	OWNPID, _ := strconv.Atoi(os.Args[1])*/

	GetActiveConnections()

	killedMalware := 0
	killedMiners := 0

	listProcesses, _ := process.Processes()
	for _, process := range listProcesses {

		minerResult := ScanForMiners(process)
		if minerResult == "malicious" {
			process.Terminate()
			killedMiners++
		}

		malwareResult := ScanForMalware(process)

		if malwareResult == "malicious" {
			process.Terminate()
			killedMalware++
		}

	}

	fmt.Println("Miners killed " + strconv.Itoa(killedMiners))
	fmt.Println("Malware killed " + strconv.Itoa(killedMalware))
}
