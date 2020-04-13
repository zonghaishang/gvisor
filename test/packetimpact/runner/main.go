// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The runner starts docker containers and networking for a packetimpact test.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	re "regexp"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/runsc/dockerutil"
)

type stringList []string

func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

var (
	dutPlatform       = flag.String("dut_platform", "", "either \"linux\" or \"netstack\"")
	posixServerBinary = flag.String("posix_server_binary", "", "path to the posix server binary")
	testbenchBinary   = flag.String("testbench_binary", "", "path to the testbench binary")
	tshark            = flag.Bool("tshark", false, "use more verbose tshark in logs instead of tcpdump")
	extraTestArgs     = stringList{}
	expectFailure     = flag.Bool("expect_failure", false, "expect that the test will fail when run")

	imageTag      = "gcr.io/gvisor-presubmit/packetimpact"
	testDevice    = "eth2"
	dutAddr       = net.IPv4(0, 0, 0, 10)
	testbenchAddr = net.IPv4(0, 0, 0, 20)
	ctrlPort      = strconv.Itoa(40000)
)

func main() {
	if err := runOne(); err != nil {
		log.Fatalf("FAIL: %s", err)
	}
}

func runOne() error {
	flag.Var(&extraTestArgs, "extra_test_arg", "extra arguments to pass to the testbench")
	flag.Parse()
	if *dutPlatform != "linux" && *dutPlatform != "netstack" {
		return fmt.Errorf("--dut_platform should be either linux or netstack")
	}
	if len(*posixServerBinary) == 0 {
		return fmt.Errorf("--posix_server_binary is missing")
	}
	if len(*testbenchBinary) == 0 {
		return fmt.Errorf("--testbench_binary is missing")
	}
	if *dutPlatform == "netstack" {
		if _, err := dockerutil.RuntimePath(); err != nil {
			return fmt.Errorf("--runtime is missing or invalid with --dut_platform=netstack")
		}
	}
	dockerutil.EnsureSupportedDockerVersion()

	// Create the networks needed for the test. One control network is needed for
	// the gRPC control packets and one test network on which to transmit the test
	// packets.
	ctrlNet := dockerutil.MakeDockerNetwork("ctrl_net")
	testNet := dockerutil.MakeDockerNetwork("test_net")
	for _, dn := range []*dockerutil.DockerNetwork{&ctrlNet, &testNet} {
		for err := createDockerNetwork(dn); err != nil; err = createDockerNetwork(dn) {
			// This can fail if another docker network claimed the same IP so we'll
			// just try again.
			time.Sleep(100 * time.Millisecond)
		}
		defer func(dn *dockerutil.DockerNetwork) {
			if err := dn.Cleanup(); err != nil {
				log.Printf("unable to cleanup %v: %s", dn, err)
			}
		}(dn)
	}

	// Pull the specially-made docker image that has all the utilities that
	// packetimpact needs.
	if err := dockerutil.Pull(imageTag); err != nil {
		return fmt.Errorf("unable to docker pull %s: %w", imageTag, err)
	}

	// Create the Docker container for the DUT.
	dut := dockerutil.MakeDocker("dut")
	if *dutPlatform == "linux" {
		dut.Runtime = ""
	}

	// Create the Docker container for the testbench.
	testbench := dockerutil.MakeDocker("testbench")
	testbench.Runtime = "" // The testbench always runs on Linux.

	// Connect each container to each network.
	for _, d := range []struct {
		dockerutil.Docker
		ipSuffix net.IP
	}{
		{dut, dutAddr},
		{testbench, testbenchAddr},
	} {
		// Create the container.
		if err := d.Docker.Create("--privileged", "--rm", "--stop-timeout", "60", "-it", imageTag); err != nil {
			return fmt.Errorf("unable to create %v: %w", d.Docker, err)
		}
		defer d.CleanUp()
		for _, dn := range []*dockerutil.DockerNetwork{&ctrlNet, &testNet} {
			ip := addressInSubnet(d.ipSuffix, *dn.Subnet)
			// Connect to the network with the specified IP address.
			if err := dn.Connect(d.Docker, "--ip", ip.String()); err != nil {
				return fmt.Errorf("unable to connect %v to network %v: %w", d.Docker, dn, err)
			}
		}
		if err := d.Docker.Start(); err != nil {
			return fmt.Errorf("unable to start %v: %w", d.Docker, err)
		}
	}

	containerPosixServerBinary := "/" + path.Base(*posixServerBinary)
	if err := dut.CpTo(*posixServerBinary, containerPosixServerBinary, "-L"); err != nil {
		return fmt.Errorf("unable to docker cp %s to %s: %w", *posixServerBinary, containerPosixServerBinary, err)
	}

	ip := addressInSubnet(dutAddr, *ctrlNet.Subnet)
	_, ptmx, err := execToStdio("Server listening.*\n", &dut, containerPosixServerBinary, "--ip="+ip.String(), "--port="+ctrlPort)
	if err != nil {
		return fmt.Errorf("unable to exec %s on %v: %w", containerPosixServerBinary, dut, err)
	}
	defer func(ptmx *os.File) {
		if err := ptmx.Close(); err != nil {
			log.Printf("unable to close %v: %s", ptmx, err)
		}
	}(ptmx)

	// Because the Linux kernel receives the SYN-ACK but didn't send the SYN it
	// will issue a RST. To prevent this IPtables can be used to filter out all
	// incoming packets. The raw socket that packetimpact tests use will still see
	// everything.
	if _, err := testbench.Exec("iptables", "-A", "INPUT", "-i", testDevice, "-j", "DROP"); err != nil {
		return fmt.Errorf("unable to Exec iptables on %v: %w", testbench, err)
	}

	remoteMAC, err := macAddress(&dut, testDevice)
	if err != nil {
		return fmt.Errorf("unable to macAddress of %s on %v: %w", testDevice, dut, err)
	}
	localMAC, err := macAddress(&testbench, testDevice)
	if err != nil {
		return fmt.Errorf("unable to macAddress of %s on %v: %w", testDevice, testbench, err)
	}

	containerTestbenchBinary := "/" + path.Base(*testbenchBinary)
	if err := testbench.CpTo(*testbenchBinary, containerTestbenchBinary, "-L"); err != nil {
		return fmt.Errorf("unable to copy %s to %s: %w", *testbenchBinary, containerTestbenchBinary, err)
	}

	// Run tcpdump in the test bench unbuffered, without dns resolution, just on
	// the interface with the test packets.
	snifferArgs := []string{"tcpdump", "-S", "-vvv", "-U", "-n", "-i", testDevice, "net", testNet.Subnet.String()}
	snifferRegex := "tcpdump: listening.*\n"
	if *tshark {
		// Run tshark in the test bench unbuffered, without dns resolution, just on
		// the interface with the test packets.udp_recv_multicast_linux_test
		snifferArgs = []string{"tshark", "-V", "-l", "-n", "-i", testDevice,
			"-o", "tcp.check_checksum:TRUE",
			"-o", "udp.check_checksum:TRUE",
			"net", testNet.Subnet.String()}
		snifferRegex = "Capturing on.*\n"
	}
	_, ptmx, err = execToStdio(snifferRegex, &testbench, snifferArgs...)
	if err != nil {
		return fmt.Errorf("unable to run tshark on %v: %w", testbench, err)
	}
	defer func(ptmx *os.File) {
		if err := ptmx.Close(); err != nil {
			log.Printf("unable to close %v: %s", ptmx, err)
		}
	}(ptmx)
	// Kill so that it will flush output.
	defer testbench.Exec("killall", snifferArgs[0])

	// Start a packetimpact test on the test bench. The packetimpact test sends
	// and receives packets and also sends POSIX socket commands to the
	// posix_server to be executed on the DUT.
	testArgs := []string{containerTestbenchBinary}
	testArgs = append(testArgs, extraTestArgs...)
	testArgs = append(testArgs,
		"--posix_server_ip", addressInSubnet(dutAddr, *ctrlNet.Subnet).String(),
		"--posix_server_port", ctrlPort,
		"--remote_ipv4", addressInSubnet(dutAddr, *testNet.Subnet).String(),
		"--local_ipv4", addressInSubnet(testbenchAddr, *testNet.Subnet).String(),
		"--remote_mac", remoteMAC.String(),
		"--local_mac", localMAC.String(),
		"--device", testDevice,
	)
	cmd, ptmx, err := execToStdio("", &testbench, testArgs...)
	if err != nil {
		return fmt.Errorf("unable to exec %s on %v: %w", testArgs, testbench, err)
	}
	defer func(ptmx *os.File) {
		if err := ptmx.Close(); err != nil {
			log.Printf("unable to close %v: %s", ptmx, err)
		}
	}(ptmx)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("unable to wait for %v: %w", cmd, err)
	}
	if !*expectFailure && !cmd.ProcessState.Success() {
		return fmt.Errorf("test failed with exit code %d", cmd.ProcessState.ExitCode())
	}
	if *expectFailure && cmd.ProcessState.Success() {
		return fmt.Errorf("test failure expected but the test succeeded")
	}
	return nil
}

// addressInSubnet combines the subnet provided with the address and returns a
// new address. The return address bits come from the subnet where the mask is 1
// and from the ip address where the mask is 0.
func addressInSubnet(addr net.IP, subnet net.IPNet) net.IP {
	var octets []byte
	for i := 0; i < 4; i++ {
		octets = append(octets, (subnet.IP.To4()[i]&subnet.Mask[i])+(addr.To4()[i]&(^subnet.Mask[i])))
	}
	return net.IP(octets)
}

// makeDockerNetwork makes a randomly-named network that will start with the
// namePrefix. The network will be a random /24 subnet.
func createDockerNetwork(n *dockerutil.DockerNetwork) error {
	randSource := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(randSource)
	// Class C, 192.0.0.0 to 223.255.255.255, transitionally has mask 24.
	ip := net.IPv4(byte(r1.Intn(224-192)+192), byte(r1.Intn(256)), byte(r1.Intn(256)), 0)
	n.Subnet = &net.IPNet{
		IP:   ip,
		Mask: ip.DefaultMask(),
	}
	return n.Create()
}

// execToStdio runs a docker command on a container in the background, streaming
// the output to os.Stdout. It returns as soon as the output matches the regex
// provided and will continue to stream to os.Stdout.
func execToStdio(regex string, d *dockerutil.Docker, args ...string) (*exec.Cmd, *os.File, error) {
	cmd, ptmx, err := d.ExecWithPty(args...)
	if err != nil {
		return nil, nil, err
	}
	var bb bytes.Buffer
	var b [1]byte
	for {
		if _, err := ptmx.Read(b[:]); err != nil {
			return nil, nil, err
		}
		if _, err := bb.Write(b[:]); err != nil {
			return nil, nil, err
		}
		if _, err := os.Stdout.Write(b[:]); err != nil {
			return nil, nil, err
		}
		found, err := re.Match(regex, bb.Bytes())
		if err != nil {
			return nil, nil, err
		}
		if found {
			break
		}
	}
	go func(ptmx *os.File) {
		if _, err := io.Copy(os.Stdout, ptmx); err != nil {
			log.Printf("io.Copy failed: %s", err)
		}
		if err := ptmx.Close(); err != nil {
			log.Printf("unable to close %v: %s", ptmx, err)
		}
	}(ptmx)
	return cmd, ptmx, nil
}

// macAddress returns the MAC address of the provided device in the provided
// container.
func macAddress(d *dockerutil.Docker, dev string) (net.HardwareAddr, error) {
	// Get the MAC addresses of the devices.
	mac, err := d.Exec("ip", "link", "show", dev)
	if err != nil {
		return nil, err
	}
	mac = strings.TrimSpace(mac)
	lines := strings.Split(mac, "\n")
	lastLine := lines[len(lines)-1]
	return net.ParseMAC(strings.Split(lastLine, " ")[5])
}
