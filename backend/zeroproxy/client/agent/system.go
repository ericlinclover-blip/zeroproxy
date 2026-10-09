package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// : 单条外部命令的上限。状态类命令必须"问不出来就快速放弃" —— 界面卡住比报错更难查。
const probeTimeout = 5 * time.Second

// : 手动动作 (add / drop / refresh) 会真的去拉配置、重建、重启内核, 给足时间。
const actionTimeout = 90 * time.Second

// run 执行一条命令并返回 (stdout+stderr, 是否成功)。用 context 而不是自己起 goroutine:
// 到点连子进程一起收掉, 不会留下一个卡住的 procd 子进程。
func run(timeout time.Duration, name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err == nil
}

func ok(timeout time.Duration, name string, args ...string) bool {
	_, good := run(timeout, name, args...)
	return good
}

// logf 走 **stdout** 而不是 stderr: procd 把 stderr 记成 `daemon.err`, 于是每次重启
// 日志里都躺一条看着像错误的东西 (真机上就是这样: `daemon.err zpcore[…]`), 日子久了对
// 真正的错误就麻木了。stdout 记成 user.notice, 是"说一句话"的正确档位。
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "zpcore: "+format+"\n", args...)
}

// discoverLANIP 找本机的局域网地址。三处用它 (绑定 / 界面地址), 而**不能**拿它当
// "随便一个本机地址": 绑错就起不来, 绑成 0.0.0.0 等于把管理界面挂到 WAN 上。
// 先问 uci (权威), 再从接口地址里取第一个非回环 IPv4。
func discoverLANIP() string {
	if out, good := run(probeTimeout, "uci", "-q", "get", "network.lan.ipaddr"); good {
		if ip := trimSpace(out); isIPv4(ip) {
			return ip
		}
	}
	out, good := run(probeTimeout, "ip", "-4", "addr", "show")
	if !good {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "inet" {
				continue
			}
			ip := strings.Split(fields[i+1], "/")[0]
			if isIPv4(ip) && !strings.HasPrefix(ip, "127.") {
				return ip
			}
		}
	}
	return ""
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return true
}

func isLANIP(ip string) bool {
	if !isIPv4(ip) {
		return false
	}
	parts := strings.Split(ip, ".")
	a, _ := strconv.Atoi(parts[0])
	b, _ := strconv.Atoi(parts[1])
	switch {
	case a == 10:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	case a == 127:
		return true // 本机调试用; 见 serve() 里的说明
	}
	return false
}

// liveMode 判断内核**现在**接管到哪 —— 看现场 (设备/表在不在), 不看 caps 里的意图。
// 与安装脚本的 datapath_live / agent.sh 的 actual_covered 是同一条判据, 三处必须一致,
// 否则面板、路由界面、CLI 会各说各话。
func liveMode() (mode string, covered string) {
	// 性能模式排第一: 它开着的时候 mihomo 是停的 (下面几条都不会命中), 但顺序上先说清楚 ——
	// "谁在接管"是界面上最该回答的问题。判据同样是现场: dae 进程在不在。
	if daeRunning() {
		return "ebpf", "full"
	}
	if ok(probeTimeout, "ip", "link", "show", "zp-tun") {
		return "tun", "full"
	}
	if ok(probeTimeout, "nft", "list", "table", "inet", "zp_router") {
		return "tproxy", "lan"
	}
	if ok(probeTimeout, "iptables", "-t", "nat", "-L", "zp_router") {
		return "redirect", "lan_tcp"
	}
	return "none", "none"
}

// daeRunning 判断性能模式的内核 (dae) 在不在 —— 直接翻 /proc, 不起进程。
// 为什么不用 pidof: 这个函数在每一次界面轮询里都会被走到 (表盘要按状态刷新), 而路由器上
// fork 是要花钱的; 读 /proc 一次就够, 而且对"进程名被截断"这类固件差异更稳。
func daeRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", name, "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == "dae" {
			return true
		}
	}
	return false
}

// wanBytes 是 WAN 口的收+发字节数。界面那块表盘的转速就是它算出来的 —— 真流量才有转速,
// 拿不到就是 0 (表针贴怠速), 绝不假装在动。
func wanBytes() int64 {
	dev := ""
	if out, good := run(probeTimeout, "sh", "-c",
		"ip route show default 2>/dev/null | awk 'NR==1{print $5}'"); good {
		dev = trimSpace(out)
	}
	if dev == "" {
		return 0
	}
	rx, _ := strconv.ParseInt(readTrimmed("/sys/class/net/"+dev+"/statistics/rx_bytes"), 10, 64)
	tx, _ := strconv.ParseInt(readTrimmed("/sys/class/net/"+dev+"/statistics/tx_bytes"), 10, 64)
	return rx + tx
}

// perfFile 读性能模式目录里的一个小文件 (state / why / exit_ip / progress)。读不到就是空 ——
// 界面据此显示"未开启", 而不是显示一个错的东西。
func perfFile(dir, name string) string {
	return readTrimmed(filepath.Join(dir, "perf", name))
}

// datapathPackets 是数据面上真的过了多少包 —— **规则存在 ≠ 有流量**。接口名写错时规则
// 照样"装得上", 却一个包都不命中; 这是唯一能证明"真的接管了"的现场证据。
// 与 CLI 的 datapath_packets 是同一条判据 (两处必须一致, 否则界面与命令行会各说各话)。
func datapathPackets(mode string) int {
	switch mode {
	case "tun":
		return atoi(readTrimmed("/sys/class/net/zp-tun/statistics/rx_packets"))
	case "tproxy":
		out, good := run(probeTimeout, "nft", "list", "table", "inet", "zp_router")
		if !good {
			return 0
		}
		total := 0
		for _, m := range reNFTCounter.FindAllStringSubmatch(out, -1) {
			total += atoi(m[1])
		}
		return total
	case "redirect":
		out, good := run(probeTimeout, "iptables", "-t", "nat", "-L", "zp_router", "-v", "-n")
		if !good {
			return 0
		}
		total := 0
		for i, line := range strings.Split(out, "\n") {
			if i < 2 { // 表头两行 (Chain xxx / 列名) 不算
				continue
			}
			fields := strings.Fields(line)
			if len(fields) > 0 {
				total += atoi(fields[0])
			}
		}
		return total
	}
	return 0
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// readCaps 读 /etc/zeroproxy/caps (一行一个 key=value)。本进程直接读文件 —— 不必为了
// 读一个自己目录里的文本再去 fork 一个 cat (路由器上 fork 是要花钱的)。
func readCaps(dir string) map[string]string {
	caps := map[string]string{}
	data, err := os.ReadFile(filepath.Join(dir, "caps"))
	if err != nil {
		return caps
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			caps[line[:i]] = line[i+1:]
		}
	}
	return caps
}

var (
	reJSONString = regexp.MustCompile(`"([A-Za-z0-9_]+)"\s*:\s*"([^"]*)"`)
	reNFTCounter = regexp.MustCompile(`counter packets ([0-9]+)`)
)

// readServers 读 servers/*.json。文件是扁平的字符串字段 (安装脚本与 CLI 自己写的),
// 所以这里只认 "键": "值" 这一种写法 —— 与 cgi / CLI 的极简解析保持一致, 不引 YAML。
func readServers(dir string) []serverEntry {
	entries, err := os.ReadDir(filepath.Join(dir, "servers"))
	if err != nil {
		return nil
	}
	var out []serverEntry
	for _, dirent := range entries {
		name := dirent.Name()
		if dirent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "servers", name))
		if err != nil {
			continue
		}
		// 文件名就是键 (安装脚本用 srv_key 把面板地址归一化成文件名) —— 不再归一化一次,
		// 免得两处规则哪天走偏。
		entry := serverEntry{Key: strings.TrimSuffix(name, ".json")}
		for _, m := range reJSONString.FindAllStringSubmatch(string(data), -1) {
			switch m[1] {
			case "base":
				entry.Base = m[2]
			case "id":
				entry.ID = m[2]
			}
		}
		if entry.Base != "" {
			out = append(out, entry)
		}
	}
	return out
}

// tailLines 取最后 n 行 (日志用; 日志可能上万行)。
func tailLines(text string, n int) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
