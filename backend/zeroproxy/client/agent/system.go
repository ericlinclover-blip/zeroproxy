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

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "zpcore: "+format+"\n", args...)
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

var reJSONString = regexp.MustCompile(`"([A-Za-z0-9_]+)"\s*:\s*"([^"]*)"`)

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
