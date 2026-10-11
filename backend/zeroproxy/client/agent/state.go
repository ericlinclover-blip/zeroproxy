package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// 状态: "这台路由器现在是什么样的" 的唯一生产者。
//
// 以前这份状态被四处各拼一遍 —— 安装脚本、agent 心跳、运维 CLI (status / doctor)、本地
// 界面。它们各自去 sed-grep caps 文件、各自探一遍现场, 靠注释里的"必须一致"维持。真机上
// 它漂过: 性能模式 (eBPF / dae) 下 mihomo 是停的, 而 CLI 只看 zp-tun / nft / iptables,
// 于是报"未生效", 家里却正由 dae 分流 (8.88)。
//
// 现在只有这一处: 一处解析 caps、一处探现场、一处算覆盖。shell (live.sh / agent.sh / CLI)
// 用 `zpcore state` 拿一份 key=value, 本地界面用同一个 snapshot 组装它的 JSON。zpcore 不在
// 的机器上, shell 退回它自己那份等价的判据 (它仍然是可选件)。
// ---------------------------------------------------------------------------

// capsData 是 /etc/zeroproxy/caps (扁平 key=value) 的只读视图。
type capsData struct{ kv map[string]string }

func capsFrom(dir string) capsData {
	kv := map[string]string{}
	if data, err := os.ReadFile(filepath.Join(dir, "caps")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '='); i > 0 {
				kv[line[:i]] = line[i+1:]
			}
		}
	}
	return capsData{kv: kv}
}

func (c capsData) get(key string) string { return c.kv[key] }

// snapshot 是这台机器现在的一份完整快照。**现场 (live) 与能力 (caps) 分开**: 面板上的
// 「模式」取现场, 「该渲染哪份配置」取能力 (caps.chosen), 两者不该混在一起。
type snapshot struct {
	Dir     string
	Version string
	Core    string // running / stopped (问 init, 不是问我们下过什么命令)
	Mode    string // 现场: dae / tun / tproxy / redirect / none
	Covered string // 现场覆盖: full / lan / lan_tcp / none
	Chosen  string // 能力: caps 里那一档 (意图)
	CapsCov string
	Why     string // 一级都没接管时, 每一级为什么不行 (内核原话)
	Caps    capsData
	Packets int
	WAN     int64
	Perf    perfResp
	Servers []serverEntry
}

func snapshotAt(cfg commonConfig) snapshot {
	dir := cfg.dir
	caps := capsFrom(dir)
	mode, covered := liveMode(cfg.initd)
	why := ""
	if mode == "none" {
		// 一级都没接管时把**每一级为什么不行**都带上: 只报"选中的那一级"会漏掉关键信息。
		var parts []string
		for _, level := range []string{"tun", "tproxy", "redirect"} {
			if v := caps.get("why." + level); v != "" {
				parts = append(parts, level+": "+v)
			}
		}
		why = strings.Join(parts, " · ")
	}
	core := "stopped"
	if initRunning(cfg.initd) {
		core = "running"
	}
	return snapshot{
		Dir:     dir,
		Version: readTrimmed(filepath.Join(dir, "version")),
		Core:    core,
		Mode:    mode,
		Covered: covered,
		Chosen:  caps.get("chosen"),
		CapsCov: caps.get("covered"),
		Why:     why,
		Caps:    caps,
		Packets: datapathPackets(mode),
		WAN:     wanBytes(),
		Perf:    currentPerf(dir, cfg.initd),
		Servers: readServers(dir),
	}
}

// initRunning 问内核的服务在不在跑 —— 与 CLI 的 running() / agent 的 core_up 同一条判据。
func initRunning(initd string) bool {
	return ok(probeTimeout, initd, "running")
}

// ---------------------------------------------------------------------------
// 输出: shell 用 key=value (就当是 caps 再读一次), 人/CI 用 --json。
// ---------------------------------------------------------------------------

// shellLines 保持 caps 那套键 (chosen / ipv6 / tun_mtu / why.* / …), 再补上现场量
// (mode / covered / core / packets / wan) —— shell 侧**不需要知道**这些是算出来的。
func (s snapshot) shellLines() string {
	var b strings.Builder
	keys := make([]string, 0, len(s.Caps.kv))
	for k := range s.Caps.kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, s.Caps.kv[k])
	}
	fmt.Fprintf(&b, "mode=%s\n", s.Mode)
	fmt.Fprintf(&b, "covered=%s\n", s.Covered)
	fmt.Fprintf(&b, "core=%s\n", s.Core)
	fmt.Fprintf(&b, "packets=%d\n", s.Packets)
	fmt.Fprintf(&b, "wan=%d\n", s.WAN)
	fmt.Fprintf(&b, "client=%s\n", s.Version)
	fmt.Fprintf(&b, "perf_live=%s\n", s.Perf.Live)
	fmt.Fprintf(&b, "perf_busy=%s\n", s.Perf.Busy)
	return b.String()
}

type snapshotJSON struct {
	Version      string            `json:"version"`
	Core         string            `json:"core"`
	Mode         string            `json:"mode"`
	Covered      string            `json:"covered"`
	Chosen       string            `json:"chosen"`
	CapsCovered  string            `json:"caps_covered"`
	Why          string            `json:"why"`
	IPv6         string            `json:"ipv6"`
	MTU          string            `json:"tun_mtu"`
	Offload      string            `json:"offload"`
	Autoredirect string            `json:"autoredirect"`
	Packets      int               `json:"packets"`
	WAN          int64             `json:"wan"`
	Perf         perfResp          `json:"perf"`
	Caps         map[string]string `json:"caps"`
	Servers      []serverEntry     `json:"servers"`
}

func (s snapshot) toJSON() snapshotJSON {
	return snapshotJSON{
		Version:      s.Version,
		Core:         s.Core,
		Mode:         s.Mode,
		Covered:      s.Covered,
		Chosen:       s.Chosen,
		CapsCovered:  s.CapsCov,
		Why:          s.Why,
		IPv6:         s.Caps.get("ipv6"),
		MTU:          s.Caps.get("tun_mtu"),
		Offload:      s.Caps.get("offload"),
		Autoredirect: s.Caps.get("autoredirect"),
		Packets:      s.Packets,
		WAN:          s.WAN,
		Perf:         s.Perf,
		Caps:         s.Caps.kv,
		Servers:      s.Servers,
	}
}

func printState(cfg commonConfig, asJSON bool) error {
	s := snapshotAt(cfg)
	if !asJSON {
		fmt.Print(s.shellLines())
		return nil
	}
	blob, err := json.MarshalIndent(s.toJSON(), "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(blob))
	return nil
}
