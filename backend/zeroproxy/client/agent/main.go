// zpcore —— ZeroProxy 路由器本地控制面。
//
// 为什么要有这个二进制
// --------------------
// 路由器管理界面原来的三条路都不牢靠, 而且是**三种不同的坏法** (真机各踩过一次):
//   - uhttpd (OpenWrt 默认): 文档根 /www + /cgi-bin/ 会执行脚本 —— 落盘即通;
//   - nginx + fcgiwrap (GL.iNet 部分固件): 也通, 但 /cgi-bin/ 那条 location 是 LuCI
//     带进来的, 固件没有 LuCI 时根本没有 (真机: 界面被当文本文件发出来);
//   - 原厂 nginx 没有 cgi: 退回自带的 busybox httpd —— 而 busybox 的 httpd 是**可选
//     applet**, 厂商精简固件里常常没编进去。
//
// 三者的共同点是"能不能打开界面"取决于**固件**, 而这件事用户改不了。zpcore 把这一段
// 收回自己手里: 一个静态二进制, 自己起 HTTP 服务、自己校验令牌、自己只绑局域网地址。
// 界面的内容它不管 —— 页面与数据接口的**契约与原来的 cgi 一模一样** (`/cgi-bin/zeroproxy`
// + `?a=status|add|drop|toggle|refresh|log` + `?file=app.js`), 所以那个页面一个字节都没改。
//
// 它**不做**的事 (刻意的): 不解析 YAML、不重建配置、不动数据面。那些是 agent.sh 与
// 安装脚本的活, 已经过了七次真机验证。zpcore 只是一层薄薄的前端: 读状态、转手动动作
// 给 CLI 执行。薄, 所以可审。
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// : 客户端版本 (与 router-install.sh 的 ZP_CLIENT_VERSION 对应; 面板按它决定发哪一版二进制)。
// : 单独一个常量是有意的: 二进制可以落后于脚本 (老机器上留着上一版), 只要接口不变就能跑。
const agentVersion = "1.0.0"

const usage = `zpcore —— ZeroProxy 路由器本地控制面

用法:
  zpcore serve [选项]      起本地管理界面 (只绑局域网地址)
  zpcore version           打印版本

serve 选项:
  --dir <路径>       运行目录 (默认 /etc/zeroproxy)
  --bind <地址>      监听地址 (默认自动找局域网 IP; 找不到就拒绝启动)
  --port <端口>      监听端口 (默认读 <dir>/ui.port, 再退回 8399)
  --cli <路径>       执行手动动作的 CLI (默认 /usr/bin/zeroproxy)
  --init <路径>      内核的 init 脚本 (默认 /etc/init.d/zeroproxy; 用它判断内核在不在跑)
  --allow-wan        允许绑非局域网地址 (默认**拒绝**: 管理界面不该挂到 WAN 上)
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "serve":
		cfg, err := parseServe(args)
		if err != nil {
			fmt.Fprintln(os.Stderr, "zpcore:", err)
			os.Exit(2)
		}
		if err := serve(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "zpcore: 启动失败:", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("zpcore %s\n", agentVersion)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "zpcore: 未知命令 %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

type serveConfig struct {
	dir      string
	bind     string
	port     int
	cli      string
	initd    string
	allowWAN bool
	token    string
}

func parseServe(args []string) (serveConfig, error) {
	cfg := serveConfig{
		dir:   "/etc/zeroproxy",
		port:  0,
		cli:   "/usr/bin/zeroproxy",
		initd: "/etc/init.d/zeroproxy",
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s 后面缺少参数", arg)
			}
			i++
			return args[i], nil
		}
		switch arg {
		case "--dir":
			v, err := next()
			if err != nil {
				return cfg, err
			}
			cfg.dir = v
		case "--bind":
			v, err := next()
			if err != nil {
				return cfg, err
			}
			cfg.bind = v
		case "--cli":
			v, err := next()
			if err != nil {
				return cfg, err
			}
			cfg.cli = v
		case "--init":
			v, err := next()
			if err != nil {
				return cfg, err
			}
			cfg.initd = v
		case "--port":
			v, err := next()
			if err != nil {
				return cfg, err
			}
			var p int
			if _, err := fmt.Sscanf(v, "%d", &p); err != nil || p <= 0 || p > 65535 {
				return cfg, fmt.Errorf("端口不合法: %q", v)
			}
			cfg.port = p
		case "--allow-wan":
			cfg.allowWAN = true
		default:
			return cfg, fmt.Errorf("不认识的选项: %q", arg)
		}
	}

	// 令牌是**必须**的: 没有它这个服务等于把"全屋代理开关"挂在局域网上给任何人点。
	// 令牌由安装脚本生成 (0600), 与走固件 Web 服务时用的是同一个文件 —— 两种界面路径
	// 共用一份凭据, 用户看到的地址形状也一样。
	tokenPath := filepath.Join(cfg.dir, "ui.token")
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return cfg, fmt.Errorf("读不到界面令牌 %s (重跑一次安装命令会重新生成)", tokenPath)
	}
	cfg.token = trimSpace(string(raw))
	if cfg.token == "" {
		return cfg, fmt.Errorf("界面令牌 %s 是空的", tokenPath)
	}

	if cfg.port == 0 {
		cfg.port = 0
		if raw, err := os.ReadFile(filepath.Join(cfg.dir, "ui.port")); err == nil {
			if _, err := fmt.Sscanf(trimSpace(string(raw)), "%d", &cfg.port); err != nil {
				cfg.port = 0
			}
		}
	}
	if cfg.port == 0 {
		cfg.port = 8399
	}
	if cfg.bind == "" {
		cfg.bind = discoverLANIP()
	}
	if cfg.bind == "" && !cfg.allowWAN {
		return cfg, fmt.Errorf("找不到局域网地址 —— 拒绝启动而不是改成 0.0.0.0 " +
			"(那等于把管理界面挂到 WAN 上; 确实需要就加 --allow-wan)")
	}
	return cfg, nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
