package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	// A simple, fast, and fun package for building command line apps in Go
	"github.com/urfave/cli/v2"

	// Package ssh implements an SSH client and server
	"golang.org/x/crypto/ssh"
)

type Project struct {
	Name     string
	Info     string
	FullPath string
	Host     string
	Port     string

	// 密码和用户名只允许覆盖，不允许查看
	UserName string
	Password string
}

type ProjectList struct {
	Projects []Project
}

var PList ProjectList

func main() {

	content := readConfig()

	if len(content) != 0 {
		// 获取配置 JSON 内容
		PList = getProjectJson(content)
	} else {
		// 初始化加密
		initProjectJson()
	}

	app := &cli.App{
		// 项目名
		Name: "OPS-TOOL",

		// 便捷说明，跟在 Name 后面显示
		Usage: "便捷部署工具 @半醒的狐狸",

		// 专门显示在 Usage 的位置
		// TODO:这里的显示从远程获取
		UsageText: "1、使用前请确保本地与服务器都安装了 SSH \n   " +
			"2、基于服务器上基于 git 部署，请确保装了 git\n   " +
			"3、可以通过 `ops-tool help` 来获取帮助 \n   " +
			"4、更多内容请访问：www.goenv.cn",

		Action: func(c *cli.Context) error {
			fmt.Println("可以通过运行 `ops-tool help` 来获取使用指南")
			return nil
		},

		Commands: []*cli.Command{
			{
				Name:  "publish",
				Usage: "部署指定项目",
				UsageText: "将根据配置进入该项目的服务器与目录下，进行 pull 操作，所以请确保该远端项目已经绑定了 git 仓库 \n   " +
					"使用方法 ops-tool publish [项目编号] [分支名]",
				Action: publish,
			},
			{
				Name:      "list",
				Usage:     "查看现有项目列表",
				UsageText: "直接运行 ops-tool list 就能看到当前支持的项目列表",
				Action:    list,
			},
			{
				Name:  "add",
				Usage: "添加项目到配置",
				UsageText: "ops-tool add [项目名] [项目描述] [项目绝对路径] [Host] [Port] [Username] [Password]\n   " +
					"注意：password 一旦添加，再不可查看，如果想要更改项目配置，请先删除该项目",
				Action: addProject,
			},
			{
				Name:      "rm",
				Usage:     "删除项目",
				UsageText: "ops-tool rm [项目编号]",
				Action:    rmProject,
			},

			// 重置 help 命令
			{
				Name:  "help",
				Usage: "ops-tool help ，也可以通过 ops-tool [命令] -h 来查看具体命令的指南",
				Action: func(c *cli.Context) error {
					args := c.Args()
					if args.Present() {
						return cli.ShowCommandHelp(c, args.First())
					}
					_ = cli.ShowAppHelp(c)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// 读取配置
func readConfig() (content []byte) {
	// 读取项目配置
	f, _ := os.OpenFile("./conf/p.ob", os.O_RDWR|os.O_CREATE, 0755)
	fInfo, _ := f.Stat()
	content = make([]byte, fInfo.Size())
	f.Read(content)
	defer f.Close()
	return
}

// 写入配置
func writeConfig(c []byte) error {
	// os.O_TRUNC 覆盖写
	f, _ := os.OpenFile("./conf/p.ob", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	_, err := f.Write(c)
	defer f.Close()
	return err
}

// 加密 key
// 16 字节 - AES-128
// 24 字节 - AES-192
// 32 字节 - AES-256
var k = "www.goenv.cn.net"

// 初始向量，加密和解密时的向量长度必须一致
var iv = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

// 解密配置文件并解析到结构体
func getProjectJson(content []byte) (pList ProjectList) {
	// 如果出现 err ，直接 panic ，无法解析配置值，则项目已经无法运行

	// 创建加解密算法
	ci, err := aes.NewCipher([]byte(k))
	if err != nil {
		fmt.Printf("Error: NewCipher(%d bytes)\n", len(k))
		panic(err)
	}

	// 解密
	cfbdec := cipher.NewCFBDecrypter(ci, iv)
	contentJson := make([]byte, len(content))
	cfbdec.XORKeyStream(contentJson, content) // 将 content 解密后的内容放到 contentJson

	// json 串解析到 ProjectList
	err = json.Unmarshal([]byte(contentJson), &pList)
	if err != nil {
		fmt.Println(string(contentJson))
		fmt.Println(err)
		panic("格式转换出错，无法继续运行")
	}

	return
}

// 初始化配置文件
func initProjectJson() {
	PList.Projects = append(PList.Projects, Project{
		"Demo",
		"this is an init project",
		"/www/wwwroot/www.goenv.cn",
		"127.0.0.1",
		"22",
		"root",
		"root",
	})

	s, err0 := encrypPlist()
	if err0 != nil {
		panic(err0)
	}

	err1 := writeConfig(s)
	if err1 != nil {
		panic("初始化配置写入文件失败")
	}
}

// 对数据进行加密
func encrypPlist() (s []byte, err error) {
	// 组织成 json 串
	b, err0 := json.Marshal(PList)
	if err0 != nil {
		return nil, err0
	}

	// 创建加解密算法
	ci, err1 := aes.NewCipher([]byte(k))
	if err1 != nil {
		return nil, err1
	}

	// 加密
	cfb := cipher.NewCFBEncrypter(ci, iv)
	s = make([]byte, len(b))
	cfb.XORKeyStream(s, b)

	return
}

// 连接服务器
func connect(user, password, host string, port int) (*ssh.Session, error) {
	var (
		auth    []ssh.AuthMethod
		addr    string
		client  *ssh.Client
		session *ssh.Session
		err     error
	)

	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	// connect to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	client, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},

		// 需要验证服务端，不做验证返回 nil 就可以，点击 HostKeyCallback 看源码就知道了
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	})

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}

// ... 以下都为工具命令

// 项目列表
func list(c *cli.Context) error {
	for k, item := range PList.Projects {
		fmt.Println("=============")
		fmt.Printf(" 编号：%d \n 项目名：%s \n 项目说明：%s \n 绝对路径：%s \n", k, item.Name, item.Info, item.FullPath)
	}
	return nil
}

// 发布
func publish(c *cli.Context) error {
	pId := c.Args().Get(0)
	branch := c.Args().Get(1)
	if pId == "" || branch == "" {
		return errors.New("参数不正确")
	}

	// 检查项目是否存在
	// 不能用 len 来判断，万一输入的是浮点数，很容易出问题
	pIdInt, _ := strconv.Atoi(pId)
	flag := 0
	for k, _ := range PList.Projects {
		if k == pIdInt {
			flag = 1
			break
		}
	}
	if flag == 0 {
		return errors.New("不存在这个项目，请使用 `projects` 命令查看可部署的项目")
	}

	// 建立会话
	p := PList.Projects[pIdInt]
	port, _ := strconv.Atoi(PList.Projects[pIdInt].Port)
	session, err := connect(p.UserName, p.Password, p.Host, port)
	if err != nil {
		return err
	}

	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	// 服务器上的项目，永远都是从仓库拉，不会自己产生 commit，所以永远不会冲突
	err = session.Run("cd " + p.FullPath + " && git pull origin " + branch)

	if err != nil {
		return err
	}

	return nil
}

// 添加项目
func addProject(c *cli.Context) error {
	// 参数校验
	name := c.Args().Get(0)
	info := c.Args().Get(1)
	fullPath := c.Args().Get(2)
	host := c.Args().Get(3)
	port := c.Args().Get(4)
	username := c.Args().Get(5)
	password := c.Args().Get(6)

	if name == "" || info == "" || fullPath == "" || host == "" || port == "" || username == "" || password == "" {
		return errors.New("参数错误")
	}

	portInt, _ := strconv.Atoi(port)
	if portInt < 20 || portInt > 65535 {
		return errors.New("端口号错误")
	}

	// 数据添加
	PList.Projects = append(PList.Projects, Project{
		name,
		info,
		fullPath,
		host,
		port,
		username,
		password,
	})

	// 加密
	s, err := encrypPlist()
	if err != nil {
		return err
	}

	// 持久化
	err0 := writeConfig(s)
	if err0 != nil {
		return err0
	}

	return nil
}

// 删除项目
func rmProject(c *cli.Context) error {
	id := c.Args().Get(0)
	if id == "" {
		return errors.New("参数错误")
	}

	idInt, _ := strconv.Atoi(id)
	PList.Projects = append(PList.Projects[:idInt], PList.Projects[idInt+1:]...)

	//fmt.Println(PList.Projects)
	//return nil

	// 加密
	s, err := encrypPlist()
	if err != nil {
		return err
	}

	// 持久化
	err0 := writeConfig(s)
	if err0 != nil {
		return err0
	}

	return nil
}
