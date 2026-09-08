package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ankye/dshker-server/internal/coordinator"
	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		// 只输出错误码，避免配置、SQL 或命令参数中的秘密被记录。
		code := err.Error()
		if !strings.HasPrefix(code, "p2p.") || strings.ContainsAny(code, " \r\n") {
			code = "p2p.operation_failed"
		}
		fmt.Fprintln(os.Stderr, code)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("p2p.command_required")
	}
	action := args[0]
	switch action {
	case "serve", "init", "user-add", "user-disable":
	default:
		return errors.New("p2p.unknown_command")
	}
	flags := flag.NewFlagSet("dshker-server "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "显式 JSON 配置路径")
	username := flags.String("username", "", "创建账号的邮箱")
	userID := flags.String("user-id", "", "禁用的用户 ID")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("p2p.invalid_arguments")
	}
	if *path == "" {
		return errors.New("p2p.config_required")
	}
	if action != "user-add" && *username != "" || action != "user-disable" && *userID != "" {
		return errors.New("p2p.invalid_arguments")
	}
	config, err := coordinator.ReadConfig(*path)
	if err != nil {
		return err
	}
	if action == "init" {
		if err = coordinator.Initialize(config.DatabasePath, config.IdentityKeyPath, time.Now()); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]bool{"initialized": true})
	}
	store, err := coordinator.OpenStore(config.DatabasePath, config.IdentityKeyPath)
	if err != nil {
		return err
	}
	defer store.Close()
	switch action {
	case "serve":
		server, err := coordinator.NewServer(config, store)
		if err != nil {
			return err
		}
		return server.Run(ctx)
	case "user-add":
		if *username == "" {
			return errors.New("p2p.username_required")
		}
		// 密码只从 stdin 读取，单行最多 72 字节，不提供 argv/env 密码入口。
		data, err := io.ReadAll(io.LimitReader(input, 75))
		if err != nil {
			return err
		}
		password := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if strings.ContainsAny(password, "\r\n") || len(password) > 72 {
			return errors.New("p2p.invalid_user_credentials")
		}
		user, err := store.CreateUser(*username, password)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(user)
	case "user-disable":
		if *userID == "" {
			return errors.New("p2p.user_id_required")
		}
		if err = store.DisableUser(*userID, time.Now()); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]bool{"disabled": true})
	}
	return errors.New("p2p.unknown_command")
}
