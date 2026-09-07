// 检查独立构建边界，不引入运行时依赖。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("standalone boundaries: PASS")
}

func check() error {
	data, err := exec.Command("go", "mod", "edit", "-json").Output()
	if err != nil {
		return err
	}
	var module struct {
		Module  struct{ Path string }
		Replace []json.RawMessage
	}
	if err = json.Unmarshal(data, &module); err != nil {
		return err
	}
	if module.Module.Path != "github.com/ankye/dshker-server" || len(module.Replace) != 0 {
		return fmt.Errorf("module identity or replace violates standalone boundary")
	}
	if _, err = os.Stat("go.work"); !os.IsNotExist(err) {
		return fmt.Errorf("repository must not require its own go.work")
	}
	command := exec.Command("go", "list", "-mod=readonly", "-deps", "-json", "./cmd/dshker-server")
	command.Stderr = os.Stderr
	output, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err = command.Start(); err != nil {
		return err
	}
	decoder := json.NewDecoder(output)
	var violation error
	for {
		var dependency struct {
			ImportPath string
			Module     *struct {
				Path, Dir string
				Replace   *json.RawMessage
			}
		}
		err = decoder.Decode(&dependency)
		if err == io.EOF {
			break
		}
		if err != nil {
			violation = err
			break
		}
		path := strings.ToLower(dependency.ImportPath)
		if strings.Contains(path, "nethopper") || strings.Contains(path, "oneisland") || strings.HasPrefix(path, "github.com/nats-io/") || strings.HasPrefix(path, "github.com/airkits/") || strings.HasPrefix(path, "github.com/ankye/dshker/") || strings.Contains(path, "/mock") {
			violation = fmt.Errorf("forbidden production dependency: %s", dependency.ImportPath)
		}
		if dependency.Module != nil && dependency.Module.Replace != nil {
			violation = fmt.Errorf("replaced production dependency: %s", dependency.Module.Path)
		}
	}
	if err = command.Wait(); err != nil {
		return err
	}
	if violation != nil {
		return violation
	}
	return filepath.WalkDir(".", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "bin" || entry.Name() == "artifacts" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Count(string(data), "\n") > 1000 {
			return fmt.Errorf("source file exceeds 1000 lines: %s", path)
		}
		return nil
	})
}
