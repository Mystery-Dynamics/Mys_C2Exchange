package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
)

type CommandOption struct {
	Command, Description string
	Function             func(db *sql.DB, prompt []string, args ...string) error
}

type MenuOptions struct {
	db     *sql.DB
	Prompt []string
}

type Menu struct {
	Commands []CommandOption
	Options  MenuOptions
}

func NewMenuOptions(prompt []string, db *sql.DB) MenuOptions {
	return MenuOptions{db, prompt}
}

// Creates a new menu with options
func NewMenu(cmds []CommandOption, options MenuOptions) *Menu {
	if len(options.Prompt) == 0 {
		options.Prompt = []string{"root>"}
	}
	return &Menu{cmds, options}
}

func (m *Menu) prompt() {
	fmt.Print("[", strings.Join(m.Options.Prompt, ">"), "]", "$ ")
}

func (m *Menu) help() {
	for i := range m.Commands {
		fmt.Printf("*%s\t%s\n", m.Commands[i].Command, m.Commands[i].Description)
	}
}

func (m *Menu) Start() {
	m.start(os.Stdin)
}

func (m *Menu) SetMenuPrompt(prompt []string) {
	m.Options.Prompt = prompt
}

func (m *Menu) start(reader io.Reader) {
MainLoop:
	for {
		input := bufio.NewReader(reader)
		m.prompt()

		inputString, err := input.ReadString('\n')
		if err != nil {
			break MainLoop
		}

		cmd := strings.Split(strings.Trim(inputString, " \r\n"), " ")
		if len(cmd) < 1 {
			break MainLoop
		}
	Route:
		switch cmd[0] {
		case "exit", "quit":
			fmt.Println("Exiting...")
			os.Exit(0)
		case "back":
			break MainLoop
		case "help":
			m.help()
			break

		default:
			for i := range m.Commands {
				if m.Commands[i].Command == cmd[0] {
					err := m.Commands[i].Function(m.Options.db, m.Options.Prompt, cmd[1:]...)
					if err != nil {
						panic(err)
					}

					break Route
				}
			}
			fmt.Println("Unknown command")
		}
	}
}
