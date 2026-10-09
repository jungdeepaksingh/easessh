package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// ImportSSHConfig reads concrete (non-wildcard) Host entries from an OpenSSH config file.
// Like ssh, the first value seen for each setting wins, and a host named in several
// Host blocks collects settings from all of them.
func ImportSSHConfig(path string) ([]Host, error) {
	f, err := os.Open(ExpandPath(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []Host
	byName := map[string]int{}
	portSet := map[int]bool{}
	var cur []int // indices into hosts affected by the current Host block
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitDirective(line)
		if !ok {
			continue
		}
		val = strings.Trim(val, `"`)
		switch strings.ToLower(key) {
		case "host":
			cur = cur[:0]
			for _, pat := range strings.Fields(val) {
				if strings.ContainsAny(pat, "*?!") {
					continue
				}
				i, seen := byName[pat]
				if !seen {
					hosts = append(hosts, Host{Name: pat, Port: 22, Auth: AuthAgent})
					i = len(hosts) - 1
					byName[pat] = i
				}
				cur = append(cur, i)
			}
		case "match":
			cur = cur[:0]
		case "hostname":
			for _, i := range cur {
				if hosts[i].Host == "" {
					hosts[i].Host = expandTokens(val, hosts[i].Name)
				}
			}
		case "user":
			for _, i := range cur {
				if hosts[i].User == "" {
					hosts[i].User = val
				}
			}
		case "port":
			if p, err := strconv.Atoi(val); err == nil {
				for _, i := range cur {
					if !portSet[i] {
						hosts[i].Port, portSet[i] = p, true
					}
				}
			}
		case "identityfile":
			for _, i := range cur {
				if hosts[i].KeyPath == "" {
					hosts[i].KeyPath = expandTokens(val, hosts[i].Name)
					hosts[i].Auth = AuthKey
				}
			}
		}
	}
	for i := range hosts {
		if hosts[i].Host == "" {
			hosts[i].Host = hosts[i].Name
		}
	}
	return hosts, sc.Err()
}

// expandTokens handles the ssh_config tokens that make sense outside a live connection.
func expandTokens(s, host string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	return strings.NewReplacer("%%", "%", "%h", host, "%n", host, "%d", "~", "%u", user).Replace(s)
}

// splitDirective splits "Key value" or "Key=value".
func splitDirective(line string) (string, string, bool) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return "", "", false
	}
	key := line[:i]
	val := strings.TrimLeft(line[i:], " \t")
	val = strings.TrimSpace(strings.TrimPrefix(val, "="))
	return key, val, val != ""
}
