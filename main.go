package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/vultr/govultr/v2"
	"golang.org/x/oauth2"
)

type DnsEntry struct {
	Name      string
	ShortName string
	Address   string
	Device    string
}

var output string
var target string
var dnscache string
var short string
var debug bool
var server bool
var client string
var listen string
var vultrdns string
var syncInterval time.Duration

func main() {

	flag.StringVar(&output, "output", "hosts", "Output style, hosts, unbound-control")
	flag.StringVar(&short, "short", "no", "Omit short format ie just the part without the domain")
	flag.StringVar(&dnscache, "dnscache", "./.dnscache", "The dns cache file location - used for unbound diff")
	flag.StringVar(&target, "target", "/etc/hosts", "server or file target depending on context")
	flag.BoolVar(&debug, "debug", false, "Debug Flag")
	flag.BoolVar(&server, "server", false, "Run as an HTTP server and sync Vultr DNS entries")
	flag.StringVar(&client, "client", "", "Server host or URL to pull entries from")
	flag.StringVar(&listen, "listen", ":8080", "HTTP listen address for server mode")
	flag.StringVar(&vultrdns, "vultrdns", "./.vultrdns", "Server mode cache file location")
	flag.DurationVar(&syncInterval, "interval", 5*time.Minute, "Server mode Vultr sync interval")
	flag.Parse()

	ConfigSetup()
	ApplyConfig()

	log.Println("Starting Up")

	if viper.GetBool("debug") || debug == true {

		log.SetFlags(log.LstdFlags | log.Lshortfile)

	}

	if syncInterval <= 0 {
		syncInterval = 5 * time.Minute
	}

	log.Printf("Output Mode: %s\n", output)

	if client != "" {
		if err := RunClient(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if server {
		RunServer()
		return
	}

	entries, err := MakeRequest()

	if err != nil {
		log.Fatal(err)
	}

	OutputEntries(entries)

}

func ConfigSetup() {
	viper.SetConfigType("json")
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/vultrunbound/")
	if home, err := os.UserHomeDir(); err == nil {
		viper.AddConfigPath(home + "/.vultrunbound")
	}
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err == nil {
		return
	}

	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		return
	}

	panic(fmt.Errorf("Fatal error config file: %s \n", err))
}

func ApplyConfig() {
	setStringFromConfig("output", &output)
	setStringFromConfig("short", &short)
	setStringFromConfig("dnscache", &dnscache)
	setStringFromConfig("target", &target)
	setStringFromConfig("client", &client)
	setStringFromConfig("listen", &listen)
	setStringFromConfig("vultrdns", &vultrdns)

	if !flagPassed("debug") && viper.IsSet("debug") {
		debug = viper.GetBool("debug")
	}

	if !flagPassed("server") && viper.IsSet("server") {
		server = viper.GetBool("server")
	}

	if !flagPassed("interval") && viper.IsSet("interval") {
		syncInterval = viper.GetDuration("interval")
	}
}

func setStringFromConfig(name string, target *string) {
	if !flagPassed(name) && viper.IsSet(name) {
		*target = viper.GetString(name)
	}
}

func flagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

//* This method overwrites whatever is existing in hosts */

func OutputHosts(entries []DnsEntry) {
	err := WriteHosts(FormatHosts(entries, short))

	if err != nil {
		log.Fatal(err)
	}
}

func WriteHosts(hosts string) error {
	return ioutil.WriteFile(target, []byte(hosts), 0644)
}

func FormatHosts(entries []DnsEntry, shortMode string) string {
	entries = append(copyEntries(entries),
		DnsEntry{"localhost", "localhost.localdomain localhost4 localhost4.localdomain4", "127.0.0.1", ""},
		DnsEntry{"localhost", "localhost.localdomain localhost6 localhost6.localdomain6", "127.0.0.1", ""},
	)

	str := ""

	for _, ent := range entries {
		if len(ent.Address) < 1 {
			continue
		}

		if shortMode == "yes" {
			str += ent.Address + " " + ent.Name + "\n"
		} else {
			str += ent.Address + " " + ent.ShortName + " " + ent.Name + "\n"
		}
	}

	return str
}

func OutputEntries(entries []DnsEntry) {
	switch output {
	case "hosts":
		OutputHosts(entries)
	case "unbound-control":
		OutputUnboundControl(entries)
	default:
		log.Fatalf("Unknown output mode: %s", output)
	}

}

type EntryCache struct {
	mu      sync.RWMutex
	entries []DnsEntry
}

func NewEntryCache(entries []DnsEntry) *EntryCache {
	return &EntryCache{entries: copyEntries(entries)}
}

func (c *EntryCache) Set(entries []DnsEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = copyEntries(entries)
}

func (c *EntryCache) Get() []DnsEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return copyEntries(c.entries)
}

func RunServer() {
	entries, err := LoadVultrDNS()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Unable to load %s: %v", vultrdns, err)
	}

	cache := NewEntryCache(entries)
	log.Printf("Loaded %d cached entries from %s", len(entries), vultrdns)

	syncNow := func() {
		entries, err := MakeRequest()
		if err != nil {
			log.Printf("Vultr sync failed: %v", err)
			return
		}

		if err := SaveVultrDNS(entries); err != nil {
			log.Printf("Unable to write %s: %v", vultrdns, err)
			return
		}

		cache.Set(entries)
		log.Printf("Synced %d entries from Vultr", len(entries))
	}

	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	go func() {
		syncNow()

		for range ticker.C {
			syncNow()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/entries", func(w http.ResponseWriter, r *http.Request) {
		if !requireGet(w, r) {
			return
		}

		setModifiedAtHeader(w)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(cache.Get()); err != nil {
			log.Printf("Unable to encode entries: %v", err)
		}
	})
	mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !requireGet(w, r) {
			return
		}

		shortMode := short
		if requestedShort := r.URL.Query().Get("short"); requestedShort != "" {
			shortMode = requestedShort
		}

		setModifiedAtHeader(w)
		w.Header().Set("Content-Type", "text/plain")
		_, err := w.Write([]byte(FormatHosts(cache.Get(), shortMode)))
		if err != nil {
			log.Printf("Unable to write hosts response: %v", err)
		}
	})

	log.Printf("Server listening on %s; syncing every %s; cache %s", listen, syncInterval, vultrdns)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func RunClient() error {
	switch output {
	case "hosts":
		hosts, err := FetchHosts()
		if err != nil {
			return err
		}
		return WriteHosts(hosts)
	case "unbound-control":
		entries, err := FetchEntries()
		if err != nil {
			return err
		}
		OutputUnboundControl(entries)
		return nil
	default:
		return fmt.Errorf("unknown output mode: %s", output)
	}
}

func LoadVultrDNS() ([]DnsEntry, error) {
	data, err := ioutil.ReadFile(vultrdns)
	if err != nil {
		return nil, err
	}

	var entries []DnsEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	return entries, nil
}

func SaveVultrDNS(entries []DnsEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(vultrdns, data, 0644)
}

func FetchEntries() ([]DnsEntry, error) {
	endpoint, err := ServerEndpoint("/entries", nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s for %s", resp.Status, endpoint)
	}

	var entries []DnsEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	return entries, nil
}

func FetchHosts() (string, error) {
	query := url.Values{}
	query.Set("short", short)
	endpoint, err := ServerEndpoint("/hosts", query)
	if err != nil {
		return "", err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %s for %s", resp.Status, endpoint)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func ServerEndpoint(endpoint string, query url.Values) (string, error) {
	base := client
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}

	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	if u.Host == "" {
		return "", fmt.Errorf("invalid client server: %s", client)
	}

	if u.Port() == "" && !strings.Contains(u.Host, ":") {
		u.Host = u.Host + ":8080"
	}

	basePath := strings.TrimRight(u.Path, "/")
	u.Path = basePath + endpoint
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func requireGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func setModifiedAtHeader(w http.ResponseWriter) {
	info, err := os.Stat(vultrdns)
	if err != nil {
		return
	}

	w.Header().Set("X-ModifiedAt", info.ModTime().UTC().Format(time.RFC3339))
}

//Its imporant we remove any zones that were once present, so we need to diff, meaning we keep a cache//

func OutputUnboundControl(entries []DnsEntry) {

	//this block will give us a list of zones that need to be removed as they are present in the cache but no longer in the current list

	// entries = entries[:len(entries)-3]

	if fileExists(dnscache) {

		// do a diff, see if we need an update

		data, derr := ioutil.ReadFile(dnscache)

		if derr != nil {
			log.Fatal(derr)
		}

		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)

		var cache_entries []DnsEntry

		if err := dec.Decode(&cache_entries); err != nil {
			log.Fatal(err)
		}

		if len(cache_entries) > 0 && len(entries) > 1 {

			remove, err := EntryDiff(entries, cache_entries)

			if err != nil {
			}

			if len(remove) > 0 {

				for _, rem := range remove {

					cmd := "local_data_remove " + rem.Name

					state, err := UnboundCMD(cmd)

					if err != nil {

						log.Println(err)
					} else {

						log.Println(state, "-", cmd)
					}

				}

			}

		}

	}

	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(entries); err != nil {
		log.Fatal(err)
	}

	//save this!

	err2 := ioutil.WriteFile(dnscache, buf.Bytes(), 0644)

	if err2 != nil {

		log.Fatal(err2)
	}

	for _, ent := range entries {

		cmd := "local_data_remove " + ent.Name

		state, err := UnboundCMD(cmd)

		if err != nil {

			log.Println(err)

		} else {

			log.Println(state, "-", cmd)
		}

		cmd = "local_data " + ent.Name + " A " + ent.Address

		state, err = UnboundCMD(cmd)

		if err != nil {

			log.Println(err)
		} else {

			log.Println(state, "-", cmd)
		}

	}

}

func UnboundCMD(in string) (string, error) {
	args := strings.Fields(in)
	cmd := exec.Command("/usr/sbin/unbound-control", args...)

	out, err := cmd.CombinedOutput()

	if err != nil {
		return "", err
	}

	return strings.Trim(string(out), "\n"), nil
}

func EntryDiff(a []DnsEntry, b []DnsEntry) ([]DnsEntry, error) {
	present := make(map[DnsEntry]bool)

	for _, ent := range a {
		present[ent] = true
	}

	var remove []DnsEntry

	for _, ent := range b {
		if !present[ent] {
			remove = append(remove, ent)
		}
	}

	return remove, nil
}

func MakeRequest() ([]DnsEntry, error) {

	var entries []DnsEntry

	apiKey := viper.GetString("vultr_key")

	if apiKey == "" {
		return nil, fmt.Errorf("vultr_key is required for Vultr sync")
	}

	config := &oauth2.Config{}
	ctx := context.Background()
	ts := config.TokenSource(ctx, &oauth2.Token{AccessToken: apiKey})
	vultrClient := govultr.NewClient(oauth2.NewClient(ctx, ts))

	// Optional changes
	_ = vultrClient.SetBaseURL("https://api.vultr.com")
	vultrClient.SetUserAgent("vultrunbound-2")
	vultrClient.SetRateLimit(100 * time.Millisecond)
	vultrClient.SetRetryLimit(2)

	listOptions := &govultr.ListOptions{PerPage: 50}

	if debug == true {

		acc, _ := vultrClient.Account.Get(context.Background())

		log.Printf("%+v\n", acc)

	}

	for {
		i, meta, err := vultrClient.Instance.List(context.Background(), listOptions)
		if err != nil {
			if debug == true {
				log.Println(err)
			}
			return nil, err
		}
		for _, it := range i {

			if debug == true {
				log.Printf("%+v\n", i)
			}

			sname, shortname, shortnamep := ShortName(it.Label)

			d := DnsEntry{it.Label, shortname, it.MainIP, "eth0"}
			d2 := DnsEntry{sname, shortnamep, it.InternalIP, "eth1"}

			entries = append(entries, d)
			entries = append(entries, d2)

		}

		if meta.Links.Next == "" {
			break
		} else {
			listOptions.Cursor = meta.Links.Next
			continue
		}
	}

	return entries, nil
}

func ShortName(name string) (string, string, string) {

	shortname_raw := strings.Split(name, ".")

	shortname := name

	if len(shortname_raw) > 0 {

		shortname = shortname_raw[0]

	}

	if len(shortname_raw) > 3 {

		shortname = shortname_raw[0] + "." + shortname_raw[1]

	}

	shortname_rawp := shortname_raw

	shortnamep := shortname + "i"
	shortname_rawp[0] = shortname_rawp[0] + "i"

	sname := strings.Join(shortname_rawp, ".")

	if len(shortname_raw) > 3 {

		shortnamep = shortname_rawp[0] + "." + shortname_rawp[1]

	}

	return sname, shortname, shortnamep

}

func copyEntries(entries []DnsEntry) []DnsEntry {
	if entries == nil {
		return nil
	}

	entriesCopy := make([]DnsEntry, len(entries))
	copy(entriesCopy, entries)
	return entriesCopy
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
