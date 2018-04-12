package namespaces

import (
	"runtime"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"io/ioutil"
	tw "github.com/olekukonko/tablewriter"
	"strconv"
	"sort"
)

type NSTYPE string

var(
	DEBUG bool
	NS []NSTYPE
	namespaces map[Namespace][]Process
	processes map[string][]Namespace
	availablecgs map[string]string
	MAX_COMMAND_LEN int
)


func debug(m string) {
	if DEBUG {
		fmt.Printf("DEBUG: %s\n", m)
	}
}

const (
	NS_MOUNT  NSTYPE = "mnt"    // CLONE_NEWNS, filesystem mount points
	NS_UTS    NSTYPE = "uts"    // CLONE_NEWUTS, nodename and NIS domain name
	NS_IPC    NSTYPE = "ipc"    // CLONE_NEWIPC, interprocess communication
	NS_PID    NSTYPE = "pid"    // CLONE_NEWPID, process ID number space isolation
	NS_NET    NSTYPE = "net"    // CLONE_NEWNET, network system resources
	NS_USER   NSTYPE = "user"   // CLONE_NEWUSER, user and group ID number space isolation
	NS_CGROUP NSTYPE = "cgroup" // CLONE_NEWCGROUP, cgroup root directory

)


type Namespace struct{
	Type NSTYPE
	Id string
}

type Process struct{
	Pid string `json:"pid"`
	PPid string `json:"ppid"`
	Name string `json:"name"`
	State string `json:"state"`
	Threads string `json:"nthreads"`
	Cgroups string `json:"cgroups"`
	Uids string `json:"uids"`
	Command string `json:"cmd"`
}


func init() {
	NS = []NSTYPE{NS_MOUNT, NS_UTS, NS_IPC, NS_PID, NS_NET, NS_USER}
	// for all default operations and lookups:
	namespaces = make(map[Namespace][]Process)
	// for lookups only (PID -> namespaces):
	processes = make(map[string][]Namespace)
	MAX_COMMAND_LEN = 20

}

func initcgs(){
	acgs := "/proc/cgroups"
	availablecgs = map[string]string{}
	if c, err := ioutil.ReadFile(acgs); err == nil{
		lines := strings.Split(string(c), "\n")
		for _, l := range lines{
			if l != "" && !strings.Contains(l, "#"){
				name := strings.Fields(l)[0]
				id := strings.Fields(l)[1]
				enabled := strings.Fields(l)[3]
				if enabled == "1"{
					availablecgs[name] = id
				}
			}
		}
	}
	debug(fmt.Sprintf("available cgroups: %v\n", availablecgs))
}

func Gather() {
	if runtime.GOOS != "linux" {
		fmt.Printf("Sorry this is a Linux specific tool cannot work on %s OS\n", runtime.GOOS)
		os.Exit(1)
	}

	// this will read all the process files to get the information about each process.
	fn, _ := filepath.Glob("/proc/[0-9]*")
	for _, f := range fn{
		_, pid := filepath.Split(f) // this gives the file name after the final file separator
		debug(fmt.Sprintf("For filename %s pid is %s", f, pid))
		for _, tns := range NS{
			debug("for namespace : "+string(tns))
			if ns, e := resolve(tns, pid); e == nil{
				debug(fmt.Sprintf("%+v",ns))
				p, _ := status(pid)
				namespaces[*ns] = append(namespaces[*ns], *p)
				// processes information
				processes[pid] = append(processes[pid], *ns)
			}else {
				debug(fmt.Sprintf("%s of process %s", e, pid))
			}
		}
	}
	initcgs()
}

func status(pid string) (*Process, error){
	sfile := filepath.Join("/proc", pid, "status")
	debug("reading" + sfile)

	if s, err := ioutil.ReadFile(sfile); err == nil{
		p := Process{}
		lines := strings.Split(string(s), "\n")
		for _, l := range lines {
			debug("status field :"+l)
			if l != ""{
				k := strings.Split(l, ":")[0]
				v := strings.TrimSpace(strings.Split(l,":")[1])
				switch k {
					case "Pid" :
						p.Pid = v
					case "PPid" :
						p.PPid = v
					case "Name" :
						p.Name = v
					case "State":
						p.State = v
					case "Threads":
						p.Threads = v
					case "Uid":
						p.Uids = v
				}
			}
		}
		cfile := filepath.Join("/proc", pid, "cgroup")
		if cg, cerr := ioutil.ReadFile(cfile); cerr == nil{
			p.Cgroups = string(cg)
		}

		cmdfile := filepath.Join("/proc", pid, "cmdline")
		if cmd, cerr := ioutil.ReadFile(cmdfile); cerr == nil{
			p.Command = strings.TrimSpace(string(cmd))
		}
		debug(fmt.Sprintf("%+v\n", p))
		return &p, nil
	}else{
		return nil, err
	}
}

func resolve(nstype NSTYPE, pid string) (*Namespace, error){
	debug("namespace type: "+string(nstype))
	nsfile := filepath.Join("/proc", pid, "ns", string(nstype))
	debug(nsfile)
	if content, err := os.Readlink(nsfile); err == nil{
		debug(content)
		nsnum := strings.Split(content, ":")[1]
		nsnum = nsnum[1: len(nsnum)-1]
		ns := Namespace{}
		ns.Type = nstype
		ns.Id = string(nsnum)
		return &ns, nil
	}else{
		return nil, err
	}
}

func LookupPID(pid string){
	ptable := tw.NewWriter(os.Stdout)
	ptable.SetHeader([]string{"NAMESPACE", "TYPE"})
	ptable.SetCenterSeparator("")
	ptable.SetColumnSeparator("")
	ptable.SetRowSeparator("")
	ptable.SetHeaderAlignment(tw.ALIGN_LEFT)
	ptable.SetAlignment(tw.ALIGN_LEFT)

	for _, ns := range processes[pid]{
		row := []string{ns.Id, string(ns.Type)}
		ptable.Append(row)
	}
	ptable.Render()
}

func LookupNS(targetns string){
	ptable := tw.NewWriter(os.Stdout)
	ptable.SetHeader([]string{"PID",  "PPID", "NAME", "CMD", "NTHREADS", "CGROUPS", "STATE"})
	ptable.SetCenterSeparator("")
	ptable.SetColumnSeparator("")
	ptable.SetRowSeparator("")
	ptable.SetAlignment(tw.ALIGN_LEFT)
	ptable.SetHeaderAlignment(tw.ALIGN_LEFT)
	for _, tns := range NS{
		ns := Namespace{}
		ns.Type = tns
		ns.Id = targetns
		pl := namespaces[ns]
		for _, p := range pl{
			cmd := p.Command
			if len(cmd) > MAX_COMMAND_LEN {
				cmd = cmd[:MAX_COMMAND_LEN]
			}
			row := []string{string(p.Pid), string(p.PPid), p.Name, cmd, string(p.Threads), p.Cgroups, p.State}
			ptable.Append(row)
		}
	}
	ptable.Render()
}

func ShowAll(){
	ntable := tw.NewWriter(os.Stdout)
	ntable.SetHeader([]string{"NAMESPACE", "TYPE", "NPROCS", "USERS", "CMD"})
	ntable.SetCenterSeparator("")
	ntable.SetColumnSeparator("")
	ntable.SetRowSeparator("")
	ntable.SetAlignment(tw.ALIGN_LEFT)
	ntable.SetHeaderAlignment(tw.ALIGN_LEFT)

	for n, pl := range namespaces{
		u := ""
		suids := make([]int,0)
		for _, p := range pl{
			uid, _ := strconv.Atoi(strings.Fields(p.Uids)[1])
			if !contains(uid,suids){
				suids = append(suids,int(uid))
			}
		}
		sort.Ints(suids)
		for _, uid := range suids{
			u += fmt.Sprintf("%d ", uid)
		}
		if strings.HasSuffix(u, ","){
			u = u[0:len(u)-1]
		}
		cmd := pl[0].Command
		if len(cmd) > MAX_COMMAND_LEN{
			cmd = cmd[:MAX_COMMAND_LEN]
		}
		row := []string{string(n.Id), string(n.Type), strconv.Itoa(len(pl)), u, cmd}
		ntable.Append(row)
	}
	ntable.Render()
}


func contains(s int, slist []int) bool {
	for _, b := range slist {
		if b == s {
			return true
		}
	}
	return false
}