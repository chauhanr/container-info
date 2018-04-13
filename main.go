package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"container-info/namespaces"
)

var (
	version bool
	DEBUG bool
	targetns string
	targetpid string
	cgspec string
	monspec string
)

const(
	BANNER = `
   __________
  / ____/  _/
 / /    / /
/ /____/ /
\____/___/

`
    VERSION = "0.1"
)

func debug (m string){
	if DEBUG{
		fmt.Printf("DEBUG: %s\n",m)
	}
}

func init(){
	flag.BoolVar(&version, "version", false ,"Lists the version of the tool")
	flag.StringVar(&targetns, "namespace", "" ,"Lists the details about the namespaces with procided ID")
	flag.StringVar(&targetpid, "pid", "" ,"Lists the namespaces that the processes with the id belongs to")
	flag.StringVar(&cgspec, "cgroup", "", "Lists the details of all the cgroups a process belogs to. Format PID:CGROUP_HIERARCHY")
	flag.StringVar(&monspec, "monitor", "", "Monitor process with provided control. Format PID:CF1, CF2...")

	flag.Usage = func(){
		fmt.Printf("Usage: %s [args] \n\n",os.Args)
		fmt.Println("Arguments: ")
		flag.PrintDefaults()
	}
	flag.Parse()

	DEBUG = false
	if envd := os.Getenv("DEBUG"); envd != "" {
		if d, err := strconv.ParseBool(envd); err ==nil{
			DEBUG = d
		}
	}
}

func about() {
	fmt.Printf(BANNER)
	fmt.Printf("\nThis is ci in version %s\n", VERSION)
}

func main(){
	if version{
		about()
		os.Exit(0)
	}
	namespaces.DEBUG = DEBUG
    namespaces.Gather()

	switch{
		case targetns != "":
			namespaces.LookupNS(targetns)
		case targetpid != "":
			namespaces.LookupPID(targetpid)
		case cgspec != "":
			namespaces.LookupCG(cgspec)
		case monspec != "":
			namespaces.MonitorPID(monspec)
		default:
			namespaces.ShowAll()
	}
}