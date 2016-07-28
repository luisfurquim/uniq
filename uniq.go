package uniq

import (
   "os"
   "fmt"
   "regexp"
   "io/ioutil"
   "github.com/luisfurquim/goose"
)

var Goose     goose.Alert
var procRE   *regexp.Regexp
var BinName   string

func init() {
   procRE  = regexp.MustCompile("^[0-9]+$")
}

func Check() ([]int, error) {
   var err          error
   var selfPID      string
   var pid          int
   var pids       []int
   var selfExe      string
   var otherExe     string

   selfPID = fmt.Sprintf("%d",os.Getpid())
   selfExe, err = os.Readlink("/proc/" + selfPID + "/exe")
   if err != nil {
      Goose.Logf(1,"Error reading self exe link: %s",err)
      return nil, err
   }

   pids            = []int{}
   files, _ := ioutil.ReadDir("/proc")
   for _, f := range files {
      if selfPID == f.Name() {
         continue
      }
      if procRE.MatchString(f.Name()) {
         otherExe, err = os.Readlink("/proc/" + f.Name() + "/exe")
         if err != nil {
            Goose.Logf(1,"Error reading other exe link: %s",err)
            continue
         }

         if selfExe == otherExe {
            fmt.Sscanf(f.Name(),"%d",&pid)
            pids = append(pids,pid)
         }
      }
   }

   return pids, nil
}

