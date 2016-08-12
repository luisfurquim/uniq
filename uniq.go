package uniq

import (
   "os"
   "fmt"
   "time"
   "regexp"
   "os/user"
   "io/ioutil"
   "golang.org/x/crypto/ssh"
   "github.com/luisfurquim/goose"
)

var Goose     goose.Alert
var procRE   *regexp.Regexp
var BinName   string

func init() {
   procRE  = regexp.MustCompile("^[0-9]+$")
}

// Checks if there are other running processes with the same name of the current one and
// returns its PIDs (if any)
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
            Goose.Logf(3,"Error reading other exe link: %s",err)
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

// Checks if there are running processes with the given name and
// returns its PIDs (if any)
func CheckByName(targetExe string) ([]int, error) {
   var err          error
   var pid          int
   var pids       []int
   var otherExe     string

   pids            = []int{}
   files, _ := ioutil.ReadDir("/proc")
   for _, f := range files {
      if procRE.MatchString(f.Name()) {
         otherExe, err = os.Readlink("/proc/" + f.Name() + "/exe")
         if err != nil {
            Goose.Logf(3,"Error reading other exe link: %s",err)
            continue
         }

         if targetExe == otherExe {
            fmt.Sscanf(f.Name(),"%d",&pid)
            pids = append(pids,pid)
         }
      }
   }

   return pids, nil
}

// Checks if there are running processes with the given name and reruns it if not found.
// It uses SSH to run the program
func Sustain(exe, run, port string) error {
   var err          error
   var pids       []int
   var usr         *user.User
   var sshCliCfg   *ssh.ClientConfig
   var sshclient   *ssh.Client
   var session     *ssh.Session
   var clientKey  []byte
   var signer       ssh.Signer
   var privKeyPath  string

   Goose.Logf(3,"Checking if %s is running",exe)

   pids, err = CheckByName(exe)
   if err != nil {
      Goose.Logf(1,"Error checking if %s is running: %s",exe,err)
      return err
   }

   if len(pids) == 0 {
      Goose.Logf(3,"%s not running",exe)
      if run == "" {
         run = exe
      }

      if port == "" {
         port = "22"
      }

      usr, err = user.Current()
      if err != nil {
         Goose.Logf(1,"Cannot identify myself: %s",err)
         return err
      }

      privKeyPath = usr.HomeDir + "/.ssh/id_dsa"

      clientKey, err = ioutil.ReadFile(privKeyPath)
      if err != nil {
         privKeyPath = usr.HomeDir + "/.ssh/id_rsa"
         clientKey, err = ioutil.ReadFile(privKeyPath)
         if err != nil {
            Goose.Logf(1,"Error reading SSH keys (%s)",err)
            return err
         }
      }

      Goose.Logf(4,"Reading SSH private key from %s",privKeyPath)

      signer, err = ssh.ParsePrivateKey(clientKey)
      if err != nil {
         Goose.Logf(1,"Error parsing SSH keys (%s)",err)
         return err
      }

      sshCliCfg = &ssh.ClientConfig{
         User: usr.Username,
         Auth: []ssh.AuthMethod{
            ssh.PublicKeys(signer),
         },
      }

      Goose.Logf(4,"Connecting to %s@127.0.0.1 on port %s using config %#v",usr.Username,port,sshCliCfg)

      sshclient, err = ssh.Dial("tcp", "127.0.0.1:" + port, sshCliCfg)
      if err != nil {
         Goose.Logf(1,"Error connecting to local SSH server (%s)",err)
         return err
      }

      session, err = sshclient.NewSession()
      if err != nil {
         Goose.Logf(1,"Error starting a new SSH session (%s)",err)
         return err
      }

      defer session.Close()

      Goose.Logf(2,"SSH starting %s", exe)

      if err = session.Start(run); err != nil {
         Goose.Logf(1,"Error running %s (%s)",run,err)
         return err
      }

      time.Sleep(3 * time.Second)

      Goose.Logf(3,"Waited 5 seconds, gueesing %s has started...", exe)

   }

   return nil
}

