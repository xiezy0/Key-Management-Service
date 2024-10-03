package consensus

import (
	"fmt"
	aba "hacss/src/aba/waterbear"
	"hacss/src/hacss"
	"hacss/src/logging"
	"hacss/src/quorum"
	"hacss/src/utils"
	"log"
	"time"
)

func MonitorWaterBearHACSSStatus(e int) {
	for {
		if epoch.Get() > e {
			p := fmt.Sprintf("[Consensus HACSS] Current epoch %v is greater than the input epoch %v", epoch.Get(), e)
			logging.PrintLog(verbose, logging.NormalLog, p)
			return
		}

		for i := 0; i < n; i++ {
			instanceid := GetInstanceID(members[i])
			status := hacss.QueryStatus(instanceid)
			if !astatus.GetStatus(instanceid) && status {
				astatus.Insert(instanceid, true)
				go StartWBABA(instanceid, 1)
			}

			/*if astatus.GetCount() >= quorum.QuorumSize(){
				go StartWBOtherABAs()
			}*/

			switch consensus {
			case WaterBearBiased:
				if astatus.GetCount() >= quorum.QuorumSize() {
					go StartWBOtherABAs()
				}
			}

		}
		time.Sleep(time.Duration(sleepTimerValue) * time.Millisecond)
	}
}

func MonitorWaterBearABAStatus(e int) {
	for {
		if epoch.Get() > e {
			p := fmt.Sprintf("[Consensus ABA] Current epoch %v is greater than the input epoch %v", epoch.Get(), e)
			logging.PrintLog(true, logging.NormalLog, p)
			return
		}

		for i := 0; i < n; i++ {
			instanceid := GetInstanceID(members[i])
			status := aba.QueryStatus(instanceid)
			//if fstatus.GetStatus(instanceid) && status{
			//	p := fmt.Sprintf("[Consensus] Instance %v has been insert to fstatus %v",instanceid,fstatus)
			//	logging.PrintLog(true, logging.InfoLog, p)
			//}
			if !fstatus.GetStatus(instanceid) && status {
				//log.Printf("[%v] Instance has been decided!**************************************%v",instanceid,instanceid)
				fstatus.Insert(instanceid, true)
				go UpdateWBOutput(instanceid)
			}

			if fstatus.GetCount() == n {
				return
			}

		}
		time.Sleep(time.Duration(sleepTimerValue) * time.Millisecond)
	}
}

func UpdateWBOutputSet(instanceid int) {
	for {
		v := hacss.QueryReq(instanceid)
		if v != nil {
			output.AddItem(v)
			break
		} else {
			time.Sleep(time.Duration(sleepTimerValue) * time.Millisecond)
		}
	}
}

func UpdateWBOutput(instanceid int) {
	p := fmt.Sprintf("[Consensus] Update Output for instance %v in epoch %v", instanceid, epoch.Get())
	logging.PrintLog(true, logging.NormalLog, p)
	value := aba.QueryValue(instanceid)

	if value == 0 {
		outputCount.Increment()
	} else {
		outputSize.Increment()
		outputCount.Increment()
		go UpdateWBOutputSet(instanceid)
	}
	//p = fmt.Sprintf("[Consensus] outputCount %v for epoch %v",outputCount.Get(),epoch.Get())
	//logging.PrintLog(true, logging.InfoLog, p)
	//elock.Lock()
	if outputCount.Get() == n && curStatus.Get() != READY {
		curStatus.Set(READY)
		//elock.Unlock()

		var acceptInstance []int
		for i := 0; i < n; i++ {
			tmpid := GetInstanceID(members[i])
			value = aba.QueryValue(tmpid)
			if value != 0 {
				acceptInstance = append(acceptInstance, tmpid)
			}
		}
		curEp := epoch.Get()
		sk, pk, suc := hacss.GenerateShareKey(curEp, acceptInstance)
		fmt.Println("Recover the sk: ", sk)
		fmt.Println("Recover the pk: ", pk)
		if !suc {
			log.Printf("Fail to recover the sk and pk\n")
			log.Printf("Recover the sk:%v", sk)
			//tb, err := sk.V.MarshalBinary()
			//if err == nil {
			//	log.Printf("Recover the sk(byte):%v", tb)
			//}
			log.Printf("Recover the pk:%v", pk)
		}

		ExitEpoch()
		return
	}
	//elock.Unlock()
}

func StartWBABA(instanceid int, input int) {
	if bstatus.GetStatus(instanceid) {
		return
	}
	bstatus.Insert(instanceid, true)
	//log.Printf("[%v] Starting ABA from zero with input %v in epoch %v", instanceid, input,epoch.Get())
	switch consensus {
	case WaterBearBiased:
		aba.StartABAFromRoundZero(instanceid, input)
	default:
		log.Fatalf("This script only supports WaterBear and biased WaterBear")
	}
}

func StartWBOtherABAs() {
	//log.Printf("Start other ABAs")
	if otherlock.Get() == 1 {
		return
	}
	//log.Printf("Start other ABAs")
	for i := 0; i < n; i++ {
		instanceid := GetInstanceID(members[i])
		if !astatus.GetStatus(instanceid) {
			//log.Printf("[%v] Start other ABAs for %v with 0",instanceid,instanceid)
			go StartWBABA(instanceid, 0)
		}
	}
	otherlock.Set(1)
}

func StartWaterBear(data []byte, ct bool) {
	/*rbc.InitRBC(id,n,verbose)
	aba.InitABA(id,n,verbose,members,sleepTimerValue)
	aba.SetEpoch(epoch.Get())
	rbc.SetEpoch(epoch.Get())*/
	if ct {
		log.Println("starting WaterBear-BFT-HACSS")
	} else {
		log.Println("start WaterBear-BFT")
	}

	InitWaterBearBFT(ct)
	t1 = utils.MakeTimestamp()

	hacss.StartHACSS(GetInstanceID(iid), data)

	go MonitorWaterBearHACSSStatus(epoch.Get())

	go MonitorWaterBearABAStatus(epoch.Get())
}

func InitWaterBearBFT(ct bool) {
	InitStatus(n)
	//aba.SetEpoch(epoch.Get())

	hacss.SetEpoch(epoch.Get())

	aba.InitCoinType(ct)
}
