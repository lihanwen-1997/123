/**************************
 * author 童坤坤
 * email  tkk48036@ly.com
 * date   03/02/20 10:32:58
 * desc   海南银行支付
 ***************************/
package cfg

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"common/dbclient"
	"common/log"
	pb "grpc_proto/db_server"

	"github.com/thinkoner/openssl"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	GCfg         JsonConf
	GAccInfos    []*AccInfo
	GAccPool     chan int
	confFile     = `conf\conf.json`
	shadowFile   = `conf\shadow.json`
	desKey       = "bHlfdG9u"
	signUsername = "userdbsvr"
	signUserkey  = "np!34(*ujo$%vns#)_MPK$@'-0MBf0m31fd"
	xqMap        = map[string]string{
		"midinfoUrl":      "http://172.18.151.13:9120",
		"midinfoUsername": "busPayRecord",
		"midinfoUserkey":  "",
		"notifyUrl":       "http://172.18.226.75:9800",
		"monitorUrl":      "172.18.226.12",
	}

	tcMap = map[string]string{
		"midinfoUrl":      "http://61.177.22.189:9120",
		"midinfoUsername": "busPayRecord",
		"midinfoUserkey":  "",
		"notifyUrl":       "http://10.101.180.4:7808",
		"monitorUrl":      "61.177.22.12",
	}

	envMap = map[string]map[string]string{
		"tc": tcMap,
		"xq": xqMap,
	}
)

type CustomInfo struct {
	RobotRegisterServerURL string
	Channel                string
	Idc                    string
	PayType                string
}

type JsonConf struct {
	HttpAddr        string
	JsHttpAddr      string
	RobotId         int
	RobotIdStr      string
	RobotCenter     string
	EnvMap          map[string]string
	UnitIndex       int
	UnitIndexStr    string
	HttpRealAddr    string
	DbServerUrl     string
	DbServerHttpUrl string
	ChromePath      string
}

type AccInfo struct {
	GAccount   string `json:"bankAccount"`
	GPassword  string `json:"payPwd"`
	GCheckcode string `json:"checkCode"`
	GIdentity  string `json:"idCard"`
	GPhone     string `json:"phoneNumber"`
}

type DbAcountInfo struct {
	Accounts []string
}

func init() {
	if !parseCfg() {
		panic(errors.New("cfg init failed"))
	}
}

func DesEncrypt(src string, key string) string {
	encryptBytes, err := openssl.DesECBEncrypt([]byte(src), []byte(key), openssl.PKCS7_PADDING)
	if err != nil {
		log.Error("DesEncrypt DesECBEncrypt failed, err:%+v", err)
		return ""
	}

	encodeString := base64.StdEncoding.EncodeToString(encryptBytes)
	return encodeString
}

func Des3Encrypt(src string, key string) string {
	for i := 0; i < 3; i++ {
		src = DesEncrypt(src, key)
		if src == "" {
			return ""
		}
	}
	return src
}

func DesDecrypt(src string, key string) string {
	decodeBytes, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		log.Error("Des3Decrypt base64 failed, err:%+v", err)
		return ""
	}
	decryptBytes, err := openssl.DesECBDecrypt(decodeBytes, []byte(key), openssl.PKCS7_PADDING)
	if err != nil {
		log.Error("Des3Decrypt DesECBDecrypt failed, err:%+v", err)
		return ""
	}
	return string(decryptBytes)
}

func Des3Decrypt(src string, key string) string {
	for i := 0; i < 3; i++ {
		src = DesDecrypt(src, key)
		if src == "" {
			return ""
		}
	}
	return src
}

func parseCfg() bool {
	log.Info("================ parseCfg begin ================")
	defer log.Info("================ parseCfg end ================")
	data, err := ioutil.ReadFile(confFile)
	if err != nil {
		log.Error("parseCfg Read %s failed, err:%s", confFile, err.Error())
		return false
	}

	if err := json.Unmarshal(data, &GCfg); err != nil {
		log.Error("parseCfg json.Unmarshal data:%+v, err:%s", data, err.Error())
		return false
	}

	GCfg.RobotIdStr = strconv.FormatInt(int64(GCfg.RobotId), 10)
	GCfg.UnitIndexStr = strconv.FormatInt(int64(GCfg.UnitIndex), 10)
	httpAddr, err := strconv.ParseInt(string(GCfg.HttpAddr[1:]), 10, 32)
	if err != nil {
		log.Error("parseCfg ParseInt HttpAddr %s failed, err:%s", GCfg.HttpAddr, err.Error())
		return false
	}
	GCfg.HttpRealAddr = fmt.Sprintf(":%d", httpAddr+int64(GCfg.UnitIndex))
	if !GetCfgFromDBServer() {
		log.Info("parseCfg GetCfgFromDBServer failed, use local cfg")
	}

	log.Info("GCfg:%+v", GCfg)
	data, err = ioutil.ReadFile(shadowFile)
	if err != nil {
		log.Error("parseCfg Read %s failed, err:%s", shadowFile, err.Error())
		return false
	}

	log.Info("parseCfg data:%v", string(data))
	if err := json.Unmarshal(data, &GAccInfos); err != nil {
		log.Error("parseCfg json.Unmarshal data:%+v, err:%s", data, err.Error())
		return false
	}

	log.Info("parseCfg GAccInfos:%+v len:%v", GAccInfos, len(GAccInfos))
	for i, accInfo := range GAccInfos {
		accInfo.GAccount = Des3Decrypt(accInfo.GAccount, desKey)
		accInfo.GPassword = Des3Decrypt(accInfo.GPassword, desKey)
		accInfo.GCheckcode = Des3Decrypt(accInfo.GCheckcode, desKey)
		accInfo.GIdentity = Des3Decrypt(accInfo.GIdentity, desKey)
		accInfo.GPhone = Des3Decrypt(accInfo.GPhone, desKey)

		if accInfo.GAccount == "" ||
			accInfo.GPassword == "" ||
			accInfo.GPassword == "" ||
			accInfo.GIdentity == "" ||
			accInfo.GPhone == "" {
			log.Error("parseCfg invalid accInfo:%+v", accInfo)
			return false
		}
		GAccInfos[i] = accInfo
		log.Info("parseCfg GAccInfos[%v]:%+v", i, GAccInfos[i])
	}
	accNum := len(GAccInfos)
	GAccPool = make(chan int, accNum)
	for i := 0; i < accNum; i++ {
		GAccPool <- i
	}
	log.Info("parseCfg GAccPool len:%+v", len(GAccPool))
	return true
}

func GetCfgFromDBServer() bool {
	log.Info("================ getCfgFromDBServer begin ================")

	// payUnitTb
	var respPayUnitTb *pb.PayUnitTbResponse
	var err error
	conn, err := grpc.Dial(GCfg.DbServerUrl, grpc.WithInsecure())
	if err != nil {
		log.Error("getCfgFromDBServer grpc.Dial failed, err:%s", err.Error())
		return false
	}

	defer conn.Close()
	c := pb.NewDBServerClient(conn)
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	respPayUnitTb, err = c.GetPayUnitTb(context.Background(), &pb.PayUnitTbRequest{
		Username:  "",
		RobotId:   int32(GCfg.RobotId),
		Timestamp: timestamp,
		Sign: fmt.Sprintf("%x", md5.Sum([]byte(signUsername+timestamp+
			fmt.Sprintf("%x", md5.Sum([]byte(timestamp+signUserkey))))))})
	if err != nil {
		log.Error("getCfgFromDBServer GetPayUnitTb failed, robotid:%d, err:%s", GCfg.RobotId, err.Error())
		return false
	}
	log.Info("getCfgFromDBServer GetPayUnitTb resp: %+v", respPayUnitTb)
	var customInfo CustomInfo
	if respPayUnitTb.Custom != "" {
		if err := json.Unmarshal([]byte(respPayUnitTb.Custom), &customInfo); err != nil {
			log.Error("getCfgFromDBServer json.Unmarshal customInfo:<%v>, err:<%s>", respPayUnitTb.Custom, err.Error())
			return false
		}

		//		log.Info("getCfgFromDBServer Custom: %+v", customInfo)
	}

	if customInfo.Idc == "" {
		customInfo.Idc = "tc"
	}

	if customInfo.Idc != "tc" && customInfo.Idc != "xq" {
		log.Error("getCfgFromDBServer invalid Idc:<%v>", customInfo.Idc)
		return false
	}
	GCfg.EnvMap = envMap[customInfo.Idc]

	// 银行账号
	var respBankTbs []*pb.BankTbResponse
	var accountNum = 0
	dbclt := dbclient.New(GCfg.DbServerHttpUrl)
	resp, ok := dbclt.GetAllHNBCAccounts()
	log.Info("GetCfgFromDBServer GetAllHNBCAccounts resp:%+v, ok:%v", resp, ok)
	if !ok {
		log.Error("getCfgFromDBServer GetAllHNBCAccounts failed")
		return false
	}

	var accounts []string
	if err := json.Unmarshal([]byte(resp.ResultData), &accounts); err != nil {
		log.Error("getCfgFromDBServer Unmarshal accounts failed, err:%v", err)
		return false
	}

	if len(accounts) != 0 {
		// if err := json.Unmarshal([]byte(respPayUnitTb.AccountInfo), &dbAccountInfo); err != nil {
		// 	log.Error("json.Unmarshal acountInfo:<%v>, err:<%s>", respPayUnitTb.AccountInfo, err.Error())
		// 	return false
		// }
		var respBankTbEntry *pb.BankTbResponse
		// log.Info("respPayUnitTb.AccountInfo:<%+v>, accountInfo:<%+v>, accountInfo.Accounts:<%+v>", respPayUnitTb.AccountInfo, dbAccountInfo, dbAccountInfo.Accounts)

		for i, account := range accounts {
			encAccount := Des3Encrypt(account, desKey)
			timestamp = strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
			log.Info("i:<%+v>, account:<%+v>, encAccount:<%v>, timestamp:<%+v>", i, account, encAccount, timestamp)
			respBankTbEntry, err = c.GetBankTb(context.Background(), &pb.BankTbRequest{
				BankAccount: encAccount,
				Timestamp:   timestamp,
				Sign: fmt.Sprintf("%x", md5.Sum([]byte(signUsername+timestamp+
					fmt.Sprintf("%x", md5.Sum([]byte(timestamp+signUserkey))))))})
			if err != nil {
				log.Error("getCfgFromDBServer GetBankTb failed, BankAccount:%s, err:%s", account, err.Error())
				return false
			}
			respBankTbs = append(respBankTbs, respBankTbEntry)
			accountNum = i + 1
			//		log.Info("i:<%+v>, account:<%+v>, respBankTbEntry:<%+v>, accountNum:<%+v>", i, account, respBankTbEntry, accountNum)
		}

		//	log.Info("getCfgFromDBServer respBankTbs: %+v", respBankTbs)
	}

	cfgStr := ""
	for i := 0; i < accountNum; i++ {
		cfgStr = cfgStr + fmt.Sprintf(`
	{
		"bankAccount":"%s",
		"phoneNumber":"%s",
		"payPwd":"%s",
		"checkCode":"%s",
		"idCard":"%s"
	},`,
			respBankTbs[i].GetBankAccount(),
			respBankTbs[i].GetPhoneNumber(),
			respBankTbs[i].GetPayPwd(),
			respBankTbs[i].GetCheckCode(),
			respBankTbs[i].GetIdCard())
		// log.Info("getCfgFromDBServer cfgStr:%v", cfgStr)
	}

	// log.Info("getCfgFromDBServer cfgStr out loop:%v", cfgStr)
	cfgStr = fmt.Sprintf("[%s\n]", cfgStr[:len(cfgStr)-1])
	// log.Info("getCfgFromDBServer cfgStr after sanitize:%v", cfgStr)
	if err := ioutil.WriteFile(shadowFile, []byte(cfgStr), 0777); err != nil {
		log.Error("writeCfg write cfgStr:<%s> to file:<%s> failed, err:%s", cfgStr, shadowFile, err.Error())
		return false
	}

	log.Info("================ getCfgFromDBServer end ================")
	return true
}
