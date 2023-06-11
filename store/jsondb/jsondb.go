package jsondb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/robfig/cron/v3"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/romaxa55/wireguard-ui/model"
	"github.com/romaxa55/wireguard-ui/util"
	"github.com/sdomino/scribble"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type JsonDB struct {
	conn            *scribble.Driver
	dbPath          string
	notifiedClients map[string]time.Time
}

// New returns a new pointer JsonDB
func New(dbPath string) (*JsonDB, error) {
	conn, err := scribble.New(dbPath, nil)
	if err != nil {
		return nil, err
	}
	ans := JsonDB{
		conn:   conn,
		dbPath: dbPath,
	}
	return &ans, nil

}

func (o *JsonDB) Init() error {
	var clientPath string = path.Join(o.dbPath, "clients")
	var serverPath string = path.Join(o.dbPath, "server")
	var wakeOnLanHostsPath string = path.Join(o.dbPath, "wake_on_lan_hosts")
	var serverInterfacePath string = path.Join(serverPath, "interfaces.json")
	var serverKeyPairPath string = path.Join(serverPath, "keypair.json")
	var globalSettingPath string = path.Join(serverPath, "global_settings.json")
	var hashesPath string = path.Join(serverPath, "hashes.json")
	var userPath string = path.Join(serverPath, "users.json")

	// create directories if they do not exist
	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		os.MkdirAll(clientPath, os.ModePerm)
	}
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		os.MkdirAll(serverPath, os.ModePerm)
	}
	if _, err := os.Stat(wakeOnLanHostsPath); os.IsNotExist(err) {
		os.MkdirAll(wakeOnLanHostsPath, os.ModePerm)
	}
	if _, err := os.Stat(userPath); os.IsNotExist(err) {
		os.MkdirAll(userPath, os.ModePerm)
	}

	// server's interface
	if _, err := os.Stat(serverInterfacePath); os.IsNotExist(err) {
		serverInterface := new(model.ServerInterface)
		serverInterface.Addresses = util.LookupEnvOrStrings(util.ServerAddressesEnvVar, []string{util.DefaultServerAddress})
		serverInterface.ListenPort = util.LookupEnvOrInt(util.ServerListenPortEnvVar, util.DefaultServerPort)
		serverInterface.PostUp = util.LookupEnvOrString(util.ServerPostUpScriptEnvVar, "")
		serverInterface.PostDown = util.LookupEnvOrString(util.ServerPostDownScriptEnvVar, "")
		serverInterface.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "interfaces", serverInterface)
	}

	// server's key pair
	if _, err := os.Stat(serverKeyPairPath); os.IsNotExist(err) {

		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return scribble.ErrMissingCollection
		}
		serverKeyPair := new(model.ServerKeypair)
		serverKeyPair.PrivateKey = key.String()
		serverKeyPair.PublicKey = key.PublicKey().String()
		serverKeyPair.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "keypair", serverKeyPair)
	}

	// global settings
	if _, err := os.Stat(globalSettingPath); os.IsNotExist(err) {
		endpointAddress := util.LookupEnvOrString(util.EndpointAddressEnvVar, "")
		if endpointAddress == "" {
			// automatically find an external IP address
			publicInterface, err := util.GetPublicIP()
			if err != nil {
				return err
			}
			endpointAddress = publicInterface.IPAddress
		}

		globalSetting := new(model.GlobalSetting)
		globalSetting.EndpointAddress = endpointAddress
		globalSetting.DNSServers = util.LookupEnvOrStrings(util.DNSEnvVar, []string{util.DefaultDNS})
		globalSetting.TelegramToken = util.LookupEnvOrString(util.EnvTelegramToken, util.DefaultTelegramToken)
		globalSetting.TelegramChat = int64(util.LookupEnvOrInt(util.EnvTelegramChat, util.DefaultTelegramChat))
		globalSetting.MTU = util.LookupEnvOrInt(util.MTUEnvVar, util.DefaultMTU)
		globalSetting.PersistentKeepalive = util.LookupEnvOrInt(util.PersistentKeepaliveEnvVar, util.DefaultPersistentKeepalive)
		globalSetting.FirewallMark = util.LookupEnvOrString(util.FirewallMarkEnvVar, util.DefaultFirewallMark)
		globalSetting.Table = util.LookupEnvOrString(util.TableEnvVar, util.DefaultTable)
		globalSetting.ConfigFilePath = util.LookupEnvOrString(util.ConfigFilePathEnvVar, util.DefaultConfigFilePath)
		globalSetting.RemoteAPI = util.LookupEnvOrString(util.ConfigRemoteAPIEnvVar, util.DefaultRemoteAPI)
		globalSetting.UpdatedAt = time.Now().UTC()
		o.conn.Write("server", "global_settings", globalSetting)
	}

	// hashes
	if _, err := os.Stat(hashesPath); os.IsNotExist(err) {
		clientServerHashes := new(model.ClientServerHashes)
		clientServerHashes.Client = "none"
		clientServerHashes.Server = "none"
		o.conn.Write("server", "hashes", clientServerHashes)
	}

	// user info
	results, err := o.conn.ReadAll("users")
	if err != nil || len(results) < 1 {
		user := new(model.User)
		user.Username = util.LookupEnvOrString(util.UsernameEnvVar, util.DefaultUsername)
		user.Admin = util.DefaultIsAdmin
		user.PasswordHash = util.LookupEnvOrString(util.PasswordHashEnvVar, "")
		if user.PasswordHash == "" {
			plaintext := util.LookupEnvOrString(util.PasswordEnvVar, util.DefaultPassword)
			hash, err := util.HashPassword(plaintext)
			if err != nil {
				return err
			}
			user.PasswordHash = hash
		}
		o.conn.Write("users", user.Username, user)
	}

	// Запуск планировщика
	o.StartScheduler()

	return nil
}

// GetUser func to query user info from the database
func (o *JsonDB) GetUser() (model.User, error) {
	user := model.User{}
	return user, o.conn.Read("server", "users", &user)
}

// GetUsers func to get all users from the database
func (o *JsonDB) GetUsers() ([]model.User, error) {
	var users []model.User
	results, err := o.conn.ReadAll("users")
	if err != nil {
		return users, err
	}
	for _, i := range results {
		user := model.User{}

		if err := json.Unmarshal([]byte(i), &user); err != nil {
			return users, fmt.Errorf("cannot decode user json structure: %v", err)
		}
		users = append(users, user)

	}
	return users, err
}

// GetUserByName func to get single user from the database
func (o *JsonDB) GetUserByName(username string) (model.User, error) {
	user := model.User{}

	if err := o.conn.Read("users", username, &user); err != nil {
		return user, err
	}

	return user, nil
}

// SaveUser func to save user in the database
func (o *JsonDB) SaveUser(user model.User) error {
	return o.conn.Write("users", user.Username, user)
}

// DeleteUser func to remove user from the database
func (o *JsonDB) DeleteUser(username string) error {
	return o.conn.Delete("users", username)
}

// GetGlobalSettings func to query global settings from the database
func (o *JsonDB) GetGlobalSettings() (model.GlobalSetting, error) {
	settings := model.GlobalSetting{}
	return settings, o.conn.Read("server", "global_settings", &settings)
}

// GetServer func to query Server settings from the database
func (o *JsonDB) GetServer() (model.Server, error) {
	server := model.Server{}
	// read server interface information
	serverInterface := model.ServerInterface{}
	if err := o.conn.Read("server", "interfaces", &serverInterface); err != nil {
		return server, err
	}

	// read server key pair information
	serverKeyPair := model.ServerKeypair{}
	if err := o.conn.Read("server", "keypair", &serverKeyPair); err != nil {
		return server, err
	}

	// create Server object and return
	server.Interface = &serverInterface
	server.KeyPair = &serverKeyPair
	return server, nil
}

func (o *JsonDB) GetClients(hasQRCode bool) ([]model.ClientData, error) {
	var clients []model.ClientData

	// read all client json files in "clients" directory
	records, err := o.conn.ReadAll("clients")
	if err != nil {
		return clients, err
	}

	// build the ClientData list
	for _, f := range records {
		client := model.Client{}
		clientData := model.ClientData{}

		// get client info
		if err := json.Unmarshal([]byte(f), &client); err != nil {
			return clients, fmt.Errorf("cannot decode client json structure: %v", err)
		}

		// generate client qrcode image in base64
		if hasQRCode && client.PrivateKey != "" {
			server, _ := o.GetServer()
			globalSettings, _ := o.GetGlobalSettings()

			png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
			if err == nil {
				clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
			} else {
				fmt.Print("Cannot generate QR code: ", err)
			}
		}

		// create the list of clients and their qrcode data
		clientData.Client = &client
		clients = append(clients, clientData)
	}

	return clients, nil
}

func (o *JsonDB) GetClientByID(clientID string, qrCodeSettings model.QRCodeSettings) (model.ClientData, error) {
	client := model.Client{}
	clientData := model.ClientData{}

	// read client information
	if err := o.conn.Read("clients", clientID, &client); err != nil {
		return clientData, err
	}

	// generate client qrcode image in base64
	if qrCodeSettings.Enabled && client.PrivateKey != "" {
		server, _ := o.GetServer()
		globalSettings, _ := o.GetGlobalSettings()
		client := client
		if !qrCodeSettings.IncludeDNS {
			globalSettings.DNSServers = []string{}
		}
		if !qrCodeSettings.IncludeMTU {
			globalSettings.MTU = 0
		}

		png, err := qrcode.Encode(util.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
		if err == nil {
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(png))
		} else {
			fmt.Print("Cannot generate QR code: ", err)
		}
	}

	clientData.Client = &client

	return clientData, nil
}

func (o *JsonDB) SaveClient(client model.Client) error {
	return o.conn.Write("clients", client.ID, client)
}

func (o *JsonDB) DeleteClient(clientID string) error {
	return o.conn.Delete("clients", clientID)
}

func (o *JsonDB) SaveServerInterface(serverInterface model.ServerInterface) error {
	return o.conn.Write("server", "interfaces", serverInterface)
}

func (o *JsonDB) SaveServerKeyPair(serverKeyPair model.ServerKeypair) error {
	return o.conn.Write("server", "keypair", serverKeyPair)
}

func (o *JsonDB) SaveGlobalSettings(globalSettings model.GlobalSetting) error {
	return o.conn.Write("server", "global_settings", globalSettings)
}

func (o *JsonDB) GetRemoteApi() string {
	return o.dbPath
}

func (o *JsonDB) GetPath() string {
	return o.dbPath
}

func (o *JsonDB) GetHashes() (model.ClientServerHashes, error) {
	hashes := model.ClientServerHashes{}
	return hashes, o.conn.Read("server", "hashes", &hashes)
}

func (o *JsonDB) SaveHashes(hashes model.ClientServerHashes) error {
	return o.conn.Write("server", "hashes", hashes)
}

func (o *JsonDB) StartScheduler() {
	cronTime := util.LookupEnvOrString(util.CronEnvVar, "*/30 * * * * *")
	// Global map to keep track of notified clients
	o.notifiedClients = make(map[string]time.Time)

	c := cron.New(cron.WithSeconds())
	_, err := c.AddFunc(cronTime, func() {
		o.checkPaymentsAndUpdateWireguard()
	})
	if err != nil {
		log.Fatalf("Invalid cron time: %v", err)
	}
	c.Start()
}

func (o *JsonDB) checkPaymentsAndUpdateWireguard() {
	fmt.Println("Checking payments at", time.Now())

	clients, err := o.GetClients(false) // false, если вам не нужны QR-коды

	if err != nil {
		fmt.Println("Error getting clients:", err)
		return
	}

	for _, clientData := range clients {
		client := clientData.Client
		if !client.Enabled {
			continue
		}

		paymentDate := client.PaymentDate
		if paymentDate.IsZero() {
			fmt.Println("Payment date not set for client:", client.Name)
			continue
		}
		// Вычисляем количество оставшихся дней до платежа
		daysUntilPayment := paymentDate.Sub(time.Now()).Hours() / 24
		days := int(math.Ceil(daysUntilPayment))
		switch {
		case days > 3:
			// Дата платежа еще не наступила
			fmt.Println("Payment for client", client.Name, "is GOOD ", days, "days")
		case days > 0:
			now := time.Now()
			if now.Hour() == 10 && (now.Minute() >= 0 && now.Minute() <= 30) { // Если текущее время между 10:00 и 10:30
				if lastNotification, ok := o.notifiedClients[client.Name]; !ok || lastNotification.Day() != now.Day() { // Если уведомление еще не отправлено или было отправлено в другой день
					// Осталось менее 3 дней до платежа
					logMessage := fmt.Sprintf("Payment for client %s is due soon %d days", client.Name, days)
					messageText := fmt.Sprintf("⚠️ *Клиент*: `%s`*\nОсталось: ⏳ `%d Дня(ей)`*\nПожалуйста, обновите аккаунт! 💼🔐", client.Name, days)
					// Отправляем уведомление
					logAndNotify(o, messageText, logMessage)
					// Обновляем время последнего уведомления
					o.notifiedClients[client.Name] = now
				}
			}
			// Здесь вы можете добавить логику для отправки сообщения в Telegram
		default:
			// The payment is overdue
			err := o.blockClient(client)
			if err != nil {
				log.Println("Error saving client:", err)
				return
			}

			err = o.updateServerConfig()
			if err != nil {
				log.Println(err)
				return
			}

			logMessage := fmt.Sprintf("Payment for client %s is overdue %d days", client.Name, days)
			messageText := fmt.Sprintf("❗️ *Клиент*: `%s`\n⛔️ *Заблокирован из-за неуплаты!* \nПожалуйста, обновите аккаунт! 💼🔐", client.Name)
			logAndNotify(o, messageText, logMessage)
		}
	}
}

func (o *JsonDB) SendTelegramMessage(messageText string) error {
	var (
		ipv4only = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * 8000,
				}
				return d.DialContext(ctx, "udp4", "8.8.8.8:53")
			},
		}

		dialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  ipv4only,
		}

		transport = &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DialContext:       dialer.DialContext,
			ForceAttemptHTTP2: false,
		}

		client = &http.Client{
			Transport: transport,
		}
	)

	globalSettings, err := o.GetGlobalSettings()
	if err != nil {
		return fmt.Errorf("ошибка получения глобальных настроек: %v", err)
	}

	// Создаем нового бота с использованием токена
	bot, err := tgbotapi.NewBotAPIWithClient(globalSettings.TelegramToken, tgbotapi.APIEndpoint, client)
	if err != nil {
		return err
	}

	// Создаем сообщение для отправки
	message := tgbotapi.NewMessage(globalSettings.TelegramChat, messageText) // Отправляем сообщение
	message.ParseMode = "markdown"
	_, err = bot.Send(message)
	if err != nil {
		return err
	}

	return nil
}

func logAndNotify(o *JsonDB, messageText string, logMessage ...interface{}) {
	fmt.Println(logMessage...)
	err := o.SendTelegramMessage(messageText)
	if err != nil {
		log.Println("Ошибка отправки сообщения в Telegram:", err)
	}
}

// Block the client and save changes to the database
func (o *JsonDB) blockClient(client *model.Client) error {
	client.Enabled = false
	return o.SaveClient(*client)
}

// Update the WireGuard server configuration
func (o *JsonDB) updateServerConfig() error {
	// Get the current serverConfig, clientDataList, usersList and globalSettings
	server, err := o.GetServer()
	if err != nil {
		return fmt.Errorf("Cannot get server config: %v", err)
	}
	clientDataList, err := o.GetClients(true)
	if err != nil {
		return fmt.Errorf("Cannot get clients: %v", err)
	}
	usersList, err := o.GetUsers()
	if err != nil {
		return fmt.Errorf("Cannot get users: %v", err)
	}
	globalSettings, err := o.GetGlobalSettings()
	if err != nil {
		return fmt.Errorf("Cannot get global settings: %v", err)
	}

	// Specify the directory with templates
	tmplDir := "templates"
	// Create a fs.FS from tmplDir
	fs := os.DirFS(tmplDir)
	// Call WriteWireGuardServerConfig to update the configuration
	err = util.WriteWireGuardServerConfig(fs, server, clientDataList, usersList, globalSettings)
	if err != nil {
		return fmt.Errorf("Error writing server config: %v", err)
	}

	return nil
}
