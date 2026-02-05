package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// ==========================================
// Constants & Configuration
// ==========================================

const (
	BotConfigFile = "/etc/zivpn/bot-config.json"
	ApiPortFile   = "/etc/zivpn/api_port"
	ApiKeyFile    = "/etc/zivpn/apikey"
	DomainFile    = "/etc/zivpn/domain"
	PortFile      = "/etc/zivpn/port"
)

var ApiUrl = "http://127.0.0.1:8787/api"
var ApiKey = "AutoFtBot-agskjgdvsbdreiWG1234512SDKrqw"

type BotConfig struct {
	BotToken      string `json:"bot_token"`
	AdminID       int64  `json:"admin_id"`
	Mode          string `json:"mode"`
	Domain        string `json:"domain"`
	PakasirSlug   string `json:"pakasir_slug"`
	PakasirApiKey string `json:"pakasir_api_key"`
	DailyPrice    int    `json:"daily_price"`
}

type IpInfo struct {
	City string `json:"city"`
	Isp  string `json:"isp"`
}

type PakasirPayment struct {
	PaymentNumber string `json:"payment_number"`
	ExpiredAt     string `json:"expired_at"`
}

// ==========================================
// Global State
// ==========================================

var (
	userStates     = make(map[int64]string)            // userID -> state
	tempUserData   = make(map[int64]map[string]string) // userID -> temp map
	lastMessageIDs = make(map[int64]int)               // chatID -> msgID
	mutex          = &sync.Mutex{}
)

// ==========================================
// UI THEME (YinnStore VVIP)
// ==========================================

const (
	btnBuy     = "𝘽𝙀𝙇𝙄 𝘼𝙆𝙐𝙉"
	btnTrial   = "𝙏𝙍𝙄𝘼𝙇"
	btnInfo    = "𝙎𝙔𝙎𝙏𝙀𝙈 𝙄𝙉𝙁𝙊"
	btnAdmin   = "𝘼𝘿𝙈𝙄𝙉 𝙋𝘼𝙉𝙀𝙇"
	btnCancel  = "𝘽𝘼𝙏𝘼𝙇"
	btnBack    = "𝙆𝙀𝙈𝘽𝘼𝙇𝙄"
	btnConfirm = "𝙆𝙊𝙉𝙁𝙄𝙍𝙈𝘼𝙎𝙄 𝙊𝙍𝘿𝙀𝙍"

	btnBackup  = "𝘽𝘼𝘾𝙆𝙐𝙋"
	btnRestore = "𝙍𝙀𝙎𝙏𝙊𝙍𝙀"
)

const (
	limitIPDefault = 2
	trialDays      = 1
)

// Telegram MarkdownV2 escape
func mdv2Escape(s string) string {
	replacer := strings.NewReplacer(
		`_`, `\_`,
		`*`, `\*`,
		`[`, `\[`,
		`]`, `\]`,
		`(`, `\(`,
		`)`, `\)`,
		`~`, `\~`,
		"`", "\\`",
		`>`, `\>`,
		`#`, `\#`,
		`+`, `\+`,
		`-`, `\-`,
		`=`, `\=`,
		`|`, `\|`,
		`{`, `\{`,
		`}`, `\}`,
		`.`, `\.`,
		`!`, `\!`,
	)
	return replacer.Replace(s)
}

func codeSpan(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	return "`" + mdv2Escape(s) + "`"
}

func boldV2(s string) string {
	return "*" + mdv2Escape(s) + "*"
}

func moneyIDR(n int) string {
	if n < 0 {
		n = 0
	}
	s := strconv.Itoa(n)
	var out []byte
	cnt := 0
	for i := len(s) - 1; i >= 0; i-- {
		out = append([]byte{s[i]}, out...)
		cnt++
		if cnt%3 == 0 && i != 0 {
			out = append([]byte{','}, out...)
		}
	}
	return string(out)
}

func serverNameFromISP(isp string) string {
	isp = strings.TrimSpace(isp)
	if isp == "" {
		return "ZIVPN"
	}
	isp = strings.Join(strings.Fields(isp), " ")
	if len(isp) > 26 {
		isp = isp[:26]
	}
	return isp
}

func genPassword(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b.WriteByte(chars[idx.Int64()])
	}
	return b.String()
}

// ==========================================
// Main Entry Point
// ==========================================

func main() {
	if keyBytes, err := ioutil.ReadFile(ApiKeyFile); err == nil {
		ApiKey = strings.TrimSpace(string(keyBytes))
	}

	if portBytes, err := ioutil.ReadFile(ApiPortFile); err == nil {
		port := strings.TrimSpace(string(portBytes))
		if port != "" {
			ApiUrl = fmt.Sprintf("http://127.0.0.1:%s/api", port)
		}
	} else {
		if p2, err2 := ioutil.ReadFile(PortFile); err2 == nil {
			port := strings.TrimSpace(string(p2))
			if port != "" {
				ApiUrl = fmt.Sprintf("http://127.0.0.1:%s/api", port)
			}
		}
	}

	config, err := loadConfig()
	if err != nil {
		log.Fatal("Gagal memuat konfigurasi bot:", err)
	}

	bot, err := tgbotapi.NewBotAPI(config.BotToken)
	if err != nil {
		log.Panic(err)
	}
	bot.Debug = false
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	go startPaymentChecker(bot, &config) // 3 detik

	for update := range updates {
		if update.Message != nil {
			handleMessage(bot, update.Message, &config)
		} else if update.CallbackQuery != nil {
			handleCallback(bot, update.CallbackQuery, &config)
		}
	}
}

// ==========================================
// Telegram Event Handlers
// ==========================================

func handleMessage(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, config *BotConfig) {
	userID := msg.From.ID
	chatID := msg.Chat.ID

	if state, exists := userStates[userID]; exists {
		handleState(bot, msg, state, config)
		return
	}

	if msg.Document != nil && userID == config.AdminID {
		if state, exists := userStates[userID]; exists && state == "waiting_restore_file" {
			processRestoreFile(bot, msg, config)
			return
		}
	}

	if msg.IsCommand() {
		switch msg.Command() {
		case "start":
			showMainMenu(bot, chatID, userID, config)
		default:
			replyError(bot, chatID, "Perintah tidak dikenal.")
		}
	}
}

func handleCallback(bot *tgbotapi.BotAPI, query *tgbotapi.CallbackQuery, config *BotConfig) {
	chatID := query.Message.Chat.ID
	userID := query.From.ID

	switch query.Data {

	// MAIN MENU
	case "menu_buy":
		showPriceList(bot, chatID, userID, config, false)

	case "menu_trial":
		showPriceList(bot, chatID, userID, config, true)

	case "menu_info":
		systemInfo(bot, chatID, userID, config)

	case "menu_admin":
		if userID == config.AdminID {
			showBackupRestoreMenu(bot, chatID)
		}

	// BUY FLOW
	case "buy_confirm":
		// baru minta password setelah konfirmasi
		userStates[userID] = "create_password"
		mutex.Lock()
		if _, ok := tempUserData[userID]; !ok {
			tempUserData[userID] = make(map[string]string)
		}
		tempUserData[userID]["chat_id"] = strconv.FormatInt(chatID, 10)
		tempUserData[userID]["is_trial"] = "0"
		mutex.Unlock()

		sendPlain(bot, chatID, "Masukkan Password Baru:")

	// TRIAL FLOW
	case "trial_confirm":
		// trial langsung create (tanpa payment)
		pw := genPassword(8)
		createUser(bot, chatID, pw, trialDays, config)
		// balik menu
		showMainMenu(bot, chatID, userID, config)

	// BACK/CANCEL
	case "cancel":
		cancelOperation(bot, chatID, userID, config)

	case "menu_backup_action":
		if userID == config.AdminID {
			performBackup(bot, chatID)
		}

	case "menu_restore_action":
		if userID == config.AdminID {
			startRestore(bot, chatID, userID)
		}
	}

	_, _ = bot.Request(tgbotapi.NewCallback(query.ID, ""))
}

func handleState(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, state string, config *BotConfig) {
	userID := msg.From.ID
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)

	switch state {
	case "create_password":
		if !validatePassword(bot, chatID, text) {
			return
		}
		mutex.Lock()
		if _, ok := tempUserData[userID]; !ok {
			tempUserData[userID] = make(map[string]string)
		}
		tempUserData[userID]["password"] = text
		mutex.Unlock()

		userStates[userID] = "create_days"
		sendPlain(bot, chatID, fmt.Sprintf("Masukkan Durasi (hari)\nHarga per hari: Rp %s", moneyIDR(config.DailyPrice)))

	case "create_days":
		days, ok := validateNumber(bot, chatID, text, 1, 365, "Durasi")
		if !ok {
			return
		}
		mutex.Lock()
		if _, ok := tempUserData[userID]; !ok {
			tempUserData[userID] = make(map[string]string)
		}
		tempUserData[userID]["days"] = text
		mutex.Unlock()

		processPayment(bot, chatID, userID, days, config)

	case "waiting_restore_file":
		sendPlain(bot, chatID, "Silakan kirim file ZIP backup.")
	}
}

// ==========================================
// Pages
// ==========================================

func showMainMenu(bot *tgbotapi.BotAPI, chatID, userID int64, config *BotConfig) {
	ipInfo, _ := getIpInfo()

	domain := config.Domain
	if domain == "" {
		if b, err := ioutil.ReadFile(DomainFile); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				domain = s
			}
		}
	}
	if domain == "" {
		domain = "(Not Configured)"
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	serverName := serverNameFromISP(ipInfo.Isp)

	text := ""
	text += boldV2("YINN STORE ZIVPN") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Domain      : " + codeSpan(domain) + "\n"
	text += "Server      : " + codeSpan(serverName) + "\n"
	text += "Harga/Hari   : " + codeSpan("Rp "+moneyIDR(config.DailyPrice)) + "\n"
	text += "Waktu        : " + codeSpan(now) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"

	kb := [][]tgbotapi.InlineKeyboardButton{
		{
			tgbotapi.NewInlineKeyboardButtonData(btnBuy, "menu_buy"),
			tgbotapi.NewInlineKeyboardButtonData(btnTrial, "menu_trial"),
		},
	}

	if userID == config.AdminID {
		kb = append(kb,
			[]tgbotapi.InlineKeyboardButton{tgbotapi.NewInlineKeyboardButtonData(btnInfo, "menu_info")},
			[]tgbotapi.InlineKeyboardButton{tgbotapi.NewInlineKeyboardButtonData(btnAdmin, "menu_admin")},
		)
	}

	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(kb...)
	sendAndTrack(bot, msg)
}

func showPriceList(bot *tgbotapi.BotAPI, chatID, userID int64, config *BotConfig, isTrial bool) {
	ipInfo, _ := getIpInfo()
	serverName := serverNameFromISP(ipInfo.Isp)

	daily := config.DailyPrice
	h30 := daily * 30

	title := "Daftar Dan Harga Akun ZIVPN"
	if isTrial {
		title = "Informasi Trial ZIVPN"
	}

	text := ""
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += " " + mdv2Escape(title) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Nama Server  : " + codeSpan(serverName) + "\n"

	if isTrial {
		text += "Durasi       : " + codeSpan(fmt.Sprintf("%d hari", trialDays)) + "\n"
		text += "Limit IP     : " + codeSpan(fmt.Sprintf("%d", limitIPDefault)) + "\n"
		text += "────────────────────────────\n"
		text += "Password akan dibuat otomatis.\n"
	} else {
		text += "Harga 30 Hari : " + codeSpan("Rp "+moneyIDR(h30)) + "\n"
		text += "Harga Per Hari: " + codeSpan("Rp "+moneyIDR(daily)) + "\n"
		text += "Limit IP      : " + codeSpan(fmt.Sprintf("%d", limitIPDefault)) + "\n"
		text += "────────────────────────────\n"
		text += "Tekan konfirmasi untuk lanjut.\n"
	}

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"

	if isTrial {
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(btnConfirm, "trial_confirm"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(btnBack, "cancel"),
			),
		)
	} else {
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(btnConfirm, "buy_confirm"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(btnBack, "cancel"),
			),
		)
	}

	sendAndTrack(bot, msg)
}

// ==========================================
// Feature Implementation
// ==========================================

func processPayment(bot *tgbotapi.BotAPI, chatID, userID int64, days int, config *BotConfig) {
	// guard config
	if strings.TrimSpace(config.PakasirSlug) == "" || strings.TrimSpace(config.PakasirApiKey) == "" || config.DailyPrice <= 0 {
		sendPlain(bot, chatID, "Payment belum diset admin. Hubungi admin untuk set Pakasir & harga.")
		resetState(userID)
		return
	}

	price := days * config.DailyPrice
	if price < 500 {
		sendPlain(bot, chatID, fmt.Sprintf("Total harga Rp %s. Minimal transaksi Rp 500. Tambah durasi.", moneyIDR(price)))
		return
	}

	orderID := fmt.Sprintf("ZIVPN-%d-%d", userID, time.Now().Unix())

	payment, err := createPakasirTransaction(config, orderID, price)
	if err != nil {
		replyError(bot, chatID, "Gagal membuat pembayaran: "+err.Error())
		resetState(userID)
		return
	}

	mutex.Lock()
	if _, ok := tempUserData[userID]; !ok {
		tempUserData[userID] = make(map[string]string)
	}
	tempUserData[userID]["order_id"] = orderID
	tempUserData[userID]["price"] = strconv.Itoa(price)
	tempUserData[userID]["chat_id"] = strconv.FormatInt(chatID, 10)
	mutex.Unlock()

	qrUrl := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=%s", payment.PaymentNumber)

	mutex.Lock()
	pw := tempUserData[userID]["password"]
	mutex.Unlock()

	caption := ""
	caption += boldV2("TAGIHAN PEMBAYARAN") + "\n"
	caption += "━━━━━━━━━━━━━━━━━━━━━━\n"
	caption += "Password : " + codeSpan(pw) + "\n"
	caption += "Durasi   : " + codeSpan(fmt.Sprintf("%d hari", days)) + "\n"
	caption += "Total    : " + codeSpan("Rp "+moneyIDR(price)) + "\n"
	caption += "Expired  : " + codeSpan(payment.ExpiredAt) + "\n"
	caption += "━━━━━━━━━━━━━━━━━━━━━━\n"
	caption += "Auto cek: " + codeSpan("3 detik") + "\n"

	photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileURL(qrUrl))
	photo.Caption = caption
	photo.ParseMode = "MarkdownV2"
	photo.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnCancel, "cancel"),
		),
	)

	deleteLastMessage(bot, chatID)
	sentMsg, err := bot.Send(photo)
	if err == nil {
		lastMessageIDs[chatID] = sentMsg.MessageID
	}

	// tunggu checker
	delete(userStates, userID)
}

func startPaymentChecker(bot *tgbotapi.BotAPI, config *BotConfig) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		mutex.Lock()
		ids := make([]int64, 0, len(tempUserData))
		for userID, data := range tempUserData {
			if _, ok := data["order_id"]; ok {
				ids = append(ids, userID)
			}
		}
		mutex.Unlock()

		for _, userID := range ids {
			mutex.Lock()
			data, ok := tempUserData[userID]
			if !ok {
				mutex.Unlock()
				continue
			}
			orderID := data["order_id"]
			price := data["price"]
			chatIDStr := data["chat_id"]
			password := data["password"]
			daysStr := data["days"]
			mutex.Unlock()

			if orderID == "" || price == "" || chatIDStr == "" {
				continue
			}

			chatID, _ := strconv.ParseInt(chatIDStr, 10, 64)
			status, err := checkPakasirStatus(config, orderID, price)
			if err != nil {
				continue
			}

			if status == "completed" || status == "success" {
				days, _ := strconv.Atoi(daysStr)
				createUser(bot, chatID, password, days, config)

				mutex.Lock()
				delete(tempUserData, userID)
				delete(userStates, userID)
				mutex.Unlock()
			}
		}
	}
}

func createUser(bot *tgbotapi.BotAPI, chatID int64, password string, days int, config *BotConfig) {
	res, err := apiCall("POST", "/user/create", map[string]interface{}{
		"password": password,
		"days":     days,
	})
	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data, _ := res["data"].(map[string]interface{})
		sendAccountInfo(bot, chatID, data, config)
	} else {
		replyError(bot, chatID, fmt.Sprintf("Gagal membuat akun: %v", res["message"]))
	}
}

// ==========================================
// Pakasir API
// ==========================================

func createPakasirTransaction(config *BotConfig, orderID string, amount int) (*PakasirPayment, error) {
	url := "https://app.pakasir.com/api/transactioncreate/qris"
	payload := map[string]interface{}{
		"project":  config.PakasirSlug,
		"order_id": orderID,
		"amount":   amount,
		"api_key":  config.PakasirApiKey,
	}

	jsonPayload, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if paymentData, ok := result["payment"].(map[string]interface{}); ok {
		pn, _ := paymentData["payment_number"].(string)
		ea, _ := paymentData["expired_at"].(string)
		if pn == "" {
			return nil, fmt.Errorf("invalid response from Pakasir (payment_number kosong)")
		}
		return &PakasirPayment{PaymentNumber: pn, ExpiredAt: ea}, nil
	}
	return nil, fmt.Errorf("invalid response from Pakasir")
}

func checkPakasirStatus(config *BotConfig, orderID string, amountStr string) (string, error) {
	url := fmt.Sprintf(
		"https://app.pakasir.com/api/transactiondetail?project=%s&amount=%s&order_id=%s&api_key=%s",
		config.PakasirSlug, amountStr, orderID, config.PakasirApiKey,
	)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if transaction, ok := result["transaction"].(map[string]interface{}); ok {
		st, _ := transaction["status"].(string)
		if st == "" {
			return "", fmt.Errorf("status kosong")
		}
		return st, nil
	}
	return "", fmt.Errorf("transaction not found")
}

// ==========================================
// Admin / Backup Restore
// ==========================================

func showBackupRestoreMenu(bot *tgbotapi.BotAPI, chatID int64) {
	text := ""
	text += boldV2("ADMIN PANEL") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Backup / Restore\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBackup, "menu_backup_action"),
			tgbotapi.NewInlineKeyboardButtonData(btnRestore, "menu_restore_action"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBack, "cancel"),
		),
	)
	sendAndTrack(bot, msg)
}

func performBackup(bot *tgbotapi.BotAPI, chatID int64) {
	sendPlain(bot, chatID, "Sedang membuat backup...")

	files := []string{
		"/etc/zivpn/config.json",
		"/etc/zivpn/users.json",
		"/etc/zivpn/domain",
		"/etc/zivpn/bot-config.json",
		"/etc/zivpn/apikey",
		"/etc/zivpn/api_port",
	}

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		func() {
			defer f.Close()
			w, err := zipWriter.Create(filepath.Base(file))
			if err != nil {
				return
			}
			_, _ = io.Copy(w, f)
		}()
	}
	_ = zipWriter.Close()

	fileName := fmt.Sprintf("zivpn-backup-%s.zip", time.Now().Format("20060102-150405"))
	tmpFile := "/tmp/" + fileName
	if err := ioutil.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		replyError(bot, chatID, "Gagal membuat file backup.")
		return
	}
	defer os.Remove(tmpFile)

	doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(tmpFile))
	doc.Caption = "Backup Berhasil"
	deleteLastMessage(bot, chatID)
	_, _ = bot.Send(doc)
}

func startRestore(bot *tgbotapi.BotAPI, chatID int64, userID int64) {
	userStates[userID] = "waiting_restore_file"
	sendPlain(bot, chatID, "Kirim file ZIP backup sekarang. Data akan ditimpa.")
}

func processRestoreFile(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, config *BotConfig) {
	chatID := msg.Chat.ID
	userID := msg.From.ID

	resetState(userID)
	sendPlain(bot, chatID, "Memproses file...")

	fileID := msg.Document.FileID
	file, err := bot.GetFile(tgbotapi.FileConfig{FileID: fileID})
	if err != nil {
		replyError(bot, chatID, "Gagal mengunduh file.")
		return
	}

	fileUrl := file.Link(config.BotToken)
	resp, err := http.Get(fileUrl)
	if err != nil {
		replyError(bot, chatID, "Gagal download content.")
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		replyError(bot, chatID, "Gagal baca file.")
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		replyError(bot, chatID, "File bukan ZIP valid.")
		return
	}

	validFiles := map[string]bool{
		"config.json":     true,
		"users.json":      true,
		"bot-config.json": true,
		"domain":          true,
		"apikey":          true,
		"api_port":        true,
		"port":            true,
	}

	for _, f := range zipReader.File {
		if !validFiles[f.Name] {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}

		dstPath := filepath.Join("/etc/zivpn", f.Name)
		dst, err := os.Create(dstPath)
		if err != nil {
			_ = rc.Close()
			continue
		}

		_, _ = io.Copy(dst, rc)
		_ = dst.Close()
		_ = rc.Close()
	}

	_ = exec.Command("systemctl", "restart", "zivpn").Run()
	_ = exec.Command("systemctl", "restart", "zivpn-api").Run()
	_, _ = bot.Send(tgbotapi.NewMessage(chatID, "Restore selesai. Service direstart."))

	go func() {
		time.Sleep(2 * time.Second)
		_ = exec.Command("systemctl", "restart", "zivpn-bot").Run()
	}()

	showMainMenu(bot, chatID, config.AdminID, config)
}

// ==========================================
// UI helpers
// ==========================================

func sendAndTrack(bot *tgbotapi.BotAPI, msg tgbotapi.MessageConfig) {
	deleteLastMessage(bot, msg.ChatID)
	sentMsg, err := bot.Send(msg)
	if err == nil {
		lastMessageIDs[msg.ChatID] = sentMsg.MessageID
	}
}

func deleteLastMessage(bot *tgbotapi.BotAPI, chatID int64) {
	if msgID, ok := lastMessageIDs[chatID]; ok {
		_, _ = bot.Request(tgbotapi.NewDeleteMessage(chatID, msgID))
		delete(lastMessageIDs, chatID)
	}
}

func sendPlain(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	deleteLastMessage(bot, chatID)
	sent, err := bot.Send(msg)
	if err == nil {
		lastMessageIDs[chatID] = sent.MessageID
	}
}

func replyError(bot *tgbotapi.BotAPI, chatID int64, text string) {
	sendPlain(bot, chatID, "Error: "+text)
}

func cancelOperation(bot *tgbotapi.BotAPI, chatID, userID int64, config *BotConfig) {
	mutex.Lock()
	delete(userStates, userID)
	delete(tempUserData, userID)
	mutex.Unlock()
	showMainMenu(bot, chatID, userID, config)
}

func resetState(userID int64) {
	mutex.Lock()
	delete(userStates, userID)
	mutex.Unlock()
}

// ==========================================
// Validators
// ==========================================

func validatePassword(bot *tgbotapi.BotAPI, chatID int64, text string) bool {
	if len(text) < 3 || len(text) > 20 {
		sendPlain(bot, chatID, "Password harus 3-20 karakter. Coba lagi.")
		return false
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(text) {
		sendPlain(bot, chatID, "Password hanya boleh huruf, angka, - dan _. Coba lagi.")
		return false
	}
	return true
}

func validateNumber(bot *tgbotapi.BotAPI, chatID int64, text string, min, max int, fieldName string) (int, bool) {
	val, err := strconv.Atoi(text)
	if err != nil || val < min || val > max {
		sendPlain(bot, chatID, fmt.Sprintf("%s harus angka (%d-%d). Coba lagi.", fieldName, min, max))
		return 0, false
	}
	return val, true
}

// ==========================================
// System Info
// ==========================================

func systemInfo(bot *tgbotapi.BotAPI, chatID, userID int64, config *BotConfig) {
	res, err := apiCall("GET", "/info", nil)
	if err != nil {
		replyError(bot, chatID, "API: "+err.Error())
		return
	}

	if res["success"] == true {
		data, _ := res["data"].(map[string]interface{})
		ipInfo, _ := getIpInfo()

		text := ""
		text += boldV2("SYSTEM INFO") + "\n"
		text += "━━━━━━━━━━━━━━━━━━━━━━\n"
		text += "Domain    : " + codeSpan(config.Domain) + "\n"
		text += "Public IP : " + codeSpan(fmt.Sprintf("%v", data["public_ip"])) + "\n"
		text += "Port      : " + codeSpan(fmt.Sprintf("%v", data["port"])) + "\n"
		text += "Service   : " + codeSpan(fmt.Sprintf("%v", data["service"])) + "\n"
		text += "City      : " + codeSpan(ipInfo.City) + "\n"
		text += "ISP       : " + codeSpan(ipInfo.Isp) + "\n"
		text += "━━━━━━━━━━━━━━━━━━━━━━\n"

		reply := tgbotapi.NewMessage(chatID, text)
		reply.ParseMode = "MarkdownV2"
		sendAndTrack(bot, reply)

		showMainMenu(bot, chatID, userID, config)
		return
	}

	replyError(bot, chatID, "Gagal ambil info.")
}

// ==========================================
// Config & API Helpers
// ==========================================

func loadConfig() (BotConfig, error) {
	var config BotConfig
	file, err := ioutil.ReadFile(BotConfigFile)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(file, &config)

	if config.Domain == "" {
		if domainBytes, err2 := ioutil.ReadFile(DomainFile); err2 == nil {
			config.Domain = strings.TrimSpace(string(domainBytes))
		}
	}

	return config, err
}

func apiCall(method, endpoint string, payload interface{}) (map[string]interface{}, error) {
	var reqBody []byte
	var err error

	if payload != nil {
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	client := &http.Client{Timeout: 25 * time.Second}
	req, err := http.NewRequest(method, ApiUrl+endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", ApiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	_ = json.Unmarshal(body, &result)

	return result, nil
}

func getIpInfo() (IpInfo, error) {
	resp, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return IpInfo{}, err
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return IpInfo{}, err
	}

	info := IpInfo{}
	if v, ok := raw["city"].(string); ok {
		info.City = v
	}
	if v, ok := raw["isp"].(string); ok {
		info.Isp = v
	}
	return info, nil
}

func sendAccountInfo(bot *tgbotapi.BotAPI, chatID int64, data map[string]interface{}, config *BotConfig) {
	domain := config.Domain
	if domain == "" {
		domain = "(Not Configured)"
	}

	pw := fmt.Sprintf("%v", data["password"])
	exp := fmt.Sprintf("%v", data["expired"])

	text := ""
	text += boldV2("ACCOUNT AKTIF") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Password : " + codeSpan(pw) + "\n"
	text += "Domain   : " + codeSpan(domain) + "\n"
	text += "Expired  : " + codeSpan(exp) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"
	sendAndTrack(bot, msg)
}