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
// Files
// ==========================================

const (
	BotConfigFile = "/etc/zivpn/bot-config.json"
	ApiPortFile   = "/etc/zivpn/api_port"
	ApiKeyFile    = "/etc/zivpn/apikey"
	DomainFile    = "/etc/zivpn/domain"
	PortFile      = "/etc/zivpn/port"
)

// ==========================================
// Globals
// ==========================================

var (
	ApiUrl = "http://127.0.0.1:8787/api"
	ApiKey = "AutoFtBot-agskjgdvsbdreiWG1234512SDKrqw"

	mutex          = &sync.Mutex{}
	userStates     = make(map[int64]string)            // userID -> state
	tempUserData   = make(map[int64]map[string]string) // userID -> temp
	lastMessageIDs = make(map[int64]int)               // chatID -> msgID
)

// ==========================================
// Models
// ==========================================

type BotConfig struct {
	BotToken      string `json:"bot_token"`
	AdminID       int64  `json:"admin_id"`
	Mode          string `json:"mode"` // public/private
	Domain        string `json:"domain"`
	PakasirSlug   string `json:"pakasir_slug"`
	PakasirApiKey string `json:"pakasir_api_key"`
	DailyPrice    int    `json:"daily_price"`
}

type IpInfo struct {
	City  string `json:"city"`
	Isp   string `json:"isp"`
	Query string `json:"query"`
}

type UserData struct {
	Password string `json:"password"`
	Expired  string `json:"expired"`
	Status   string `json:"status"`
	IpLimit  int    `json:"ip_limit"`
}

type PakasirPayment struct {
	PaymentNumber string `json:"payment_number"`
	ExpiredAt     string `json:"expired_at"`
}

// ==========================================
// UI Labels (KEEP EMOJI)
// ==========================================

const (
	btnBuy     = "🛒 𝘽𝙀𝙇𝙄 𝘼𝙆𝙐𝙉"
	btnTrial   = "🎁 𝙏𝙍𝙄𝘼𝙇"
	btnInfo    = "📊 𝙎𝙔𝙎𝙏𝙀𝙈 𝙄𝙉𝙁𝙊"
	btnAdmin   = "🛠️ 𝘼𝘿𝙈𝙄𝙉 𝙋𝘼𝙉𝙀𝙇"
	btnBack    = "⬅️ 𝙆𝙀𝙈𝘽𝘼𝙇𝙄"
	btnCancel  = "❌ 𝘽𝘼𝙏𝘼𝙇"
	btnConfirm = "✅ 𝙆𝙊𝙉𝙁𝙄𝙍𝙈𝘼𝙎𝙄 𝙊𝙍𝘿𝙀𝙍"

	btnUsers    = "👥 𝙐𝙎𝙀𝙍 𝙈𝘼𝙉𝘼𝙂𝙀𝙍"
	btnPaySet   = "💳 𝙋𝘼𝙔𝙈𝙀𝙉𝙏 𝙎𝙀𝙏𝙏𝙄𝙉𝙂"
	btnBackup   = "⬇️ 𝘽𝘼𝘾𝙆𝙐𝙋"
	btnRestore  = "⬆️ 𝙍𝙀𝙎𝙏𝙊𝙍𝙀"
	btnMode     = "🔐 𝙈𝙊𝘿𝙀"
	btnSetSlug  = "🏷️ 𝙎𝙀𝙏 𝙋𝘼𝙆𝘼𝙎𝙄𝙍 𝙎𝙇𝙐𝙂"
	btnSetKey   = "🔑 𝙎𝙀𝙏 𝙋𝘼𝙆𝘼𝙎𝙄𝙍 𝘼𝙋𝙄 𝙆𝙀𝙔"
	btnSetPrice = "💰 𝙎𝙀𝙏 𝙃𝘼𝙍𝙂𝘼/𝙃𝘼𝙍𝙄"
	btnTestPay  = "🧪 𝙏𝙀𝙎𝙏 𝙋𝘼𝙆𝘼𝙎𝙄𝙍"

	btnCreateUser = "➕ 𝘾𝙍𝙀𝘼𝙏𝙀"
	btnRenewUser  = "🔄 𝙍𝙀𝙉𝙀𝙒"
	btnDeleteUser = "🗑️ 𝘿𝙀𝙇𝙀𝙏𝙀"
	btnListUser   = "📋 𝙇𝙄𝙎𝙏"
)

const (
	limitIPDefault = 2
	trialDays      = 1
)

// ==========================================
// MarkdownV2 Helpers
// ==========================================

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

func genPassword(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b.WriteByte(chars[idx.Int64()])
	}
	return b.String()
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

// ==========================================
// Main
// ==========================================

func main() {
	// API KEY
	if keyBytes, err := ioutil.ReadFile(ApiKeyFile); err == nil {
		ApiKey = strings.TrimSpace(string(keyBytes))
	}

	// API PORT
	if portBytes, err := ioutil.ReadFile(ApiPortFile); err == nil {
		port := strings.TrimSpace(string(portBytes))
		if port != "" {
			ApiUrl = fmt.Sprintf("http://127.0.0.1:%s/api", port)
		}
	} else {
		// fallback
		if p2, err2 := ioutil.ReadFile(PortFile); err2 == nil {
			port := strings.TrimSpace(string(p2))
			if port != "" {
				ApiUrl = fmt.Sprintf("http://127.0.0.1:%s/api", port)
			}
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal("Gagal memuat konfigurasi bot:", err)
	}

	bot, err := tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		log.Panic(err)
	}
	bot.Debug = false
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	go startPaymentChecker(bot, &cfg)

	for update := range updates {
		if update.Message != nil {
			handleMessage(bot, update.Message, &cfg)
		} else if update.CallbackQuery != nil {
			handleCallback(bot, update.CallbackQuery, &cfg)
		}
	}
}

// ==========================================
// Handlers
// ==========================================

func handleMessage(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, cfg *BotConfig) {
	userID := msg.From.ID
	chatID := msg.Chat.ID

	// access control
	if cfg.Mode == "private" && userID != cfg.AdminID {
		sendPlain(bot, chatID, "⛔ Akses Ditolak. Bot ini Private.")
		return
	}

	// restore file upload
	if msg.Document != nil && userID == cfg.AdminID {
		if state, ok := userStates[userID]; ok && state == "waiting_restore_file" {
			processRestoreFile(bot, msg, cfg)
			return
		}
	}

	// state handler
	if state, ok := userStates[userID]; ok {
		handleState(bot, msg, state, cfg)
		return
	}

	if msg.IsCommand() {
		switch msg.Command() {
		case "start":
			showMainMenu(bot, chatID, userID, cfg)
		default:
			sendPlain(bot, chatID, "❌ Perintah tidak dikenal.")
		}
	}
}

func handleCallback(bot *tgbotapi.BotAPI, q *tgbotapi.CallbackQuery, cfg *BotConfig) {
	chatID := q.Message.Chat.ID
	userID := q.From.ID
	data := q.Data

	// access control
	if cfg.Mode == "private" && userID != cfg.AdminID {
		_, _ = bot.Request(tgbotapi.NewCallback(q.ID, "Akses ditolak"))
		return
	}

	switch {
	// MAIN MENU
	case data == "menu_buy":
		showPriceList(bot, chatID, userID, cfg, false)
	case data == "menu_trial":
		showPriceList(bot, chatID, userID, cfg, true)
	case data == "menu_info":
		systemInfo(bot, chatID, userID, cfg)
	case data == "menu_admin":
		if userID == cfg.AdminID {
			showAdminMenu(bot, chatID, userID, cfg)
		}

	// BUY FLOW
	case data == "buy_confirm":
		mutex.Lock()
		if _, ok := tempUserData[userID]; !ok {
			tempUserData[userID] = make(map[string]string)
		}
		tempUserData[userID]["chat_id"] = strconv.FormatInt(chatID, 10)
		tempUserData[userID]["is_trial"] = "0"
		mutex.Unlock()

		userStates[userID] = "buy_password"
		sendPlain(bot, chatID, "🔐 Masukkan Password Baru:")

	// TRIAL FLOW
	case data == "trial_confirm":
		pw := genPassword(8)
		createUser(bot, chatID, pw, trialDays, cfg)
		showMainMenu(bot, chatID, userID, cfg)

	// ADMIN PANEL NAV
	case data == "admin_users":
		if userID == cfg.AdminID {
			showAdminUsersMenu(bot, chatID, userID, cfg)
		}
	case data == "admin_payment":
		if userID == cfg.AdminID {
			showAdminPaymentMenu(bot, chatID, userID, cfg)
		}
	case data == "admin_backup":
		if userID == cfg.AdminID {
			performBackup(bot, chatID)
		}
	case data == "admin_restore":
		if userID == cfg.AdminID {
			startRestore(bot, chatID, userID)
		}
	case data == "admin_mode":
		if userID == cfg.AdminID {
			toggleMode(bot, chatID, userID, cfg)
		}

	// PAYMENT SETTINGS
	case data == "pay_set_slug":
		if userID == cfg.AdminID {
			userStates[userID] = "admin_set_slug"
			sendPlain(bot, chatID, "🏷️ Masukkan Pakasir Project Slug:")
		}
	case data == "pay_set_key":
		if userID == cfg.AdminID {
			userStates[userID] = "admin_set_key"
			sendPlain(bot, chatID, "🔑 Masukkan Pakasir API Key:")
		}
	case data == "pay_set_price":
		if userID == cfg.AdminID {
			userStates[userID] = "admin_set_price"
			sendPlain(bot, chatID, "💰 Masukkan Harga Per Hari (angka, IDR):")
		}
	case data == "pay_test":
		if userID == cfg.AdminID {
			testPakasir(bot, chatID, cfg)
		}

	// USER MANAGER
	case data == "um_create":
		if userID == cfg.AdminID {
			userStates[userID] = "admin_create_password"
			sendPlain(bot, chatID, "➕ Create (Admin)\n\nMasukkan Password:")
		}
	case data == "um_list":
		if userID == cfg.AdminID {
			listUsers(bot, chatID, cfg)
		}
	case data == "um_renew":
		if userID == cfg.AdminID {
			showUserSelection(bot, chatID, 1, "renew")
		}
	case data == "um_delete":
		if userID == cfg.AdminID {
			showUserSelection(bot, chatID, 1, "delete")
		}

	// PAGINATION & SELECTION
	case strings.HasPrefix(data, "page_"):
		if userID == cfg.AdminID {
			handlePagination(bot, chatID, data)
		}
	case strings.HasPrefix(data, "select_renew:"):
		if userID == cfg.AdminID {
			startRenewUser(bot, chatID, userID, data)
		}
	case strings.HasPrefix(data, "select_delete:"):
		if userID == cfg.AdminID {
			confirmDeleteUser(bot, chatID, data)
		}
	case strings.HasPrefix(data, "confirm_delete:"):
		if userID == cfg.AdminID {
			username := strings.TrimPrefix(data, "confirm_delete:")
			deleteUser(bot, chatID, username, cfg)
		}

	// BACK / CANCEL
	case data == "cancel":
		cancelOperation(bot, chatID, userID, cfg)
	case data == "back_main":
		showMainMenu(bot, chatID, userID, cfg)
	case data == "back_admin":
		if userID == cfg.AdminID {
			showAdminMenu(bot, chatID, userID, cfg)
		}
	case data == "back_admin_users":
		if userID == cfg.AdminID {
			showAdminUsersMenu(bot, chatID, userID, cfg)
		}
	case data == "back_admin_payment":
		if userID == cfg.AdminID {
			showAdminPaymentMenu(bot, chatID, userID, cfg)
		}
	}

	_, _ = bot.Request(tgbotapi.NewCallback(q.ID, ""))
}

func handleState(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, state string, cfg *BotConfig) {
	userID := msg.From.ID
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)

	switch state {

	// BUY FLOW (PUBLIC)
	case "buy_password":
		if !validatePassword(bot, chatID, text) {
			return
		}
		mutex.Lock()
		if _, ok := tempUserData[userID]; !ok {
			tempUserData[userID] = make(map[string]string)
		}
		tempUserData[userID]["password"] = text
		mutex.Unlock()

		userStates[userID] = "buy_days"
		sendPlain(bot, chatID, fmt.Sprintf("⏳ Masukkan Durasi (hari)\nHarga per hari: Rp %s", moneyIDR(cfg.DailyPrice)))

	case "buy_days":
		days, ok := validateNumber(bot, chatID, text, 1, 365, "Durasi")
		if !ok {
			return
		}
		mutex.Lock()
		tempUserData[userID]["days"] = strconv.Itoa(days)
		mutex.Unlock()

		processPayment(bot, chatID, userID, days, cfg)
		// state selesai, tunggu payment checker (state dihapus oleh processPayment)

	// ADMIN CREATE
	case "admin_create_password":
		if !validatePassword(bot, chatID, text) {
			return
		}
		mutex.Lock()
		if _, ok := tempUserData[userID]; !ok {
			tempUserData[userID] = make(map[string]string)
		}
		tempUserData[userID]["password"] = text
		mutex.Unlock()

		userStates[userID] = "admin_create_days"
		sendPlain(bot, chatID, "⏳ Masukkan Durasi (hari):")

	case "admin_create_days":
		days, ok := validateNumber(bot, chatID, text, 1, 3650, "Durasi")
		if !ok {
			return
		}
		mutex.Lock()
		pw := tempUserData[userID]["password"]
		mutex.Unlock()

		createUser(bot, chatID, pw, days, cfg)
		resetAllState(userID)
		showAdminUsersMenu(bot, chatID, userID, cfg)

	// ADMIN RENEW INPUT
	case "renew_days":
		days, ok := validateNumber(bot, chatID, text, 1, 3650, "Durasi")
		if !ok {
			return
		}
		mutex.Lock()
		username := tempUserData[userID]["username"]
		mutex.Unlock()

		renewUser(bot, chatID, username, days, cfg)
		resetAllState(userID)
		showAdminUsersMenu(bot, chatID, userID, cfg)

	// ADMIN PAYMENT SETTINGS
	case "admin_set_slug":
		text = strings.TrimSpace(text)
		if text == "" {
			sendPlain(bot, chatID, "❌ Slug tidak boleh kosong. Coba lagi:")
			return
		}
		cfg.PakasirSlug = text
		_ = saveConfig(cfg)
		resetAllState(userID)
		sendPlain(bot, chatID, "✅ Pakasir Slug tersimpan.")
		showAdminPaymentMenu(bot, chatID, userID, cfg)

	case "admin_set_key":
		text = strings.TrimSpace(text)
		if text == "" {
			sendPlain(bot, chatID, "❌ API Key tidak boleh kosong. Coba lagi:")
			return
		}
		cfg.PakasirApiKey = text
		_ = saveConfig(cfg)
		resetAllState(userID)
		sendPlain(bot, chatID, "✅ Pakasir API Key tersimpan.")
		showAdminPaymentMenu(bot, chatID, userID, cfg)

	case "admin_set_price":
		val, err := strconv.Atoi(strings.ReplaceAll(text, ",", ""))
		if err != nil || val < 0 {
			sendPlain(bot, chatID, "❌ Harga harus angka >= 0. Coba lagi:")
			return
		}
		cfg.DailyPrice = val
		_ = saveConfig(cfg)
		resetAllState(userID)
		sendPlain(bot, chatID, "✅ Harga per hari tersimpan.")
		showAdminPaymentMenu(bot, chatID, userID, cfg)

	case "waiting_restore_file":
		sendPlain(bot, chatID, "⬆️ Kirim file ZIP backup sekarang.")
	}
}

// ==========================================
// Pages
// ==========================================

func showMainMenu(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig) {
	ipInfo, _ := getIpInfo()

	domain := cfg.Domain
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
	text += boldV2("🟠 𝙔𝙄𝙉𝙉 𝙎𝙏𝙊𝙍𝙀 𝙕𝙄𝙑𝙋𝙉") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "📁 Server     : " + codeSpan(serverName) + "\n"
	text += "🌐 Domain     : " + codeSpan(domain) + "\n"
	text += "💸 Harga/Hari  : " + codeSpan("Rp "+moneyIDR(cfg.DailyPrice)) + "\n"
	text += "⏱ Time       : " + codeSpan(now) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"

	kb := [][]tgbotapi.InlineKeyboardButton{
		{
			tgbotapi.NewInlineKeyboardButtonData(btnBuy, "menu_buy"),
			tgbotapi.NewInlineKeyboardButtonData(btnTrial, "menu_trial"),
		},
	}
	kb = append(kb, []tgbotapi.InlineKeyboardButton{
		tgbotapi.NewInlineKeyboardButtonData(btnInfo, "menu_info"),
	})

	if userID == cfg.AdminID {
		kb = append(kb, []tgbotapi.InlineKeyboardButton{
			tgbotapi.NewInlineKeyboardButtonData(btnAdmin, "menu_admin"),
		})
	}

	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(kb...)
	sendAndTrack(bot, msg)
}

func showPriceList(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig, isTrial bool) {
	ipInfo, _ := getIpInfo()
	serverName := serverNameFromISP(ipInfo.Isp)

	daily := cfg.DailyPrice
	h30 := daily * 30

	title := "📖 Daftar Dan Harga Akun ZIVPN"
	if isTrial {
		title = "📖 Informasi Trial Akun ZIVPN"
	}

	text := ""
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += mdv2Escape(title) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "📁 Nama Server : " + codeSpan(serverName) + "\n"

	if isTrial {
		text += "🕒 Durasi      : " + codeSpan(fmt.Sprintf("%d hari", trialDays)) + "\n"
		text += "📱 Limit IP    : " + codeSpan(fmt.Sprintf("%d", limitIPDefault)) + "\n"
		text += "────────────────────────────\n"
		text += "Password dibuat otomatis.\n"
	} else {
		text += "💵 Harga 30 Hari : " + codeSpan("Rp "+moneyIDR(h30)) + "\n"
		text += "💸 Harga Per Hari: " + codeSpan("Rp "+moneyIDR(daily)) + "\n"
		text += "📱 Limit IP      : " + codeSpan(fmt.Sprintf("%d", limitIPDefault)) + "\n"
		text += "────────────────────────────\n"
		text += "Klik konfirmasi untuk lanjut.\n"
	}

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"

	if isTrial {
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnConfirm, "trial_confirm")),
			tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnBack, "back_main")),
		)
	} else {
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnConfirm, "buy_confirm")),
			tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnBack, "back_main")),
		)
	}

	sendAndTrack(bot, msg)
}

// ==========================================
// Admin Menus (SUBMENU)
// ==========================================

func showAdminMenu(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig) {
	modeText := "private"
	if strings.ToLower(cfg.Mode) == "public" {
		modeText = "public"
	}

	text := ""
	text += boldV2("🛠️ 𝘼𝘿𝙈𝙄𝙉 𝙋𝘼𝙉𝙀𝙇") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Mode         : " + codeSpan(modeText) + "\n"
	text += "Harga/Hari    : " + codeSpan("Rp "+moneyIDR(cfg.DailyPrice)) + "\n"
	text += "Pakasir Slug  : " + codeSpan(maskShort(cfg.PakasirSlug)) + "\n"
	text += "Pakasir Key   : " + codeSpan(maskKey(cfg.PakasirApiKey)) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnUsers, "admin_users")),
		tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnPaySet, "admin_payment")),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBackup, "admin_backup"),
			tgbotapi.NewInlineKeyboardButtonData(btnRestore, "admin_restore"),
		),
		tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnMode, "admin_mode")),
		tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnBack, "back_main")),
	)
	sendAndTrack(bot, msg)
}

func showAdminPaymentMenu(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig) {
	text := ""
	text += boldV2("💳 𝙋𝘼𝙔𝙈𝙀𝙉𝙏 𝙎𝙀𝙏𝙏𝙄𝙉𝙂") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Pakasir Slug : " + codeSpan(maskShort(cfg.PakasirSlug)) + "\n"
	text += "Pakasir Key  : " + codeSpan(maskKey(cfg.PakasirApiKey)) + "\n"
	text += "Harga/Hari   : " + codeSpan("Rp "+moneyIDR(cfg.DailyPrice)) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnSetSlug, "pay_set_slug"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnSetKey, "pay_set_key"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnSetPrice, "pay_set_price"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnTestPay, "pay_test"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBack, "back_admin"),
		),
	)
	sendAndTrack(bot, msg)
}

func showAdminUsersMenu(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig) {
	text := ""
	text += boldV2("👥 𝙐𝙎𝙀𝙍 𝙈𝘼𝙉𝘼𝙂𝙀𝙍") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "Pilih aksi user:\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnCreateUser, "um_create"),
			tgbotapi.NewInlineKeyboardButtonData(btnListUser, "um_list"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnRenewUser, "um_renew"),
			tgbotapi.NewInlineKeyboardButtonData(btnDeleteUser, "um_delete"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBack, "back_admin"),
		),
	)
	sendAndTrack(bot, msg)
}

// ==========================================
// Payment + Checker
// ==========================================

func processPayment(bot *tgbotapi.BotAPI, chatID, userID int64, days int, cfg *BotConfig) {
	// FIX: buy no response usually because config payment kosong -> sekarang kasih pesan jelas
	if strings.TrimSpace(cfg.PakasirSlug) == "" || strings.TrimSpace(cfg.PakasirApiKey) == "" || cfg.DailyPrice <= 0 {
		sendPlain(bot, chatID, "❌ Payment belum diset.\n\nAdmin: buka 🛠️ Admin Panel -> 💳 Payment Setting untuk set Pakasir & harga.")
		resetAllState(userID)
		return
	}

	price := days * cfg.DailyPrice
	if price < 500 {
		sendPlain(bot, chatID, fmt.Sprintf("❌ Total Rp %s. Minimal transaksi Rp 500.\nTambah durasi.", moneyIDR(price)))
		return
	}

	mutex.Lock()
	pw := tempUserData[userID]["password"]
	mutex.Unlock()

	orderID := fmt.Sprintf("ZIVPN-%d-%d", userID, time.Now().Unix())
	payment, err := createPakasirTransaction(cfg, orderID, price)
	if err != nil {
		sendPlain(bot, chatID, "❌ Gagal membuat pembayaran: "+err.Error())
		resetAllState(userID)
		return
	}

	mutex.Lock()
	if _, ok := tempUserData[userID]; !ok {
		tempUserData[userID] = make(map[string]string)
	}
	tempUserData[userID]["order_id"] = orderID
	tempUserData[userID]["price"] = strconv.Itoa(price)
	tempUserData[userID]["chat_id"] = strconv.FormatInt(chatID, 10)
	tempUserData[userID]["days"] = strconv.Itoa(days)
	tempUserData[userID]["password"] = pw
	mutex.Unlock()

	qrUrl := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=%s", payment.PaymentNumber)

	caption := ""
	caption += boldV2("🧾 𝙏𝘼𝙂𝙄𝙃𝘼𝙉 𝙋𝙀𝙈𝘽𝘼𝙔𝘼𝙍𝘼𝙉") + "\n"
	caption += "━━━━━━━━━━━━━━━━━━━━━━\n"
	caption += "🔐 Password : " + codeSpan(pw) + "\n"
	caption += "📅 Durasi   : " + codeSpan(fmt.Sprintf("%d hari", days)) + "\n"
	caption += "💰 Total    : " + codeSpan("Rp "+moneyIDR(price)) + "\n"
	caption += "⏳ Expired  : " + codeSpan(payment.ExpiredAt) + "\n"
	caption += "━━━━━━━━━━━━━━━━━━━━━━\n"
	caption += "🔄 Auto cek : " + codeSpan("3 detik") + "\n"

	photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileURL(qrUrl))
	photo.Caption = caption
	photo.ParseMode = "MarkdownV2"
	photo.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData(btnCancel, "cancel")),
	)

	deleteLastMessage(bot, chatID)
	sentMsg, err := bot.Send(photo)
	if err == nil {
		lastMessageIDs[chatID] = sentMsg.MessageID
	}

	// state buy selesai -> tunggu checker
	mutex.Lock()
	delete(userStates, userID)
	mutex.Unlock()
}

func startPaymentChecker(bot *tgbotapi.BotAPI, cfg *BotConfig) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		mutex.Lock()
		ids := make([]int64, 0, len(tempUserData))
		for uid, data := range tempUserData {
			if _, ok := data["order_id"]; ok {
				ids = append(ids, uid)
			}
		}
		mutex.Unlock()

		for _, uid := range ids {
			mutex.Lock()
			data, ok := tempUserData[uid]
			mutex.Unlock()
			if !ok {
				continue
			}

			orderID := data["order_id"]
			price := data["price"]
			chatIDStr := data["chat_id"]
			password := data["password"]
			daysStr := data["days"]

			if orderID == "" || price == "" || chatIDStr == "" || password == "" || daysStr == "" {
				continue
			}

			chatID, _ := strconv.ParseInt(chatIDStr, 10, 64)
			status, err := checkPakasirStatus(cfg, orderID, price)
			if err != nil {
				continue
			}

			if status == "completed" || status == "success" {
				days, _ := strconv.Atoi(daysStr)
				createUser(bot, chatID, password, days, cfg)

				mutex.Lock()
				delete(tempUserData, uid)
				delete(userStates, uid)
				mutex.Unlock()

				// balik menu
				showMainMenu(bot, chatID, uid, cfg)
			}
		}
	}

// NOTE: no return needed
}

func createPakasirTransaction(cfg *BotConfig, orderID string, amount int) (*PakasirPayment, error) {
	url := "https://app.pakasir.com/api/transactioncreate/qris"
	payload := map[string]interface{}{
		"project":  cfg.PakasirSlug,
		"order_id": orderID,
		"amount":   amount,
		"api_key":  cfg.PakasirApiKey,
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
			return nil, fmt.Errorf("invalid response (payment_number kosong)")
		}
		return &PakasirPayment{PaymentNumber: pn, ExpiredAt: ea}, nil
	}
	return nil, fmt.Errorf("invalid response from Pakasir")
}

func checkPakasirStatus(cfg *BotConfig, orderID string, amountStr string) (string, error) {
	url := fmt.Sprintf(
		"https://app.pakasir.com/api/transactiondetail?project=%s&amount=%s&order_id=%s&api_key=%s",
		cfg.PakasirSlug, amountStr, orderID, cfg.PakasirApiKey,
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

func testPakasir(bot *tgbotapi.BotAPI, chatID int64, cfg *BotConfig) {
	if strings.TrimSpace(cfg.PakasirSlug) == "" || strings.TrimSpace(cfg.PakasirApiKey) == "" {
		sendPlain(bot, chatID, "❌ Pakasir belum diset.")
		return
	}
	// test minimal amount 500 (Pakasir biasanya)
	orderID := fmt.Sprintf("TEST-%d", time.Now().Unix())
	p, err := createPakasirTransaction(cfg, orderID, 500)
	if err != nil {
		sendPlain(bot, chatID, "❌ Test gagal: "+err.Error())
		return
	}
	sendPlain(bot, chatID, "✅ Test OK\nPaymentNumber: "+p.PaymentNumber+"\nExpiredAt: "+p.ExpiredAt)
}

// ==========================================
// API (User Ops)
// ==========================================

func createUser(bot *tgbotapi.BotAPI, chatID int64, password string, days int, cfg *BotConfig) {
	res, err := apiCall("POST", "/user/create", map[string]interface{}{
		"password": password,
		"days":     days,
	})
	if err != nil {
		sendPlain(bot, chatID, "❌ Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data, _ := res["data"].(map[string]interface{})
		sendAccountInfo(bot, chatID, data, cfg)
		return
	}

	sendPlain(bot, chatID, fmt.Sprintf("❌ Gagal membuat akun: %v", res["message"]))
}

func renewUser(bot *tgbotapi.BotAPI, chatID int64, password string, days int, cfg *BotConfig) {
	res, err := apiCall("POST", "/user/renew", map[string]interface{}{
		"password": password,
		"days":     days,
	})
	if err != nil {
		sendPlain(bot, chatID, "❌ Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data, _ := res["data"].(map[string]interface{})
		sendAccountInfo(bot, chatID, data, cfg)
		return
	}

	sendPlain(bot, chatID, fmt.Sprintf("❌ Gagal renew: %v", res["message"]))
}

func deleteUser(bot *tgbotapi.BotAPI, chatID int64, password string, cfg *BotConfig) {
	res, err := apiCall("POST", "/user/delete", map[string]interface{}{
		"password": password,
	})
	if err != nil {
		sendPlain(bot, chatID, "❌ Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		sendPlain(bot, chatID, "✅ Password berhasil dihapus.")
		return
	}

	sendPlain(bot, chatID, fmt.Sprintf("❌ Gagal delete: %v", res["message"]))
}

func listUsers(bot *tgbotapi.BotAPI, chatID int64, cfg *BotConfig) {
	users, err := getUsers()
	if err != nil {
		sendPlain(bot, chatID, "❌ Gagal mengambil data user.")
		return
	}
	if len(users) == 0 {
		sendPlain(bot, chatID, "📂 Tidak ada user.")
		return
	}

	var b strings.Builder
	b.WriteString("📋 *List Passwords*\n")
	for _, u := range users {
		st := "🟢"
		if strings.EqualFold(u.Status, "Expired") {
			st = "🔴"
		}
		b.WriteString(fmt.Sprintf("\n%s `%s` (%s)", st, u.Password, u.Expired))
	}

	msg := tgbotapi.NewMessage(chatID, b.String())
	msg.ParseMode = "Markdown"
	sendAndTrack(bot, msg)
}

// ==========================================
// User Selection (Admin) + Pagination
// ==========================================

func showUserSelection(bot *tgbotapi.BotAPI, chatID int64, page int, action string) {
	users, err := getUsers()
	if err != nil {
		sendPlain(bot, chatID, "❌ Gagal mengambil data user.")
		return
	}
	if len(users) == 0 {
		sendPlain(bot, chatID, "📂 Tidak ada user.")
		return
	}

	perPage := 10
	totalPages := (len(users) + perPage - 1) / perPage
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	end := start + perPage
	if end > len(users) {
		end = len(users)
	}

	var rows [][]tgbotapi.InlineKeyboardButton
	for _, u := range users[start:end] {
		label := fmt.Sprintf("%s (%s)", u.Password, u.Status)
		if strings.EqualFold(u.Status, "Expired") {
			label = fmt.Sprintf("🔴 %s", label)
		} else {
			label = fmt.Sprintf("🟢 %s", label)
		}
		cb := fmt.Sprintf("select_%s:%s", action, u.Password)
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(label, cb),
		))
	}

	var navRow []tgbotapi.InlineKeyboardButton
	if page > 1 {
		navRow = append(navRow, tgbotapi.NewInlineKeyboardButtonData("⬅️ Prev", fmt.Sprintf("page_%s:%d", action, page-1)))
	}
	if page < totalPages {
		navRow = append(navRow, tgbotapi.NewInlineKeyboardButtonData("Next ➡️", fmt.Sprintf("page_%s:%d", action, page+1)))
	}
	if len(navRow) > 0 {
		rows = append(rows, navRow)
	}

	rows = append(rows,
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBack, "back_admin_users"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("📋 Pilih User untuk %s (Halaman %d/%d):", strings.Title(action), page, totalPages))
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(rows...)
	sendAndTrack(bot, msg)
}

func handlePagination(bot *tgbotapi.BotAPI, chatID int64, data string) {
	parts := strings.Split(data, ":")
	action := strings.TrimPrefix(parts[0], "page_")
	page, _ := strconv.Atoi(parts[1])
	showUserSelection(bot, chatID, page, action)
}

func startRenewUser(bot *tgbotapi.BotAPI, chatID int64, userID int64, data string) {
	username := strings.TrimPrefix(data, "select_renew:")
	mutex.Lock()
	if _, ok := tempUserData[userID]; !ok {
		tempUserData[userID] = make(map[string]string)
	}
	tempUserData[userID]["username"] = username
	mutex.Unlock()

	userStates[userID] = "renew_days"
	sendPlain(bot, chatID, fmt.Sprintf("🔄 Renew `%s`\n\n⏳ Masukkan Tambahan Durasi (hari):", username))
}

func confirmDeleteUser(bot *tgbotapi.BotAPI, chatID int64, data string) {
	username := strings.TrimPrefix(data, "select_delete:")
	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❓ Yakin ingin menghapus `%s`?", username))
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Ya, Hapus", "confirm_delete:"+username),
			tgbotapi.NewInlineKeyboardButtonData(btnCancel, "back_admin_users"),
		),
	)
	sendAndTrack(bot, msg)
}

// ==========================================
// Backup / Restore
// ==========================================

func performBackup(bot *tgbotapi.BotAPI, chatID int64) {
	sendPlain(bot, chatID, "⏳ Sedang membuat backup...")

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
		sendPlain(bot, chatID, "❌ Gagal membuat file backup.")
		return
	}
	defer os.Remove(tmpFile)

	doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(tmpFile))
	doc.Caption = "✅ Backup Data ZiVPN"
	deleteLastMessage(bot, chatID)
	_, _ = bot.Send(doc)
}

func startRestore(bot *tgbotapi.BotAPI, chatID int64, userID int64) {
	userStates[userID] = "waiting_restore_file"
	sendPlain(bot, chatID, "⬆️ Restore Data\n\nSilakan kirim file ZIP backup.\n⚠️ Data saat ini akan ditimpa.")
}

func processRestoreFile(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, cfg *BotConfig) {
	chatID := msg.Chat.ID
	userID := msg.From.ID

	resetAllState(userID)
	sendPlain(bot, chatID, "⏳ Memproses file...")

	fileID := msg.Document.FileID
	f, err := bot.GetFile(tgbotapi.FileConfig{FileID: fileID})
	if err != nil {
		sendPlain(bot, chatID, "❌ Gagal mengunduh file.")
		return
	}

	fileUrl := f.Link(cfg.BotToken)
	resp, err := http.Get(fileUrl)
	if err != nil {
		sendPlain(bot, chatID, "❌ Gagal download content.")
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		sendPlain(bot, chatID, "❌ Gagal membaca file.")
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		sendPlain(bot, chatID, "❌ File bukan ZIP valid.")
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

	for _, zf := range zipReader.File {
		if !validFiles[zf.Name] {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		dstPath := filepath.Join("/etc/zivpn", zf.Name)
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

	_, _ = bot.Send(tgbotapi.NewMessage(chatID, "✅ Restore Berhasil! Service direstart."))

	go func() {
		time.Sleep(2 * time.Second)
		_ = exec.Command("systemctl", "restart", "zivpn-bot").Run()
	}()

	showMainMenu(bot, chatID, userID, cfg)
}

// ==========================================
// System Info
// ==========================================

func systemInfo(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig) {
	res, err := apiCall("GET", "/info", nil)
	if err != nil {
		sendPlain(bot, chatID, "❌ Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data, _ := res["data"].(map[string]interface{})
		ipInfo, _ := getIpInfo()

		text := ""
		text += boldV2("📊 𝙎𝙔𝙎𝙏𝙀𝙈 𝙄𝙉𝙁𝙊") + "\n"
		text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
		text += "🌐 Domain    : " + codeSpan(cfg.Domain) + "\n"
		text += "📍 Public IP : " + codeSpan(fmt.Sprintf("%v", data["public_ip"])) + "\n"
		text += "🔌 Port      : " + codeSpan(fmt.Sprintf("%v", data["port"])) + "\n"
		text += "⚙️ Service   : " + codeSpan(fmt.Sprintf("%v", data["service"])) + "\n"
		text += "🏙 City      : " + codeSpan(ipInfo.City) + "\n"
		text += "📡 ISP       : " + codeSpan(ipInfo.Isp) + "\n"
		text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

		msg := tgbotapi.NewMessage(chatID, text)
		msg.ParseMode = "MarkdownV2"
		sendAndTrack(bot, msg)

		showMainMenu(bot, chatID, userID, cfg)
		return
	}

	sendPlain(bot, chatID, "❌ Gagal mengambil info.")
}

// ==========================================
// Mode Toggle
// ==========================================

func toggleMode(bot *tgbotapi.BotAPI, chatID int64, userID int64, cfg *BotConfig) {
	if userID != cfg.AdminID {
		return
	}
	if strings.ToLower(cfg.Mode) == "public" {
		cfg.Mode = "private"
	} else {
		cfg.Mode = "public"
	}
	_ = saveConfig(cfg)
	sendPlain(bot, chatID, "✅ Mode diubah menjadi: "+cfg.Mode)
	showAdminMenu(bot, chatID, userID, cfg)
}

// ==========================================
// Account Info Message
// ==========================================

func sendAccountInfo(bot *tgbotapi.BotAPI, chatID int64, data map[string]interface{}, cfg *BotConfig) {
	ipInfo, _ := getIpInfo()
	domain := cfg.Domain
	if domain == "" {
		domain = "(Not Configured)"
	}

	pw := fmt.Sprintf("%v", data["password"])
	exp := fmt.Sprintf("%v", data["expired"])

	text := ""
	text += boldV2("✅ 𝘼𝘾𝘾𝙊𝙐𝙉𝙏 𝘼𝙆𝙏𝙄𝙁") + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
	text += "🔐 Password : " + codeSpan(pw) + "\n"
	text += "🌐 Domain   : " + codeSpan(domain) + "\n"
	text += "🏙 City     : " + codeSpan(ipInfo.City) + "\n"
	text += "📡 ISP      : " + codeSpan(ipInfo.Isp) + "\n"
	text += "📅 Expired  : " + codeSpan(exp) + "\n"
	text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "MarkdownV2"
	sendAndTrack(bot, msg)
}

// ==========================================
// Helpers (send / delete / cancel)
// ==========================================

func sendAndTrack(bot *tgbotapi.BotAPI, msg tgbotapi.MessageConfig) {
	deleteLastMessage(bot, msg.ChatID)
	sent, err := bot.Send(msg)
	if err == nil {
		lastMessageIDs[msg.ChatID] = sent.MessageID
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

func cancelOperation(bot *tgbotapi.BotAPI, chatID, userID int64, cfg *BotConfig) {
	resetAllState(userID)
	showMainMenu(bot, chatID, userID, cfg)
}

func resetAllState(userID int64) {
	mutex.Lock()
	delete(userStates, userID)
	delete(tempUserData, userID)
	mutex.Unlock()
}

// ==========================================
// Validators
// ==========================================

func validatePassword(bot *tgbotapi.BotAPI, chatID int64, text string) bool {
	if len(text) < 3 || len(text) > 20 {
		sendPlain(bot, chatID, "❌ Password harus 3-20 karakter. Coba lagi:")
		return false
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(text) {
		sendPlain(bot, chatID, "❌ Password hanya boleh huruf, angka, - dan _. Coba lagi:")
		return false
	}
	return true
}

func validateNumber(bot *tgbotapi.BotAPI, chatID int64, text string, min, max int, fieldName string) (int, bool) {
	val, err := strconv.Atoi(strings.ReplaceAll(text, ",", ""))
	if err != nil || val < min || val > max {
		sendPlain(bot, chatID, fmt.Sprintf("❌ %s harus angka (%d-%d). Coba lagi:", fieldName, min, max))
		return 0, false
	}
	return val, true
}

// ==========================================
// Config
// ==========================================

func loadConfig() (BotConfig, error) {
	var cfg BotConfig
	b, err := ioutil.ReadFile(BotConfigFile)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}

	// normalize
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "private"
	}

	// fill domain from file if empty
	if cfg.Domain == "" {
		if d, err2 := ioutil.ReadFile(DomainFile); err2 == nil {
			cfg.Domain = strings.TrimSpace(string(d))
		}
	}

	return cfg, nil
}

func saveConfig(cfg *BotConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(BotConfigFile, b, 0644)
}

func maskKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "****" + s[len(s)-3:]
}

func maskShort(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if len(s) > 24 {
		return s[:24]
	}
	return s
}

// ==========================================
// API Client
// ==========================================

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

	var info IpInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return IpInfo{}, err
	}
	return info, nil
}

func getUsers() ([]UserData, error) {
	res, err := apiCall("GET", "/users", nil)
	if err != nil {
		return nil, err
	}
	if res["success"] != true {
		return nil, fmt.Errorf("failed to get users")
	}

	var users []UserData
	dataBytes, _ := json.Marshal(res["data"])
	_ = json.Unmarshal(dataBytes, &users)
	return users, nil
}