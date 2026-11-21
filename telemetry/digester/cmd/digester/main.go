// digester (tuần 9 T5) — ký đầu hash chain của SIEM bằng Vault Transit (SR-09, M6/M7, RP6, CR-06).
//
//	đọc  /chain/<epoch>.jsonl      (Vector ghi; volume siem-chain, mount ro) — KHÔNG đọc OpenSearch
//	nối  H_i = SHA-256(H_{i-1} ‖ event_hash_i)                                 (internal/chain)
//	ký   mỗi DIGEST_INTERVAL (5 phút), hoặc ngay khi nhận SIGUSR1, hoặc lúc tắt (SIGTERM)
//	     POST transit/sign/siem-digest, tự xác minh chữ ký bằng public key đã công bố (internal/vault)
//	ghi  /state/digests.jsonl (sổ cục bộ, fsync) + OpenSearch topic09-digests (internal/store)
//	log  digest_signed / digest_failed / chain_<bất thường> → Vector → SIEM (H9)
//
// Fail-closed (SR-11, FI-4): Vault lỗi/từ chối/chữ ký không khớp → không ghi digest nào, trạng
// thái không tiến; lần sau ký lại khoảng lớn hơn. Không bao giờ có digest không chữ ký.
//
// Kiểm sức khoẻ (Docker): digester -healthcheck — file nhịp tim trong /state còn mới.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"topic09-lab/telemetry/digester/internal/chain"
	"topic09-lab/telemetry/digester/internal/digest"
	"topic09-lab/telemetry/digester/internal/store"
	"topic09-lab/telemetry/digester/internal/vault"
)

type config struct {
	ChainDir, StateDir                      string
	VaultAddr, VaultKey, TokenFile, PubFile string
	OpenSearchURL, DigestIndex              string
	DigestInterval, PollInterval, GapGrace  time.Duration
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func dur(k, def string) (time.Duration, error) {
	d, err := time.ParseDuration(env(k, def))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s không hợp lệ", k)
	}
	return d, nil
}

var keyNameRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

func loadConfig() (config, error) {
	c := config{
		ChainDir: env("CHAIN_DIR", "/chain"), StateDir: env("STATE_DIR", "/state"),
		VaultAddr: env("VAULT_ADDR", "http://vault:8200"), VaultKey: env("VAULT_KEY_NAME", "siem-digest"),
		TokenFile:     env("VAULT_TOKEN_FILE", "/run/secrets/vault_token_digester"),
		PubFile:       env("PUBKEY_FILE", "/kms-public/siem-digest.json"),
		OpenSearchURL: env("OPENSEARCH_URL", "http://opensearch:9200"), DigestIndex: env("DIGEST_INDEX", "topic09-digests"),
	}
	var err error
	if c.DigestInterval, err = dur("DIGEST_INTERVAL", "5m"); err != nil {
		return c, err
	}
	if c.PollInterval, err = dur("POLL_INTERVAL", "10s"); err != nil {
		return c, err
	}
	if c.GapGrace, err = dur("GAP_GRACE", "30s"); err != nil {
		return c, err
	}
	for k, v := range map[string]string{"VAULT_ADDR": c.VaultAddr, "OPENSEARCH_URL": c.OpenSearchURL} {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return c, fmt.Errorf("%s phải là URL http(s)", k)
		}
	}
	if !keyNameRe.MatchString(c.VaultKey) || !keyNameRe.MatchString(c.DigestIndex) {
		return c, errors.New("VAULT_KEY_NAME / DIGEST_INDEX sai dạng")
	}
	return c, nil
}

type digester struct {
	cfg     config
	log     *slog.Logger
	tracker *chain.Tracker
	ledger  *digest.Ledger
	signer  *vault.Signer
	store   *store.OpenSearch
	now     func() time.Time
}

// event ghi một dòng log sự kiện (Vector đưa vào SIEM): luôn có event_time.
func (d *digester) event(level slog.Level, msg string, attrs ...any) {
	attrs = append([]any{"event_time", d.now().UTC().Format(time.RFC3339Nano)}, attrs...)
	d.log.Log(context.Background(), level, msg, attrs...)
}

func (d *digester) anomalies(as []chain.Anomaly) {
	for _, a := range as {
		attrs := []any{"decision", "deny", "decision_reason", a.Kind, "digest_epoch", a.Epoch}
		if a.First > 0 {
			attrs = append(attrs, "digest_first_seq", a.First, "digest_last_seq", max(a.Last, a.First))
		}
		d.event(slog.LevelWarn, "chain_"+a.Kind, attrs...)
	}
}

func reason(err error) string {
	for _, e := range []error{vault.ErrDenied, vault.ErrUnavailable, vault.ErrBadResponse, vault.ErrPubKeyMismatch, vault.ErrNoToken, vault.ErrNoPubKey} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "digest_error"
}

// digestAll ký một digest cho mỗi epoch có sự kiện mới kể từ điểm đã ký gần nhất.
func (d *digester) digestAll(ctx context.Context) {
	d.anomalies(d.tracker.CloseGaps(d.cfg.GapGrace))
	for _, ep := range d.tracker.Epochs() {
		cp := d.ledger.Checkpoint(ep.Name)
		last := ep.Last()
		if last <= cp.LastSeq {
			continue
		}
		first := cp.LastSeq + 1
		seq, prevSig := d.ledger.Next()
		p := digest.New(seq, prevSig, d.cfg.VaultKey, ep.Name, first, last, cp.Head, ep.Head(), ep.GapsIn(first, last), d.now())
		msg := p.Bytes()
		ids := []any{"digest_seq", seq, "digest_epoch", ep.Name, "digest_first_seq", first, "digest_last_seq", last}

		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		sig, err := d.signer.Sign(sctx, msg)
		cancel()
		if err != nil {
			calls := 1
			if errors.Is(err, vault.ErrNoToken) {
				calls = 0
			}
			d.event(slog.LevelError, "digest_failed", append([]any{"decision", "deny", "decision_reason", reason(err), "kms_calls", calls}, ids...)...)
			return // fail-closed: dừng cả lượt, không ký epoch sau khi epoch trước còn hở
		}
		rec := digest.Record{Payload: p, Signature: sig.Value, KeyVersion: sig.KeyVersion, PublicKey: sig.PublicKey,
			SignedPayload: base64.StdEncoding.EncodeToString(msg)}
		if err := d.ledger.Append(rec); err != nil {
			d.event(slog.LevelError, "digest_failed", append([]any{"decision", "deny", "decision_reason", "ledger_error", "kms_calls", 1}, ids...)...)
			return
		}
		d.store.Enqueue(rec)
		d.event(slog.LevelInfo, "digest_signed", append([]any{"decision", "allow", "decision_reason", "ok", "kms_calls", 1, "kms_key_version", sig.KeyVersion}, ids...)...)
	}
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := d.store.Flush(fctx); err != nil {
		// Log vận hành (không vào SIEM): digest vẫn nằm trong sổ cục bộ và hàng đợi.
		d.log.Warn("digest_store_failed", "error", err.Error(), "pending", d.store.Pending(), "dropped", d.store.Dropped)
	}
}

func (d *digester) poll() {
	as, err := d.tracker.Poll()
	d.anomalies(as)
	if err != nil {
		d.log.Warn("chain_dir_unreadable", "error", err.Error())
	}
	// Nhịp tim cho healthcheck: ghi đè file nhỏ trong /state.
	_ = os.WriteFile(filepath.Join(d.cfg.StateDir, "heartbeat"), []byte(d.now().UTC().Format(time.RFC3339)), 0o640)
}

func healthcheck(cfg config) int {
	st, err := os.Stat(filepath.Join(cfg.StateDir, "heartbeat"))
	if err != nil || time.Since(st.ModTime()) > max(3*cfg.PollInterval, time.Minute) {
		return 1
	}
	return 0
}

func main() {
	hc := flag.Bool("healthcheck", false, "kiểm file nhịp tim rồi thoát với mã 0 (khoẻ) hoặc 1")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "digester")
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config_invalid", "error", err.Error())
		os.Exit(2)
	}
	if *hc {
		os.Exit(healthcheck(cfg))
	}

	ledger, err := digest.OpenLedger(filepath.Join(cfg.StateDir, "digests.jsonl"))
	if err != nil {
		// Sổ đứt mắt xích / chữ ký sai: không nối tiếp lên một sổ không tin được.
		logger.Error("ledger_invalid", "error", err.Error())
		os.Exit(1)
	}
	tracker := chain.NewTracker(cfg.ChainDir)
	for ep, cp := range ledger.Epochs() {
		tracker.Expect(ep, cp.LastSeq, cp.Head) // đọc lại file phải ra đúng đầu chuỗi đã ký
	}
	d := &digester{
		cfg: cfg, log: logger, tracker: tracker, ledger: ledger, now: time.Now,
		signer: &vault.Signer{Addr: cfg.VaultAddr, Key: cfg.VaultKey, TokenFile: cfg.TokenFile, PubKeyFile: cfg.PubFile, Client: vault.NewClient(5 * time.Second)},
		store:  &store.OpenSearch{URL: cfg.OpenSearchURL, Index: cfg.DigestIndex, Client: vault.NewClient(5 * time.Second)},
	}
	next, _ := ledger.Next()
	logger.Info("starting", "digest_interval", cfg.DigestInterval.String(), "poll_interval", cfg.PollInterval.String(), "next_digest_seq", next, "known_epochs", len(ledger.Epochs()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	now := make(chan os.Signal, 1)
	signal.Notify(now, syscall.SIGUSR1) // docker compose kill -s USR1 digester → ký ngay (test)

	pollT := time.NewTicker(cfg.PollInterval)
	digestT := time.NewTicker(cfg.DigestInterval)
	defer pollT.Stop()
	defer digestT.Stop()
	d.poll()
	for {
		select {
		case <-ctx.Done():
			// Tắt êm: ký nốt phần đã đọc để sự kiện trước lúc tắt có digest.
			d.poll()
			d.digestAll(context.Background())
			logger.Info("stopped")
			return
		case <-pollT.C:
			d.poll()
		case <-digestT.C:
			d.poll()
			d.digestAll(ctx)
		case <-now:
			d.poll()
			d.digestAll(ctx)
			digestT.Reset(cfg.DigestInterval)
		}
	}
}
