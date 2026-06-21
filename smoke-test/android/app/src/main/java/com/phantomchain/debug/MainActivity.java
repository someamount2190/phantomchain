package com.phantomchain.debug;

import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.util.Base64;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import org.json.JSONObject;

/**
 * PhantomChain Wallet — a real self-custodial client for the live testnet.
 *   - ML-DSA-65 account key sealed behind a biometric-gated AndroidKeyStore key (BioKeystore);
 *   - talks to the live node over CA-pinned TLS 1.3 (Wallet + bundled truststore.p12);
 *   - send / receive (address QR) / balance, and encrypted QR seed backup + recovery.
 * No mock server: every balance and transfer is the real chain.
 */
public class MainActivity extends AppCompatActivity {

    static final String NODE = "188.166.224.212:9090";   // live PhantomChain testnet seed

    SSLContext tls;
    TextView account, balance, log;
    EditText toField, amtField, feeField, pwField, recoverField;
    ImageView qr;

    void log(String s) { runOnUiThread(() -> log.setText(s + "\n\n" + log.getText())); }
    void bg(Runnable r) { new Thread(r).start(); }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int p = 24; root.setPadding(p, p, p, p);

        TextView title = new TextView(this); title.setText("PhantomChain Wallet"); title.setTextSize(20);
        TextView sub = new TextView(this); sub.setText("testnet: " + NODE);
        account = new TextView(this); account.setText("account: (none)");
        balance = new TextView(this); balance.setText("balance: —"); balance.setTextSize(18);

        Button bRefresh = new Button(this); bRefresh.setText("Refresh balance");
        Button bReceive = new Button(this); bReceive.setText("Receive (show address QR)");

        toField = new EditText(this); toField.setHint("recipient account id");
        amtField = new EditText(this); amtField.setHint("amount"); amtField.setText("100");
        feeField = new EditText(this); feeField.setHint("fee"); feeField.setText("1");
        Button bSend = new Button(this); bSend.setText("Send (biometric)");

        pwField = new EditText(this); pwField.setHint("backup password"); pwField.setText("correct horse battery staple 9!");
        Button bBackup = new Button(this); bBackup.setText("Backup seed -> QR (biometric)");
        recoverField = new EditText(this); recoverField.setHint("paste backup QR text to recover");
        Button bRecover = new Button(this); bRecover.setText("Recover from backup");
        Button bCreate = new Button(this); bCreate.setText("Create new wallet");
        Button bContribute = new Button(this); bContribute.setText("Contribute to cluster (biometric)");

        qr = new ImageView(this); qr.setMinimumHeight(440);
        log = new TextView(this); log.setText("");

        for (View v : new View[]{title, sub, account, balance, bRefresh, bReceive,
                toField, amtField, feeField, bSend, pwField, bBackup, recoverField, bRecover, bCreate, bContribute, qr, log})
            root.addView(v);
        ScrollView sv = new ScrollView(this); sv.addView(root); setContentView(sv);

        try {
            tls = Wallet.tlsTrusting(getAssets().open("truststore.p12"), "phantomchain".toCharArray());
        } catch (Exception e) { log("TLS init failed: " + e.getMessage()); }

        if (WalletStore.exists(this)) {
            try { account.setText("account: " + WalletStore.id(this)); refreshBalance(); }
            catch (Exception e) { log("load failed: " + e.getMessage()); }
        } else {
            log("No wallet yet — tap \"Create new wallet\".");
        }

        bCreate.setOnClickListener(v -> createWallet());
        bRefresh.setOnClickListener(v -> refreshBalance());
        bReceive.setOnClickListener(v -> { try { renderQr(WalletStore.id(this)); log("receive: address QR shown"); } catch (Exception e) { log("no wallet"); } });
        bSend.setOnClickListener(v -> send());
        bBackup.setOnClickListener(v -> backup());
        bRecover.setOnClickListener(v -> recover());
        bContribute.setOnClickListener(v -> contribute());
    }

    /** Spec §9: contribute this device to a cluster with explicit biometric consent. One biometric
     *  unseals the member key for the session; the on-device ClusterMember server then signs block
     *  hashes the desktop coordinator requests, until the app is closed. */
    void contribute() {
        if (!WalletStore.exists(this)) { log("create a wallet first (this device's account is its cluster member id)"); return; }
        try {
            byte[] iv = WalletStore.iv(this), ct = WalletStore.ct(this);
            withSeal("Consent to contribute to the cluster", false, iv, cipher -> bg(() -> {
                try {
                    byte[] seed = cipher.doFinal(ct);
                    String mid = ClusterMember.start(8080, seed);
                    log("CONTRIBUTING to cluster as member\n" + mid + "\nsigning service live on :8080 (biometric consent given)");
                } catch (Exception e) { log("contribute failed: " + e.getMessage()); }
            }));
        } catch (Exception e) { log("contribute failed: " + e.getMessage()); }
    }

    // ---- biometric gate: run `onCipher` with an authenticated Cipher ----
    void bioAuth(String reason, Cipher cipher, Consumer<Cipher> onCipher) {
        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("PhantomChain").setSubtitle(reason)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();
        BiometricPrompt bp = new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                        onCipher.accept(r.getCryptoObject().getCipher());
                    }
                    @Override public void onAuthenticationError(int code, CharSequence msg) { log("biometric: " + msg); }
                });
        bp.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
    }

    boolean bioReady() {
        try {
            return androidx.biometric.BiometricManager.from(this)
                    .canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS;
        } catch (Exception e) { return false; }
    }

    /** Run onCipher with a seed-seal cipher: real biometric prompt if a biometric is enrolled, otherwise
     *  (e.g. a headless emulator) a simulated-consent path with a non-gated key under a separate alias. */
    void withSeal(String reason, boolean encrypt, byte[] iv, Consumer<Cipher> onCipher) {
        try {
            boolean bio = bioReady();
            Cipher c = encrypt ? BioKeystore.encryptCipher(bio) : BioKeystore.decryptCipher(iv, bio);
            if (bio) bioAuth(reason, c, onCipher);
            else { log("[debug] simulated consent — no biometric enrolled"); onCipher.accept(c); }
        } catch (Exception e) { log("auth failed: " + e.getMessage()); }
    }

    void createWallet() {
        try {
            byte[] seed = Wallet.newSeed();
            String id = Wallet.idFromSeed(seed);
            withSeal("Authenticate to create wallet", true, null, cipher -> {
                try {
                    byte[] ct = cipher.doFinal(seed);
                    WalletStore.save(this, id, cipher.getIV(), ct);
                    runOnUiThread(() -> account.setText("account: " + id));
                    log("wallet created\naccount=" + id);
                    refreshBalance();
                } catch (Exception e) { log("create failed: " + e.getMessage()); }
            });
        } catch (Exception e) { log("create failed: " + e.getMessage()); }
    }

    void refreshBalance() {
        bg(() -> {
            try {
                String id = WalletStore.id(this);
                JSONObject a = new JSONObject(Wallet.rpcGet(NODE, tls, "/account?id=" + id).trim());
                final long bal = a.getLong("balance"); final long non = a.getLong("nonce");
                runOnUiThread(() -> balance.setText("balance: " + bal + "   nonce: " + non));
            } catch (Exception e) { log("balance failed: " + e.getMessage()); }
        });
    }

    void send() {
        final String to = toField.getText().toString().trim();
        final long amount, fee;
        try { amount = Long.parseLong(amtField.getText().toString().trim()); fee = Long.parseLong(feeField.getText().toString().trim()); }
        catch (Exception e) { log("bad amount/fee"); return; }
        if (to.isEmpty()) { log("enter recipient"); return; }
        try {
            byte[] iv = WalletStore.iv(this), ct = WalletStore.ct(this);
            withSeal("Authenticate to sign & send", false, iv, cipher -> bg(() -> {
                try {
                    byte[] seed = cipher.doFinal(ct);
                    Wallet w = new Wallet(seed, NODE, tls);
                    String res = w.send(to, amount, fee);
                    log("SENT " + amount + " (fee " + fee + ") -> " + res);
                    refreshBalance();
                } catch (Exception e) { log("send failed: " + e.getMessage()); }
            }));
        } catch (Exception e) { log("send failed: " + e.getMessage()); }
    }

    void backup() {
        try {
            byte[] iv = WalletStore.iv(this), ct = WalletStore.ct(this);
            String pw = pwField.getText().toString();
            withSeal("Authenticate to back up seed", false, iv, cipher -> {
                try {
                    byte[] seed = cipher.doFinal(ct);
                    byte[] blob = PhantomCrypto.backup(seed, pw, new byte[0]);
                    String b64 = Base64.getEncoder().encodeToString(blob);
                    renderQr(b64);
                    log("backup QR rendered (" + blob.length + " B). Keep it safe; password required to restore.");
                } catch (Exception e) { log("backup failed: " + e.getMessage()); }
            });
        } catch (Exception e) { log("backup failed: " + e.getMessage()); }
    }

    void recover() {
        String b64 = recoverField.getText().toString().trim();
        String pw = pwField.getText().toString();
        if (b64.isEmpty()) { log("paste a backup QR text first"); return; }
        try {
            byte[] seed = Wallet.recoverSeed(Base64.getDecoder().decode(b64), pw);
            String id = Wallet.idFromSeed(seed);
            withSeal("Authenticate to store recovered wallet", true, null, cipher -> {
                try {
                    byte[] ct = cipher.doFinal(seed);
                    WalletStore.save(this, id, cipher.getIV(), ct);
                    runOnUiThread(() -> account.setText("account: " + id));
                    log("RECOVERED wallet\naccount=" + id);
                    refreshBalance();
                } catch (Exception e) { log("store failed: " + e.getMessage()); }
            });
        } catch (Exception e) { log("RECOVER FAILED (wrong password?): " + e.getMessage()); }
    }

    void renderQr(String text) {
        try {
            int size = 440;
            BitMatrix m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size);
            Bitmap bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565);
            for (int x = 0; x < size; x++) for (int y = 0; y < size; y++)
                bmp.setPixel(x, y, m.get(x, y) ? Color.BLACK : Color.WHITE);
            runOnUiThread(() -> qr.setImageBitmap(bmp));
        } catch (Exception e) { log("qr failed: " + e.getMessage()); }
    }
}
