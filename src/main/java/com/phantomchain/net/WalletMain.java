package com.phantomchain.net;

import com.phantomchain.debug.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

import javax.net.ssl.SSLContext;

/**
 * Wallet CLI (proves the shippable wallet logic against a live node):
 *   new     &lt;node&gt; &lt;truststore.p12&gt; &lt;walletFile&gt;
 *   balance &lt;node&gt; &lt;truststore.p12&gt; &lt;walletFile&gt;
 *   send    &lt;node&gt; &lt;truststore.p12&gt; &lt;walletFile&gt; &lt;to&gt; &lt;amount&gt; &lt;fee&gt;
 *   backup  &lt;walletFile&gt; &lt;password&gt;
 *   recover &lt;blobB64&gt; &lt;password&gt; &lt;walletFile&gt;
 */
public class WalletMain {
    static final char[] TS_PASS = "phantomchain".toCharArray();

    public static void main(String[] a) throws Exception {
        if (a.length < 1) { usage(); return; }
        switch (a[0]) {
            case "new": {
                byte[] seed = Wallet.newSeed();
                Files.write(new File(a[3]).toPath(), PhantomCrypto.hex(seed).getBytes(StandardCharsets.UTF_8));
                Wallet w = new Wallet(seed, a[1], Wallet.tlsTrusting(new File(a[2]), TS_PASS));
                System.out.println("walletFile=" + a[3]);
                System.out.println("account=" + w.id);
                break;
            }
            case "balance": {
                Wallet w = load(a);
                System.out.println("account=" + w.id);
                System.out.println(w.account().toString());
                break;
            }
            case "send": {
                Wallet w = load(a);
                System.out.println("send -> " + w.send(a[4], Long.parseLong(a[5]), Long.parseLong(a[6])));
                break;
            }
            case "backup": {
                byte[] seed = PhantomCrypto.unhex(new String(Files.readAllBytes(new File(a[1]).toPath()), StandardCharsets.UTF_8).trim());
                System.out.println("qr=" + Base64.getEncoder().encodeToString(PhantomCrypto.backup(seed, a[2], new byte[0])));
                break;
            }
            case "recover": {
                byte[] seed = Wallet.recoverSeed(Base64.getDecoder().decode(a[1]), a[2]);
                Files.write(new File(a[3]).toPath(), PhantomCrypto.hex(seed).getBytes(StandardCharsets.UTF_8));
                String id = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.deviceKeyFromSeed(seed).getPublicKeyParameters().getEncoded()));
                System.out.println("recovered account=" + id);
                break;
            }
            default: usage();
        }
    }

    static Wallet load(String[] a) throws Exception {
        byte[] seed = PhantomCrypto.unhex(new String(Files.readAllBytes(new File(a[3]).toPath()), StandardCharsets.UTF_8).trim());
        return new Wallet(seed, a[1], Wallet.tlsTrusting(new File(a[2]), TS_PASS));
    }

    static void usage() { System.err.println("usage: WalletMain new|balance|send|backup|recover ..."); }
}
