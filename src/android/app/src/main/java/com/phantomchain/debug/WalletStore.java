package com.phantomchain.debug;

import android.content.Context;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

import org.json.JSONObject;

/** Persists the wallet: the public account id in the clear + the biometric-sealed seed (iv, ciphertext). */
public class WalletStore {
    static File f(Context c) { return new File(c.getFilesDir(), "wallet.dat"); }
    static boolean exists(Context c) { return f(c).exists(); }

    static void save(Context c, String id, byte[] iv, byte[] ct) throws Exception {
        JSONObject o = new JSONObject().put("id", id)
                .put("iv", Base64.getEncoder().encodeToString(iv))
                .put("ct", Base64.getEncoder().encodeToString(ct));
        Files.write(f(c).toPath(), o.toString().getBytes(StandardCharsets.UTF_8));
    }
    static JSONObject load(Context c) throws Exception {
        return new JSONObject(new String(Files.readAllBytes(f(c).toPath()), StandardCharsets.UTF_8));
    }
    static String id(Context c) throws Exception { return load(c).getString("id"); }
    static byte[] iv(Context c) throws Exception { return Base64.getDecoder().decode(load(c).getString("iv")); }
    static byte[] ct(Context c) throws Exception { return Base64.getDecoder().decode(load(c).getString("ct")); }
}
