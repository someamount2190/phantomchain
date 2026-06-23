package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.json.JSONObject;

/**
 * Authenticated account state: verifies the Merkle commitment + inclusion proofs added in this build,
 * and that the serialization version (srVersion) is a backward-compatible, self-describing field rather
 * than a JVM launch flag.
 */
public class MerkleProofTest {

    static Ledger fresh(String ver) throws Exception {
        Ledger L = new Ledger();
        L.srVersion = ver;
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        alloc.put("aaaa1111", 1000L); alloc.put("bbbb2222", 2000L); alloc.put("cccc3333", 3000L);
        alloc.put("dddd4444", 4000L); alloc.put("eeee5555", 5000L);
        java.util.List<String> vals = new java.util.ArrayList<>(alloc.keySet());
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        for (String v : vals) { stk.put(v, 1L); idn.put(v, 1L); }
        L.genesisEcon("pc-merkle", alloc, vals, stk, idn, new HashSet<>(vals), new HashMap<>(), 0);
        return L;
    }

    public static void main(String[] a) throws Exception {
        Ledger L = fresh("full");

        // 1. every present account produces a proof that verifies against the committed root
        boolean allVerify = true, rootStable = true;
        String root = L.accountsMerkleRoot();
        for (String id : L.sortedAccountIds()) {
            JSONObject p = L.accountProof(id);
            if (!Ledger.verifyAccountProof(p)) allVerify = false;
            if (!root.equals(p.getString("root"))) rootStable = false;
        }
        ok("every account has an inclusion proof that verifies", allVerify);
        ok("all proofs share one deterministic root", rootStable);
        ok("recomputing the root is deterministic", root.equals(fresh("full").accountsMerkleRoot()));

        // 2. tamper detection: a forged balance must NOT verify against the honest root
        JSONObject good = L.accountProof("cccc3333");
        JSONObject forged = new JSONObject(good.toString()).put("balance", good.getLong("balance") + 1);
        ok("forged balance fails verification", !Ledger.verifyAccountProof(forged));
        JSONObject wrongRoot = new JSONObject(good.toString()).put("root",
                "00000000000000000000000000000000000000000000000000000000000000ff");
        ok("proof against a wrong root fails", !Ledger.verifyAccountProof(wrongRoot));

        // 3. absent account => no proof
        ok("absent account reports present=false", !L.accountProof("ffffffff").getBoolean("present"));

        // 4. changing an account changes the root (the proof is actually binding)
        String before = L.accountsMerkleRoot();
        L.accounts.get("aaaa1111").balance = 999_999L;
        ok("mutating an account changes the Merkle root", !before.equals(L.accountsMerkleRoot()));

        // 5. odd leaf count handled (5 accounts above => last level is odd at some point)
        ok("odd leaf count proof verifies (last account)",
                Ledger.verifyAccountProof(L.accountProof(L.sortedAccountIds().get(L.sortedAccountIds().size() - 1))));

        // 6. version semantics: "full" unchanged; "m1" binds the account root into the state root
        Ledger lf = fresh("full"), lm = fresh("m1");
        ok("\"full\" state root excludes the |amr| binding (backward compatible)",
                !lf.stateRoot().equals(lm.stateRoot()));
        // and m1's binding actually tracks the accounts: change one account, m1 root must move
        String m1before = lm.stateRoot();
        lm.accounts.get("bbbb2222").balance += 1;
        ok("m1 state root tracks account changes via the bound Merkle root", !m1before.equals(lm.stateRoot()));

        // 7. srVersion survives a snapshot round-trip (no launch flag needed)
        Ledger rt = new Ledger(); rt.fromJson(lm.toJson());
        ok("srVersion persists across toJson/fromJson", "m1".equals(rt.srVersion));
        Ledger legacy = new Ledger();
        JSONObject snap = new JSONObject(lf.toJson()); snap.remove("srVersion");   // simulate a pre-field snapshot
        legacy.fromJson(snap.toString());
        ok("snapshot without srVersion defaults to \"full\"", "full".equals(legacy.srVersion));

        System.out.println("\nMerkleProofTest: " + pass + " passed, " + fail + " failed");
        if (fail > 0) System.exit(1);
    }
}
