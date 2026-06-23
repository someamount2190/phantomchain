package com.phantomchain.debug;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * PhantomChain node CLI.
 *
 *   keygen  &lt;keyFile&gt;                     generate (or show) this node's ML-DSA key; prints pubkey + id
 *   genesis &lt;specFile&gt; &lt;outDir&gt;          mint genesis.json + the TLS cert bundle from a validator spec
 *   run     &lt;configFile&gt; &lt;genesisFile&gt;   run the validator
 *
 * Genesis ceremony flow (the same on one box or many):
 *   1. each operator runs `keygen` and publishes their pubkey;
 *   2. someone assembles a spec.json {chainId, genesisTime, validators:[{pubkey,stake,identity,verified,alloc}]};
 *   3. `genesis spec.json out/` writes the canonical genesis.json and mints out/tls/ (CA + per-node certs);
 *   4. genesis.json is shared with everyone; each node gets its own node-&lt;index&gt;.p12 + truststore.p12;
 *   5. each operator runs `run config.json genesis.json`.
 */
public class NodeMain {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) { usage(); return; }
        switch (args[0]) {
            case "keygen": {
                if (args.length < 2) { usage(); return; }
                MLDSAPrivateKeyParameters key = Keys.loadOrCreate(new File(args[1]));
                System.out.println("keyFile=" + args[1]);
                System.out.println("pubkey=" + Keys.pubHex(key));
                System.out.println("id=" + Keys.idOf(key));
                System.out.println("beaconCommit0=" + Ledger.beaconCommit0For(key.getEncoded()));   // publish in genesis spec / VALJOIN to bind first reveal
                break;
            }
            case "genesis": {
                if (args.length < 3) { usage(); return; }
                Genesis g = Genesis.fromJson(new String(Files.readAllBytes(new File(args[1]).toPath()), StandardCharsets.UTF_8));
                File outDir = new File(args[2]); outDir.mkdirs();
                File gf = new File(outDir, "genesis.json");
                Files.write(gf.toPath(), g.toJson().toString(2).getBytes(StandardCharsets.UTF_8));
                File tls = new File(outDir, "tls"); tls.mkdirs();
                TlsSetup.ensureCerts(tls, g.validators.size());
                System.out.println("wrote " + gf + " (chainId=" + g.chainId + ", validators=" + g.validators.size() + ")");
                System.out.println("minted TLS bundle in " + tls + " (truststore.p12 + node-0.." + (g.validators.size() - 1) + ".p12)");
                for (int i = 0; i < g.validators.size(); i++) {
                    Genesis.Validator v = g.validators.get(i);
                    System.out.println("  validator[" + i + "] id=" + v.id.substring(0, 12) + "... stake=" + v.stake
                            + " identity=" + v.identity + " verified=" + v.verified + " alloc=" + v.alloc);
                }
                break;
            }
            case "mintcert": {   // mintcert <tlsDir> <index> — issue a cert for a joining validator from the retained CA
                if (args.length < 3) { usage(); return; }
                TlsSetup.mintNodeCert(new File(args[1]), Integer.parseInt(args[2]));
                System.out.println("minted node-" + args[2] + ".p12 in " + args[1]);
                break;
            }
            case "run": {
                if (args.length < 3) { usage(); return; }
                NodeConfig cfg = NodeConfig.load(new File(args[1]));
                Genesis g = Genesis.load(new File(args[2]));
                MLDSAPrivateKeyParameters key = Keys.loadOrCreate(new File(cfg.keyFile));
                NetNode node = new NetNode(g, cfg, key);
                node.boot();
                while (true) Thread.sleep(3_600_000L);
            }
            default:
                usage();
        }
    }

    static void usage() {
        System.err.println("usage:");
        System.err.println("  NodeMain keygen  <keyFile>");
        System.err.println("  NodeMain genesis <specFile> <outDir>");
        System.err.println("  NodeMain run     <configFile> <genesisFile>");
    }
}
