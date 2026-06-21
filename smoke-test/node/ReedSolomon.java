package com.phantomchain.debug;

/**
 * Reed-Solomon erasure coding over GF(256) (primitive poly 0x11d) with a systematic Cauchy matrix
 * (every k×k submatrix invertible -> MDS: any k of n shards reconstruct the data). Used to store the
 * ledger history as n shards where each node keeps only its assigned shard (n/k overhead vs R× replication).
 */
public class ReedSolomon {
    static final int[] EXP = new int[512];
    static final int[] LOG = new int[256];
    static {
        int x = 1;
        for (int i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if ((x & 0x100) != 0) x ^= 0x11d; }
        for (int i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
    }
    static int mul(int a, int b) { return (a == 0 || b == 0) ? 0 : EXP[LOG[a] + LOG[b]]; }
    static int inv(int a) { return EXP[255 - LOG[a]]; }   // a != 0

    final int k, n;
    final int[][] M;   // n x k systematic encoding matrix: top k = identity, bottom n-k = Cauchy

    public ReedSolomon(int k, int n) {
        this.k = k; this.n = n;
        M = new int[n][k];
        for (int i = 0; i < k; i++) M[i][i] = 1;
        for (int i = 0; i < n - k; i++) {            // Cauchy rows: x in {0..n-k-1}, y in {n-k..n-1} (disjoint)
            for (int j = 0; j < k; j++) M[k + i][j] = inv(i ^ ((n - k) + j));
        }
    }

    /** Encode k equal-length data shards -> n shards (first k are the data, copied). */
    public byte[][] encode(byte[][] data) {
        int len = data[0].length;
        byte[][] shards = new byte[n][len];
        for (int i = 0; i < k; i++) System.arraycopy(data[i], 0, shards[i], 0, len);
        for (int i = 0; i < n - k; i++)
            for (int b = 0; b < len; b++) {
                int acc = 0;
                for (int j = 0; j < k; j++) acc ^= mul(M[k + i][j], data[j][b] & 0xff);
                shards[k + i][b] = (byte) acc;
            }
        return shards;
    }

    /** Reconstruct the k data shards from any >=k present shards. */
    public byte[][] decode(byte[][] shards, boolean[] present, int len) {
        int[] rows = new int[k]; int c = 0;
        for (int i = 0; i < n && c < k; i++) if (present[i]) rows[c++] = i;
        if (c < k) throw new RuntimeException("need k shards to reconstruct");
        int[][] A = new int[k][k];
        for (int r = 0; r < k; r++) for (int j = 0; j < k; j++) A[r][j] = M[rows[r]][j];
        int[][] Ainv = invert(A, k);
        byte[][] data = new byte[k][len];
        for (int b = 0; b < len; b++)
            for (int r = 0; r < k; r++) {
                int acc = 0;
                for (int j = 0; j < k; j++) acc ^= mul(Ainv[r][j], shards[rows[j]][b] & 0xff);
                data[r][b] = (byte) acc;
            }
        return data;
    }

    static int[][] invert(int[][] A, int k) {
        int[][] m = new int[k][2 * k];
        for (int i = 0; i < k; i++) { System.arraycopy(A[i], 0, m[i], 0, k); m[i][k + i] = 1; }
        for (int col = 0; col < k; col++) {
            int piv = -1;
            for (int r = col; r < k; r++) if (m[r][col] != 0) { piv = r; break; }
            if (piv < 0) throw new RuntimeException("singular");
            int[] tmp = m[col]; m[col] = m[piv]; m[piv] = tmp;
            int iv = inv(m[col][col]);
            for (int j = 0; j < 2 * k; j++) m[col][j] = mul(m[col][j], iv);
            for (int r = 0; r < k; r++) if (r != col && m[r][col] != 0) {
                int f = m[r][col];
                for (int j = 0; j < 2 * k; j++) m[r][j] ^= mul(f, m[col][j]);
            }
        }
        int[][] out = new int[k][k];
        for (int i = 0; i < k; i++) System.arraycopy(m[i], k, out[i], 0, k);
        return out;
    }

    /** Split a body into k equal data shards (4-byte big-endian length header prepended, zero-padded). */
    public static byte[][] split(byte[] body, int k) {
        byte[] wl = new byte[4 + body.length];
        wl[0] = (byte) (body.length >>> 24); wl[1] = (byte) (body.length >>> 16);
        wl[2] = (byte) (body.length >>> 8); wl[3] = (byte) body.length;
        System.arraycopy(body, 0, wl, 4, body.length);
        int sl = (wl.length + k - 1) / k;
        byte[][] data = new byte[k][sl];
        for (int i = 0; i < wl.length; i++) data[i / sl][i % sl] = wl[i];
        return data;
    }
    public static byte[] join(byte[][] data) {
        int sl = data[0].length; byte[] all = new byte[data.length * sl];
        for (int i = 0; i < data.length; i++) System.arraycopy(data[i], 0, all, i * sl, sl);
        int len = ((all[0] & 0xff) << 24) | ((all[1] & 0xff) << 16) | ((all[2] & 0xff) << 8) | (all[3] & 0xff);
        byte[] body = new byte[len]; System.arraycopy(all, 4, body, 0, len); return body;
    }

    public static void main(String[] a) {
        java.util.Random rnd = new java.util.Random(7);
        int K = 2, N = 4; ReedSolomon rs = new ReedSolomon(K, N);
        boolean ok = true; int trials = 500;
        for (int t = 0; t < trials && ok; t++) {
            byte[] body = new byte[1 + rnd.nextInt(800)]; rnd.nextBytes(body);
            byte[][] data = split(body, K); int sl = data[0].length;
            byte[][] shards = rs.encode(data);
            boolean[] present = new boolean[N];
            java.util.List<Integer> idx = new java.util.ArrayList<>();
            for (int i = 0; i < N; i++) idx.add(i);
            java.util.Collections.shuffle(idx, rnd);
            byte[][] avail = new byte[N][];
            for (int i = 0; i < K; i++) { present[idx.get(i)] = true; avail[idx.get(i)] = shards[idx.get(i)]; }
            byte[] body2 = join(rs.decode(avail, present, sl));
            if (!java.util.Arrays.equals(body, body2)) { ok = false; System.out.println("FAIL trial " + t + " (kept shards " + idx.subList(0, K) + ")"); }
        }
        System.out.println(ok ? ("RS self-test PASS: " + trials + " trials, k=2 n=4, any 2 of 4 reconstruct any body") : "RS self-test FAIL");
    }
}
