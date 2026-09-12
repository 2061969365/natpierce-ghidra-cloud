import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;

public class DecompileBatch extends GhidraScript {
    @Override
    public void run() throws Exception {
        String listPath = getScriptArgs()[0];
        String outPath = getScriptArgs()[1];
        FileWriter w = new FileWriter(outPath, true);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        BufferedReader r = new BufferedReader(new FileReader(listPath));
        String line;
        int ok = 0, fail = 0;
        while ((line = r.readLine()) != null) {
            line = line.trim();
            if (line.length() == 0 || line.startsWith("#"))
                continue;
            int ci = line.indexOf(':');
            String astr = line.substring(0, ci);
            String name = line.substring(ci + 1);
            try {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(Long.parseUnsignedLong(astr, 16));
                DecompileResults res = decomp.decompileFunction(
                        currentProgram.getFunctionManager().getFunctionAt(a), 120, monitor);
                w.write("===== " + name + " @ " + astr + " =====\n");
                w.write(res.getDecompiledFunction() != null
                        ? res.getDecompiledFunction().getC() : "DECOMPILE-FAILED\n");
                w.write("\n");
                ok++;
            } catch (Exception e) {
                w.write("===== " + name + " @ " + astr + " =====\nERROR: " + e + "\n\n");
                fail++;
            }
        }
        r.close();
        w.close();
        decomp.dispose();
        println("batch done ok=" + ok + " fail=" + fail + " -> " + outPath);
    }
}
