import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class PrintMem extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        for (String spec : getScriptArgs()) {
            int ci = spec.indexOf(':');
            String astr = spec.substring(0, ci);
            int len = Integer.parseInt(spec.substring(ci + 1));
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseUnsignedLong(astr, 16));
            byte[] buf = new byte[len];
            try {
                mem.getBytes(a, buf);
                StringBuilder hex = new StringBuilder();
                StringBuilder asc = new StringBuilder();
                for (byte b : buf) {
                    hex.append(String.format("%02x ", b));
                    asc.append((b >= 32 && b < 127) ? (char) b : '.');
                }
                println(astr + " [" + len + "] hex=" + hex + " asc=" + asc);
            } catch (Exception e) {
                println(astr + " ERROR " + e);
            }
        }
    }
}
