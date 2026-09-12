import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import java.io.FileWriter;

public class DumpAsm extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs()[0];
        FileWriter w = new FileWriter(outPath);
        Listing listing = currentProgram.getListing();
        for (int i = 1; i < getScriptArgs().length; i++) {
            String[] parts = getScriptArgs()[i].split(":");
            Address start = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseUnsignedLong(parts[0], 16));
            int count = Integer.parseInt(parts[1]);
            w.write("===== asm @ " + parts[0] + " =====\n");
            var it = listing.getCodeUnits(start, true);
            int n = 0;
            while (it.hasNext() && n < count) {
                CodeUnit cu = it.next();
                w.write(cu.getAddress().toString() + " " + cu.toString() + "\n");
                n++;
            }
            w.write("\n");
        }
        w.close();
        println("asm dumped to " + outPath);
    }
}
