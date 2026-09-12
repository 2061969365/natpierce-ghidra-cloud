import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class FindStringRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs()[0];
        List<byte[]> needles = new ArrayList<byte[]>();
        List<String> needleStr = new ArrayList<String>();
        for (int i = 1; i < getScriptArgs().length; i++) {
            needleStr.add(getScriptArgs()[i]);
            needles.add(getScriptArgs()[i].getBytes(StandardCharsets.US_ASCII));
        }
        FileWriter w = new FileWriter(outPath);
        w.write("needle|addr|function@entry\n");
        Memory mem = currentProgram.getMemory();
        int hits = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.getSize() > 128 * 1024 * 1024)
                continue;
            byte[] buf = new byte[(int) block.getSize()];
            try {
                block.getBytes(block.getStart(), buf);
            } catch (Exception e) {
                continue;
            }
            for (int n = 0; n < needles.size(); n++) {
                byte[] nd = needles.get(n);
                int from = 0;
                while (true) {
                    int at = indexOf(buf, nd, from);
                    if (at < 0)
                        break;
                    Address a = block.getStart().add(at);
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
                    // find code refs to this string address
                    StringBuilder callers = new StringBuilder();
                    for (var ref : currentProgram.getReferenceManager().getReferencesTo(a)) {
                        Function cf = currentProgram.getFunctionManager()
                                .getFunctionContaining(ref.getFromAddress());
                        if (cf != null)
                            callers.append(cf.getName()).append("@").append(cf.getEntryPoint()).append(";");
                        if (callers.length() > 400)
                            break;
                    }
                    w.write(needleStr.get(n) + "|" + a + "|"
                            + (f != null ? f.getName() + "@" + f.getEntryPoint() : "-") + "|"
                            + callers + "\n");
                    hits++;
                    from = at + 1;
                    if (hits > 20000)
                        break;
                }
                if (hits > 20000)
                    break;
            }
            if (hits > 20000)
                break;
        }
        w.close();
        println("string refs done hits=" + hits + " -> " + outPath);
    }

    private int indexOf(byte[] hay, byte[] nd, int from) {
        outer: for (int i = from; i <= hay.length - nd.length; i++) {
            for (int j = 0; j < nd.length; j++) {
                if (hay[i + j] != nd[j])
                    continue outer;
            }
            return i;
        }
        return -1;
    }
}
