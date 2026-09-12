import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;

public class DumpFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "ghidra-funcs.csv";
        FileWriter w = new FileWriter(outPath);
        w.write("addr,name\n");
        int n = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            w.write(f.getEntryPoint().toString() + "," + f.getName() + "\n");
            n++;
        }
        w.close();
        println("dumped " + n + " functions to " + outPath);
    }
}
