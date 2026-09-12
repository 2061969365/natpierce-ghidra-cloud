import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class XrefsTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (int i = 0; i < getScriptArgs().length; i++) {
            String astr = getScriptArgs()[i];
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseUnsignedLong(astr, 16));
            Function callee = currentProgram.getFunctionManager().getFunctionAt(a);
            String cname = callee != null ? callee.getName() : astr;
            println("### callers of " + cname + ":");
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
                Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                println("  " + (cf != null ? cf.getName() + " @ " + cf.getEntryPoint() : r.getFromAddress().toString()));
            }
        }
    }
}
