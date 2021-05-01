//Attempts to refactor parts of the NXT RS3 Win64 client. This might break.
//
// This WILL override ANY data you have. Make a backup BEFORE running this. You have been warned.
//
// Don't question the code at some points. This was thrown together at very-early am.
//@author Techdaan
//@category _NXT_
//@keybinding
//@menupath NXT.RS3 NXT Refactorer
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

public class RS3NXTRefactorer extends GhidraScript {

	private static class Settings {
		static boolean FIND_CLIENT_PROT = true;
		static boolean PRINT_PROTOCOL_INFO = true;

		static int MIN_CLIENT_PROTS = 120; // minimum number of client prot packets, in 918 there are 124
		static int MAX_CLIENT_PROTS = 130; // maximum number of client prot packets, in 918 there are 124
	}

	private static String TODO_DESC = "<RS3 Refactorer: TODO>";

	private static class Types {
		// Built-ins
		static DataType LONGLONG;
		static DataType BOOL;
		static DataType VOID;
		static DataType UINT;
		static DataType INT;
		static DataType BYTE;

		// Structs
		static Structure S_ISAAC;
		static Structure S_CONNECTION_MANAGER;
		static Structure S_HEAP_INTERFACE;
		static Structure S_CLIENT;
		static Structure S_PACKET;
		static Structure S_CLIENT_PROT;

		// Classes (These are *technically* namespaces)
		static GhidraClass C_ISAAC;
		static GhidraClass C_CONNECTION_MANAGER;
		static GhidraClass C_HEAP_INTERFACE;
		static GhidraClass C_CLIENT;
		static GhidraClass C_PACKET;
		static GhidraClass C_CLIENT_PROT;
	}

	@Override
	protected void run() throws Exception {
		//noinspection ConstantConditions
		if (NUM_PACKETS != PACKET_NAMES.length) {
			throw new IllegalStateException("NUM_PACKETS =/= PACKET_NAMES length");
		}

		printf("Initializing default data types%n");
		initDefaultDataTypes();

		printf("Creating/updating data structures%n");
		createDataStructures();

		printf("Refactoring: App entry function%n");
		Function fn = findAppEntryFunction();
		renameFunction(fn, "jag::App::MainInit");
		refactorAppEntry(fn);

		printf("Refactoring: jag::Isaac%n");
		refactorIsaac();

		printf("Refactoring jag::ConnectionManager%n");
		refactorConnectionManagerCtor();

		printf("%nRefactoring ServerProt%n");
		refactorPackets();

		if (Settings.FIND_CLIENT_PROT) {
			printf("%nRefactoring ClientProt%n");
			clientProtPrototype();
		}

		if (Settings.PRINT_PROTOCOL_INFO) {
			printf("%n// Packet sizes for ServerProt (server to client), mapped opcode->size%n");
			printf("val CLIENT_PROT_SIZES = mapOf(%n");
			for (int i = 0; i < clientProt.length; i++) {
				ClientProt info = clientProt[i];
				if (info == null) continue;

				printf("    %d to %d,%n", info.opcode, info.size);
			}
			printf(")%n");


			printf("%n// Packet names for ServerProt (server to client), mapped opcode->name%n");
			printf("val SERVER_PROT_NAMES = mapOf(%n");
			for (int i = 0; i < packets.length; i++) {
				ServerProtInfo info = packets[i];
				if (info.name == null) continue;

				printf("    %d to \"%s\",%n", info.opcode, info.name);
			}
			printf(")%n");

			printf("%n// Packet sizes for ServerProt (server to client), mapped opcode->size%n");
			printf("val SERVER_PROT_SIZES = mapOf(%n");
			for (int i = 0; i < packets.length; i++) {
				ServerProtInfo info = packets[i];
				if (info.name == null) continue;

				printf("    %d to %d,%n", info.opcode, info.size);
			}
			printf(")%n");
		}
	}

	private static class ClientProt {
		final Address address;
		final int opcode;
		final int size;

		ClientProt(Address address, int opcode, int size) {
			this.address = address;
			this.opcode = opcode;
			this.size = size;
		}
	}

	private ClientProt[] clientProt = null;

	private Pair<Function, Instruction> findMakeClientMessage(Function fn) {
		Function makeClientMessageFn = null;
		Instruction makeClientMessageInsn = null;
		outer:
		for (Instruction insn : getFunctionInstructions(fn)) {
			if (!insn.getMnemonicString().equals("CALL"))
				continue;
			if (insn.getNumOperands() == 0 || insn.getAddress(0) == null)
				continue;

			Function called = getFunctionAt(insn.getAddress(0));
			if (called == null)
				continue;

			for (Instruction inner : getFunctionInstructions(called)) {
				if (!inner.getMnemonicString().equals("CALL"))
					continue;
				if (inner.getNumOperands() == 0 || inner.getAddress(0) == null)
					continue;

				Function called2 = getFunctionAt(inner.getAddress(0));
				if (called2 == null)
					continue;

				if (called2.getName().equals("_Throw_C_error")) {
					if (makeClientMessageFn != null) {
						throw new IllegalStateException("more than one option for MakeClientMessage found, disable ClientProt finding");
					}

					makeClientMessageFn = called;
					makeClientMessageInsn = insn;
					continue outer;
				}
			}
		}
		return Pair.of(makeClientMessageFn, makeClientMessageInsn);
	}

	private void clientProtPrototype() throws Exception {
		// reverse lookup...
		SymbolIterator it = currentProgram.getSymbolTable().getSymbols("m_currentTimeMS");
		if (!it.hasNext()) throw new IllegalStateException("m_currentTimeMS not found");
		Symbol m_currentTimeMS = it.next();
		if (it.hasNext()) throw new IllegalStateException("more than one m_currentTimeMS found?");

		Pair<Function, Instruction> pair = null;
		outer:
		for (Reference ref : getReferencesTo(m_currentTimeMS.getAddress())) {
			Function f = getFunctionContaining(ref.getFromAddress());
			if (f == null) continue;

			for (Instruction insn : getFunctionInstructions(f)) {
				if (insn.getMnemonicString().equals("MOV") && insn.getLong(2) == 0x6666666666666667L) {
//					printf("got %s , new is %s%n", src0.getEntryPoint(), f.getEntryPoint());
//					printf("matches = %s at %s%n", findMakeClientMessage(src0), insn.getAddress());
					Pair<Function, Instruction> local = findMakeClientMessage(f);
//					printf("can work = %s @ %s%n", findMakeClientMessage(f), insn.getAddress());
					if (local.getKey() != null) {
						if (pair != null)
							throw new IllegalStateException("more than one MakeClientMessage qualifier found, disable ClientProt finding: " + f.getEntryPoint());
						pair = local;
//						printf("got %s , new is %s%n", src0.getEntryPoint(), f.getEntryPoint());
//						printf("matches = %s at %s%n", findMakeClientMessage(src0), insn.getAddress());
//						printf("got %s , new is %s%n", src0.getEntryPoint(), f.getEntryPoint());
//						printf("matches = %s at %s%n", findMakeClientMessage(src0), insn.getAddress());
					}


//					src0 = f;
					continue outer;
				}
			}
		}
		if (pair == null) {
			throw new IllegalStateException("MakeClientMessage not found, disable ClientProt finding");
		}
		Function makeClientMessageFn = pair.getKey();
		Instruction makeClientMessageInsn = pair.getValue();

//		printf("Found src0 on our way to ClientProt at %s%n", src0.getEntryPoint());
//		Instruction makeClientMessageInsn = null;
//		Function makeClientMessageFn = null;
//		outer:
//		for (Instruction insn : getFunctionInstructions(src0)) {
//			if (!insn.getMnemonicString().equals("CALL"))
//				continue;
//			if (insn.getNumOperands() == 0 || insn.getAddress(0) == null)
//				continue;
//
//			Function called = getFunctionAt(insn.getAddress(0));
//			if (called == null)
//				continue;
//
//			for (Instruction inner : getFunctionInstructions(called)) {
//				if (!inner.getMnemonicString().equals("CALL"))
//					continue;
//				if (inner.getNumOperands() == 0 || inner.getAddress(0) == null)
//					continue;
//
//				Function called2 = getFunctionAt(inner.getAddress(0));
//				if (called2 == null)
//					continue;
//
//				if (called2.getName().equals("_Throw_C_error")) {
//					if (makeClientMessageInsn != null) {
//						throw new IllegalStateException("more than one option for MakeClientMessage found, disable ClientProt finding");
//					}
//
//					makeClientMessageInsn = insn;
//					makeClientMessageFn = called;
//					continue outer;
//				}
//			}
//		}
//		if (makeClientMessageInsn == null) {
//			throw new IllegalStateException("MakeClientMessage not found, disable ClientProt finding");
//		}

		Address someClientProt = null;
		renameFunction(makeClientMessageFn, "jag::ServerConnection::MakeClientMessage");
		int i = 10;
		while (i-- > 0) {
			makeClientMessageInsn = makeClientMessageInsn.getPrevious();
			if (makeClientMessageInsn.getMnemonicString().equals("LEA") && makeClientMessageInsn.getRegister(0).getBaseRegister().getName().equals("R8")) {
				someClientProt = makeClientMessageInsn.getAddress(1);
				break;
			}
		}
		if (someClientProt == null) {
			throw new IllegalStateException("Couldn't find a ClientProt struct, please disable ClientProt finding");
		}
		printf("Found a ClientProt struct at %s%n", someClientProt);

		Address registerClientProt = null;
		for (Reference reference : getReferencesTo(someClientProt.subtract(4))) {
			Instruction insn = getInstructionAt(reference.getFromAddress());
			i = 5;
			while (i-- > 0) {
				insn = insn.getNext();
				if (insn.getMnemonicString().equals("JMP")) {
					if (registerClientProt != null) {
						throw new IllegalStateException("more than one register client prot qualifier found, disable ClientProt finding");
					}

					int numReferences = getReferencesTo(insn.getAddress(0)).length;
					if (numReferences > Settings.MIN_CLIENT_PROTS && numReferences < Settings.MAX_CLIENT_PROTS)
						registerClientProt =insn.getAddress(0);
					break;
				}
			}
		}
		if (registerClientProt == null) {
			throw new IllegalStateException("no client prot register function found, disable ClientProt finding");
		}

		// rcx -> TcpConnectionBase
		// rdx -> ?
		// r8  -> message / ClientProt
		// r9  -> ?
		Reference[] references = getReferencesTo(registerClientProt);
		clientProt = new ClientProt[references.length];
		printf("Found %d references to REGISTER_CLIENT_MESSAGE%n", references.length);
		for (Reference reference : references) {
			Instruction insn = getInstructionAt(reference.getFromAddress());
			while (getReferencesTo(insn.getAddress()).length == 0)
				insn = insn.getPrevious(); // roll back to begin of function

			Address clientProt = null;
			int opcode = -100;
			int size = -100;

			i = 10;
			boolean rcx = false, rdx = false, r8 = false;
			while (i-- > 0 && (!rcx || !rdx || !r8)) {
				if (insn.getRegister(0) == null) {
					insn = insn.getNext();
					continue;
				}

				String register = insn.getRegister(0).getBaseRegister().getName();
				switch (register) {
					case "RCX":
						if (!insn.getMnemonicString().equals("LEA"))
							throw new IllegalStateException("expected LEA for loading ClientProt struct");
						clientProt = insn.getAddress(1);
						rcx = true;
						break;
					case "RDX":
						if (insn.getMnemonicString().equals("MOV")) {
							opcode = insn.getInt(1);
						} else if (insn.getMnemonicString().equals("XOR") && insn.getRegister(0).getBaseRegister().getName().equals("RDX") && insn.getRegister(1).getBaseRegister().getName().equals("RDX")) {
							opcode = 0;
						} else if (insn.getMnemonicString().equals("LEA") && size != -100 && insn.getOpObjects(1).length == 2) {
							if (!((Register) insn.getOpObjects(1)[0]).getBaseRegister().getName().equals("R8"))
								throw new IllegalStateException("unexpected register, expected r8");

							opcode = (int) (size + ((Scalar) insn.getOpObjects(1)[1]).getValue());
						} else {
							throw new RuntimeException(" unsure how to get opcode from " + insn + " [size = " + size + "]");
						}

						/*
						} else if (opcodeInsns.size() == 1 && opcodeInsns.get(0).getMnemonicString().equals("LEA") && opcodeInsns.get(0).getOpObjects(1).length == 2) {
						if (!opcodeInsns.get(0).getRegister(0).getBaseRegister().getName().equals("RDX"))
							throw new IllegalStateException("WHAT");
						if (!((Register) opcodeInsns.get(0).getOpObjects(1)[0]).getBaseRegister().getName().equals("R8"))
							throw new IllegalStateException("WHAT 2");

						List<Instruction> sizeInsns = t.getRegisterValues("R8");
						boolean xoredd = false;

						Instruction bs = getInstructionAt(regF.getEntryPoint());
						Instruction ss = getInstructionAt(ref.getFromAddress());
						while (!bs.equals(ss)) {
							bs = bs.getNext();
							if (bs.getMnemonicString().equals("XOR") && bs.getRegister(0).getBaseRegister().getName().equals("R8") && bs.getRegister(1).getBaseRegister().getName().equals("R8")) {
								xoredd = true;
							}
						}

						if (!xoredd) throw new IllegalStateException("the fuck " + sizeInsns);
						opcode = (int) (((Scalar) opcodeInsns.get(0).getOpObjects(1)[1]).getValue());
					}
						 */

						rdx = true;
						break;
					case "R8":
						if (insn.getMnemonicString().equals("R8")) {
							size = insn.getInt(1);
						} else if (insn.getMnemonicString().equals("XOR") && insn.getRegister(0).getBaseRegister().getName().equals("R8") && insn.getRegister(1).getBaseRegister().getName().equals("R8")) {
							size = 0;
						} else if (insn.getMnemonicString().equals("LEA") && opcode != -100 && insn.getOpObjects(1).length == 2) {
							if (!((Register) insn.getOpObjects(1)[0]).getBaseRegister().getName().equals("RDX"))
								throw new IllegalStateException("unexpected register, expected rdx");

							size = (int) (opcode + ((Scalar) insn.getOpObjects(1)[1]).getValue());
						} else {
							throw new RuntimeException(" unsure how to get size from " + insn + " [opcode = " + opcode + "]");
						}
						r8 = true;
						break;
				}

				insn = insn.getNext();
			}

			if (clientProt == null || opcode == -100 || size == -100) {
				throw new IllegalStateException("failed to read clientprot from address " + reference.getFromAddress());
			}

			this.clientProt[opcode] = new ClientProt(clientProt, opcode, size);

			setDataType(clientProt, Types.S_CLIENT_PROT, 8);
			setLabel(clientProt, "jag::ClientProt::ClientProtOP_" + opcode);
		}
	}

	private void setDataType(Address address, DataType type, int length) throws Exception {
		Listing listing = currentProgram.getListing();
		Data sourceData = listing.getDataAt(address);
		if (sourceData == null) return;

		listing.clearCodeUnits(address, address.add(length), false);
		listing.createData(address, type, length);
	}

	private Data setDataType(Program program, Address address, DataType dataType, int length) {

		int txID = program.startTransaction("Change Data Type");
		boolean commit = false;
		try {
			Listing listing = program.getListing();
			Data sourceData = listing.getDataAt(address);
			if (sourceData == null) {
				return null;
			}
			listing.clearCodeUnits(address, sourceData.getMaxAddress(), false);
			Data data;
			if (length > 0) {
				data = listing.createData(address, dataType, length);
			} else {
				data = listing.createData(address, dataType);
			}
			commit = true;
			return data;
		} catch (Exception e) {
			// Commit is false by default so nothing else to do.
			return null;
		} finally {
			program.endTransaction(txID, commit);
		}
	}

	private void createDataStructures() throws DuplicateNameException, InvalidInputException {
		printf(" - jag::Isaac%n");
		Types.C_ISAAC = getOrCreateClass("jag::Isaac");
		Types.S_ISAAC = getStructureForClass(Types.C_ISAAC);
		Types.S_ISAAC.deleteAll();
		resizeStructure(Types.S_ISAAC, 2064);
		Types.S_ISAAC.replaceAtOffset(0, Types.UINT, 4, "values_left", "The amount of values left before having to generate new ones");
		Types.S_ISAAC.replaceAtOffset(4, arr(Types.UINT, 256, 4), 1024, "rand_results", "The generated random results");
		Types.S_ISAAC.replaceAtOffset(1028, arr(Types.UINT, 256, 4), 1024, "mm", TODO_DESC);
		Types.S_ISAAC.replaceAtOffset(2052, Types.INT, 4, "aa", TODO_DESC);
		Types.S_ISAAC.replaceAtOffset(2056, Types.INT, 4, "bb", TODO_DESC);
		Types.S_ISAAC.replaceAtOffset(2060, Types.INT, 4, "cc", TODO_DESC);

		printf(" - jag::HeapInterface");
		Types.C_HEAP_INTERFACE = getOrCreateClass("jag::HeapInterface");
		Types.S_HEAP_INTERFACE = getStructureForClass(Types.C_HEAP_INTERFACE);

		printf(" - jag::Client%n");
		Types.C_CLIENT = getOrCreateClass("jag::Client");
		Types.S_CLIENT = getStructureForClass(Types.C_CLIENT); // We will initialize this later on.

		printf(" - jag::ConnectionManager%n");
		Types.C_CONNECTION_MANAGER = getOrCreateClass("jag::ConnectionManager");
		Types.S_CONNECTION_MANAGER = getStructureForClass(Types.C_CONNECTION_MANAGER);
		if (Types.S_CONNECTION_MANAGER.getLength() < 0x10)
			resizeStructure(Types.S_CONNECTION_MANAGER, 0x10); // We will resize this later on
		Types.S_CONNECTION_MANAGER.replaceAtOffset(0x8, ptr(Types.S_CLIENT), 8, "client", TODO_DESC);

		printf("- jag::Packet%n");
		Types.C_PACKET = getOrCreateClass("jag::Packet");
		Types.S_PACKET = getStructureForClass(Types.C_PACKET);
		resizeStructure(Types.S_PACKET, 0x20);
		Types.S_PACKET.replaceAtOffset(0x0, Types.LONGLONG, 8, "field_0x0", TODO_DESC);
		Types.S_PACKET.replaceAtOffset(0x8, Types.LONGLONG, 8, "capacity", "The capacity of the buffer (todo: confirm)");
		Types.S_PACKET.replaceAtOffset(0x10, ptr(Types.BYTE), 8, "buffer", "The backing buffer");
		Types.S_PACKET.replaceAtOffset(0x18, Types.LONGLONG, 8, "offset", "The offset (writer AND reader offset) in the buffer");

		printf("- jag::ClientProt%n");
		Types.C_CLIENT_PROT = getOrCreateClass("jag::ClientProt");
		Types.S_CLIENT_PROT = getStructureForClass(Types.C_CLIENT_PROT);
		Types.S_CLIENT_PROT.deleteAll();
		resizeStructure(Types.S_CLIENT_PROT, 8);
		Types.S_CLIENT_PROT.replaceAtOffset(0, Types.UINT, 4, "opcode", "Opcode of this ClientProt");
		Types.S_CLIENT_PROT.replaceAtOffset(4, Types.INT, 4, "size", "Size of this ClientProt");
		Types.S_CLIENT_PROT.setDescription("ClientProt is also used by login packets, opcodes may overlap with in-game protocol definitions.");
	}

	/**
	 * Attempts to find the KERNEL32.DLL:SetErrorMode method. This is called once in the main app method.
	 */
	private Function findAppEntryFunction() {
		Symbol symbol = null;

		for (Symbol s : currentProgram.getSymbolTable().getSymbols("SetErrorMode")) {
			symbol = s;
		}

		if (symbol == null)
			throw new NullPointerException("Could not find SetErrorMode");

		int count = 0;
		Function f = null;
		for (Reference reference : getReferencesTo(symbol.getAddress())) {
			Function l = getCurrentProgram().getFunctionManager().getFunctionContaining(reference.getFromAddress());
			if (l != null) {
				f = l;
				count++;
			}
		}

		if (count > 1) {
			throw new IllegalStateException("Multiple possibilities of SetErrorMode xrefs");
		}

		if (f != null) {
			return f;
		}

		throw new NullPointerException("Could not find app entry function");
	}

	/**
	 * Handles the app's main entry. This performs the following operations:
	 * <p>
	 * - Finds function jag::HeapInterface::Alloc
	 * This is the first method with a LOT of calls in the entrypoint. Found by checking amount of xrefs
	 * <p>
	 * - Finds address jag::HeapInterface::g_pHeapInterface
	 * This is the first argument to jag::HeapInterface::Alloc
	 * <p>
	 * - Finds the size of structure jag::Client
	 * This is the second argument to the first call of jag::HeapInterface::Alloc
	 * <p>
	 * - Finds the constructor jag::Client::Client
	 * This is the first function after the jag::HeapInterface::Alloc class
	 *
	 * @param fn The app main entry
	 */
	private void refactorAppEntry(Function fn) throws Exception {
		int XREF_THRESHOLD = 1500; // Min. number of references to jag::HeapInterface::Alloc
		boolean foundAlloc = false;

		RegisterTracker tracker = new RegisterTracker();
		for (Instruction insn : getFunctionInstructions(fn)) {
			tracker.update(insn);

			if (!insn.getMnemonicString().equals("CALL"))
				continue;

			// Some call functions don't actually have addresses (eg. when using a vtable)
			if (insn.getNumOperands() == 0 || insn.getAddress(0) == null)
				continue;

			// And some don't have a function at all
			Function called = getFunctionAt(insn.getAddress(0));
			if (called == null)
				continue;

			if (!foundAlloc && getReferencesTo(called.getEntryPoint()).length > XREF_THRESHOLD) {
				Instruction rcx = tracker.getRegisterValue("RCX");
				Instruction rdx = tracker.getRegisterValue("RDX");

				setLabel(rcx.getAddress(1), "jag::HeapInterface::g_pHeapInterface");
				resizeStructure(Types.S_CLIENT, rdx.getInt(1));

				renameFunction(called, "jag::HeapInterface::Alloc");
				called.setCallingConvention("__thiscall");
				called.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.USER_DEFINED,
						new ParameterImpl("num_bytes", Types.LONGLONG, currentProgram),
						new ParameterImpl("param2", Types.LONGLONG, currentProgram));

				foundAlloc = true;
				continue;
			}

			renameFunction(called, "jag::Client::Client");
			return;
		}
	}

	/**
	 * Handles a few ISAAC functions. This performs the following operations:
	 * <p>
	 * - Finds function jag::Isaac::Init
	 * This is the only method in the client with references to a constant and certain bit shifting.
	 * <p>
	 * - Finds function jag::Isaac::Generate
	 * This is the only method that's called from function jag::Isaac::Init
	 */
	private void refactorIsaac() throws Exception {
		List<Function> initQualifiers = new ArrayList<>();

		fn_loop:
		for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
			for (Instruction insn : getFunctionInstructions(fn)) {
				if (!insn.getMnemonicString().equals("MOV"))
					continue;

				if (insn.getInt(0) == 0x9e3779b9 || insn.getInt(1) == 0x9e3779b9 || insn.getInt(2) == 0x9e3779b9) {
					boolean shl8 = false;
					boolean shla = false;
					boolean shr10 = false;

					for (Instruction inner : getFunctionInstructions(fn)) {
						if (inner.getMnemonicString().equals("SHL")) {
							if (inner.getByte(2) == 0x8)
								shl8 = true;
							else if (inner.getByte(2) == 0xa)
								shla = true;
						} else if (inner.getMnemonicString().equals("SHR")) {
							if (inner.getByte(2) == 0x10)
								shr10 = true;
						}
					}

					if (shl8 && shla && shr10) {
						initQualifiers.add(fn);
					}

					continue fn_loop;
				}
			}
		}

		if (initQualifiers.size() != 1) {
			throw new IllegalStateException("couldn't find jag::Isaac::Init qualifiers! (found " + initQualifiers.size() + ")");
		}

		Function init = initQualifiers.get(0);
		renameFunction(init, "jag::Isaac::Init");
		init.setCallingConvention("__thiscall");
		init.setReturnType(Types.VOID, SourceType.USER_DEFINED);
		init.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.USER_DEFINED,
				new ParameterImpl("seeds", ptr(Types.UINT), currentProgram));

		// Find generate
		Function generate = null;
		for (Instruction insn : getFunctionInstructions(init)) {
			if (insn.getMnemonicString().equals("CALL")) {
				if (generate != null) {
					throw new IllegalStateException("More than 1 CALL in jag::Isaac::Init");
				}

				generate = getFunctionAt(insn.getAddress(0));
			}
		}

		if (generate == null) {
			throw new IllegalStateException("Failed to find jag::Isaac::Generate in jag::Isaac::Init");
		}

		renameFunction(generate, "jag::Isaac::Generate");
		generate.setCallingConvention("__thiscall");
		generate.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.USER_DEFINED);
		generate.setReturnType(Types.VOID, SourceType.USER_DEFINED);
	}

	private Function connectionManagerCtor;

	/**
	 * Handles the connection manager ctor. This performs the following operations:
	 * <p>
	 * - Finds function jag::ConnectionManager::ConnectionManager
	 * There are only a few methods that have the int constant 20_000, which is always at the end of the function. So we
	 * scan instructions backwards to filter out the other few remaining functions.
	 */
	private void refactorConnectionManagerCtor() throws Exception {
		Map<Instruction, Function> qualifiers = new HashMap<>();

		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			for (Instruction insn : getFunctionInstructions(f)) {
				if (insn.getMnemonicString().equals("ADD")) {
					if (insn.getInt(0) == 20_000 || insn.getInt(1) == 20_000 || insn.getInt(2) == 20_000) {
						qualifiers.put(insn, f);
					}
				}
			}
		}

		Function ctor = null;
		Instruction needle = null;
		Iterator<Map.Entry<Instruction, Function>> it = qualifiers.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<Instruction, Function> entry = it.next();
			Instruction insn = entry.getKey();

			int dist = 0;
			while (!insn.getMnemonicString().equals("RET")) {
				insn = insn.getNext();
				dist++;
			}

			if (dist > 15) {
				it.remove();
				continue;
			}

			needle = entry.getKey();
			ctor = entry.getValue();
		}

		if (qualifiers.size() > 1) {
			qualifiers.forEach((insn, f) -> printerr("at: " + f.getEntryPoint() + " (" + f.getName() + ") @ " + insn.getAddress()));
			throw new IllegalStateException("Found more than one qualifier for jag::ConnectionManager::ConnectionManager");
		}

		if (ctor == null)
			throw new NullPointerException("Found no qualifiers for jag::ConnectionManager::ConnectionManager");

		renameFunction(ctor, "jag::ConnectionManager::ConnectionManager");
		ctor.setCallingConvention("__thiscall");
		ctor.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.USER_DEFINED, new ParameterImpl("client", ptr(Types.S_CLIENT), currentProgram));
		ctor.setReturnType(ptr(Types.S_CONNECTION_MANAGER), SourceType.USER_DEFINED);

		RegisterTracker tracker = new RegisterTracker();
		for (Instruction insn : getFunctionInstructions(ctor)) {
			if (insn == needle) {
				String register = insn.getRegister(0).getName();
				Instruction setter = tracker.getRegisterValue(register);

				Address m_currentTimeMS = null;
				for (int k = 0; k < 5; k++) {
					Address a = setter.getAddress(k);
					if (a != null) {
						m_currentTimeMS = a;
					}
				}

				if (m_currentTimeMS == null) {
					throw new IllegalStateException("Couldn't find jag::FrameTime::m_currentTimeMS");
				}

				setLabel(m_currentTimeMS, "jag::FrameTime::m_currentTimeMS");

				break;
			}

			tracker.update(insn);
		}

		Reference[] xrefs = getReferencesTo(ctor.getEntryPoint());
		if (xrefs.length != 1) {
			throw new IllegalStateException("0 or more than 1 xref to jag::ConnectionManager::ConnectionManager");
		}

		Instruction insn = getInstructionAt(xrefs[0].getFromAddress()).getPrevious();
		while (!insn.getMnemonicString().equals("CALL")) insn = insn.getPrevious();

		while ((insn = insn.getPrevious()) != null) {
			if (!insn.getMnemonicString().equals("MOV")) {
				continue;
			}

			if (insn.getRegister(0) == null || !insn.getRegister(0).getName().equals("RDX")) {
				continue;
			}

			int size = insn.getInt(1);

			resizeStructure(Types.S_CONNECTION_MANAGER, size);

			break;
		}

		connectionManagerCtor = ctor;
	}

	private Function serverProtReg1;

	/**
	 * Black magic.
	 */
	private void refactorPackets() throws Exception {
		RegisterTracker tracker = new RegisterTracker();
		HashSet<Address> visited = new HashSet<>();

		if (connectionManagerCtor == null) throw new NullPointerException("?");

		try {
			int i = 0;
			for (Instruction insn : getFunctionInstructions(connectionManagerCtor)) {
				tracker.update(insn);

				checkAndNameServerProt(insn);

				if (!insn.getMnemonicString().equals("CALL"))
					continue;

				i++;
				if (i <= 2)
					continue;

				Address addr = insn.getAddress(0);
				if (addr != null)
					refactorPacketsRecursive(insn, getFunctionAt(addr), visited, tracker.waistClone(), tracker.getRegisterValue("RCX"), tracker.getRegisterValue("RDX"));
			}
		} catch (Exception e) {
			if (e.getMessage().equals("yayeeeet")) {
				refactorPackets();
				return;
			} else {
				throw e;
			}
		}

		for (int i = 0; i < packets.length; i++) {
			ServerProtInfo info = packets[i];
			if (info.name == null) continue;

			StringBuilder nameBuilder = new StringBuilder();
			for (String s : info.name.split("_")) {
				if (s.length() < 2) continue;
				nameBuilder.append(s.substring(0, 1).toUpperCase(Locale.ROOT));
				nameBuilder.append(s.substring(1).toLowerCase(Locale.ROOT));
			}

			Address fnAddr = (Address) getDataAt(info.vtable.add(16)).getValue();
			Function fn;
			try {
				fn = getFunctionAt(fnAddr);
				renameFunction(fn, "jag::PacketHandlers::" + nameBuilder);
			} catch (Exception e) {
				createFunction(fnAddr, "jag::PacketHandlers::" + nameBuilder);
				fn = getFunctionAt(fnAddr);
			}
			fn.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.USER_DEFINED,
					new ParameterImpl("param1", Types.LONGLONG, currentProgram),
					new ParameterImpl("packet", ptr(Types.S_PACKET), currentProgram),
					new ParameterImpl("param3", Types.LONGLONG, currentProgram),
					new ParameterImpl("isaac", ptr(Types.S_ISAAC), currentProgram)
			);
			fn.setComment("\n << AUTO REFACTORED BY RS3 NXT REFACTORER >>\nOpcode: " + info.opcode + "\nSize: " + info.size + "\nName: " + info.name);
			println("Found ServerProt " + info);
		}
	}

	HashSet<Address> addresses = new HashSet<>();

	private ServerProtInfo serverProtFromAddress(Address a) {
		if (addresses.isEmpty()) {
			for (ServerProtInfo packet : packets) {
				addresses.add(packet.addr);
			}
		}
		for (int i = 0; i < packets.length; i++) {
			if (a.equals(packets[i].addr))
				return packets[i];
		}
		throw new IllegalStateException("???");
	}

	private void refactorPacketsRecursive(Instruction callInsn, Function fn, HashSet<Address> visited, RegisterTracker tracker, Instruction rcx, Instruction rdx) throws Exception {
		// if fn we called is null...
		if (fn == null)
			return;

		// did we find server prot register
		if (serverProtReg1 == null) {
			if (getReferencesTo(fn.getEntryPoint()).length > 200) {
				visited.remove(fn.getEntryPoint());
				serverProtReg1 = fn;

				while (callInsn.getRegister(0) == null || !callInsn.getRegister(0).getName().equals("RDX")) {
					callInsn = callInsn.getPrevious();
				}

				Address referringTo = callInsn.getAddress(1);

				if (referringTo == null) {
					if (rdx.getMnemonicString().equals("LEA") && rdx.getAddress(1) != null) {
						referringTo = rdx.getAddress(1);
					} else if (rcx.getMnemonicString().equals("LEA") && rcx.getAddress(1) != null) {
						referringTo = rcx.getAddress(1);
					} else {
						printerr("hmm0 " + callInsn + ", " + callInsn.getAddress());
						throw new IllegalStateException("wat");
					}
				}

				Reference[] references = getReferencesTo(referringTo.subtract(0x8));
				if (references.length != 1) {
					throw new IllegalStateException("What @ " + referringTo);
				}

				Function fn2 = getFunctionContaining(references[0].getFromAddress());
				Instruction callTo = null;
				for (Instruction insn : getFunctionInstructions(fn2)) {
					if (!insn.getMnemonicString().equals("CALL"))
						continue;

					if (callTo != null)
						throw new IllegalStateException("wot");

					callTo = insn;
				}

				Function fn3 = getFunctionAt(callTo.getAddress(0));
				Reference[] refs = getReferencesTo(fn3.getEntryPoint());
				if (getReferencesTo(fn3.getEntryPoint()).length != NUM_PACKETS) {
					printerr("hmm " + callInsn + ", " + callInsn.getAddress());
					return;
				}

				for (Reference ref : refs) {
					Function regF = getFunctionContaining(ref.getFromAddress());
					RegisterTracker t = new RegisterTracker();
					Instruction b = getInstructionAt(regF.getEntryPoint());
					Instruction s = getInstructionAt(ref.getFromAddress());
					while (!b.equals(s)) {
						t.update(b);
						b = b.getNext();
					}

					List<Instruction> opcodeInsns = t.getRegisterValues("RDX");
					int opcode = -500;
					if (opcodeInsns.size() == 0) { // probably no need to do this check, but whatever it's 4am i am tired
						boolean xored = false;

						b = getInstructionAt(regF.getEntryPoint());
						s = getInstructionAt(ref.getFromAddress());
						while (!b.equals(s)) {
							b = b.getNext();
							if (b.getMnemonicString().equals("XOR") && b.getRegister(0).getBaseRegister().getName().equals("RDX") && b.getRegister(1).getBaseRegister().getName().equals("RDX")) {
								xored = true;
							}
						}

						if (!xored) throw new IllegalStateException("the fuck");
						opcode = 0;
					} else if (opcodeInsns.size() == 1 && opcodeInsns.get(0).getMnemonicString().equals("MOV")) {
						opcode = opcodeInsns.get(0).getInt(1);
					} else if (opcodeInsns.size() == 1 && opcodeInsns.get(0).getMnemonicString().equals("LEA") && opcodeInsns.get(0).getOpObjects(1).length == 2) {
						if (!opcodeInsns.get(0).getRegister(0).getBaseRegister().getName().equals("RDX"))
							throw new IllegalStateException("WHAT");
						if (!((Register) opcodeInsns.get(0).getOpObjects(1)[0]).getBaseRegister().getName().equals("R8"))
							throw new IllegalStateException("WHAT 2");

						List<Instruction> sizeInsns = t.getRegisterValues("R8");
						boolean xoredd = false;

						Instruction bs = getInstructionAt(regF.getEntryPoint());
						Instruction ss = getInstructionAt(ref.getFromAddress());
						while (!bs.equals(ss)) {
							bs = bs.getNext();
							if (bs.getMnemonicString().equals("XOR") && bs.getRegister(0).getBaseRegister().getName().equals("R8") && bs.getRegister(1).getBaseRegister().getName().equals("R8")) {
								xoredd = true;
							}
						}

						if (!xoredd) throw new IllegalStateException("the fuck " + sizeInsns);
						opcode = (int) (((Scalar) opcodeInsns.get(0).getOpObjects(1)[1]).getValue());
					}

					List<Instruction> sizeInsns = t.getRegisterValues("R8");
					int size = -500;
					if (sizeInsns.size() == 0) { // probably no need to do this check, but whatever it's 4am i am tired
						boolean xored = false;

						b = getInstructionAt(regF.getEntryPoint());
						s = getInstructionAt(ref.getFromAddress());
						while (!b.equals(s)) {
							b = b.getNext();
							if (b.getMnemonicString().equals("XOR") && b.getRegister(0).getBaseRegister().getName().equals("R8") && b.getRegister(1).getBaseRegister().getName().equals("R8")) {
								xored = true;
							}
						}

						if (!xored) throw new IllegalStateException("the fuck " + sizeInsns);
						size = 0;
					} else if (sizeInsns.size() == 1 && sizeInsns.get(0).getMnemonicString().equals("MOV")) {
						if (sizeInsns.get(0).getRegister(0).getBaseRegister().getName().equals("RDX")) {
							size = opcode;
						} else {
							size = sizeInsns.get(0).getInt(2);
						}
					} else if (sizeInsns.size() == 1 && sizeInsns.get(0).getMnemonicString().equals("LEA") && sizeInsns.get(0).getOpObjects(1).length == 2) {
						if (!sizeInsns.get(0).getRegister(0).getBaseRegister().getName().equals("R8"))
							throw new IllegalStateException("WHAT");
						if (!((Register) sizeInsns.get(0).getOpObjects(1)[0]).getBaseRegister().getName().equals("RDX"))
							throw new IllegalStateException("WHAT 2");
						size = (int) (opcode + ((Scalar) sizeInsns.get(0).getOpObjects(1)[1]).getValue());
					}

					ServerProtInfo info = new ServerProtInfo();
					info.opcode = opcode;
					info.size = size;
					info.addr = t.getRegisterValue("RCX").getAddress(1).add(8);
					packets[opcode] = info;
				}

				for (int i = 0; i < NUM_PACKETS; i++) {
					if (packets[i] == null)
						throw new IllegalStateException("i thought i had em all :( at " + i);
				}

				HashSet<Address> a = new HashSet<>();
				for (ServerProtInfo packet : packets) {
					if (a.contains(packet.addr))
						throw new IllegalStateException("REWRWE");
					a.add(packet.addr);
				}

				throw new Exception("yayeeeet");
			}
		}

		// okay welp time to scan insns
		for (Instruction insn : getFunctionInstructions(fn)) {
			tracker.update(insn);

			checkAndNameServerProt(insn);

			if (!insn.getMnemonicString().equals("CALL"))
				continue;

			Address addr = insn.getAddress(0);

			boolean isRegister = (addr != null && serverProtReg1 != null && addr.equals(serverProtReg1.getEntryPoint()));
			if (addr != null && (!visited.contains(addr) || isRegister)) {
				if (!isRegister)
					visited.add(addr);
				refactorPacketsRecursive(insn, getFunctionAt(addr), visited, tracker.waistClone(), isRegister ? rdx : tracker.getRegisterValue("RCX"), tracker.getRegisterValue("RDX"));
			}
		}
	}

	private void checkAndNameServerProt(Instruction insn) {
		if (serverProtReg1 != null && insn.getAddress(1) != null) {
			try {
				ServerProtInfo info = serverProtFromAddress(insn.getAddress(1));
				addresses.remove(insn.getAddress(1));
				if (!info.done) {
					info.done = true;
//                        println("before " + info);
					info.name = PACKET_NAMES[packetNamesOffset++];

					if (insn.getRegister(0).getBaseRegister().getName().equals("RDX")) {
						Instruction t = insn.getPrevious();
						while (t.getAddress(1) == null || t.getAddress(1).getAddressSpace().isStackSpace()) {
							t = t.getPrevious();
						}
						info.vtable = t.getAddress(1);
					} else if (insn.getRegister(0).getBaseRegister().getName().equals("RCX")) {
						Function f = getFunctionAt(insn.getNext().getAddress(0));
						Instruction t = getInstructionAt(f.getEntryPoint());
						while (t.getAddress(1) == null || t.getAddress(1).getAddressSpace().isStackSpace()) {
							t = t.getNext();
						}
						info.vtable = t.getAddress(1);
					} else {
						throw new IllegalStateException();
					}

//                    println(" hmm " + insn.toString() + " @ " + insn.getAddress());

					// i know yayeet should be used here but whatever it's 4:05am
//                        StringBuilder handlerName = new StringBuilder();
//                        for (String s : info.name.toLowerCase(Locale.ROOT).split("_")) {
//                            handlerName.append(s.substring(0, 1).toUpperCase(Locale.ROOT)).append(s.substring(1).toUpperCase(Locale.ROOT));
//                        }

//                        println("after " + info);
				}
			} catch (Exception e) {
			}
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// UTILITIES SECTION                                                                                              //
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * @param fn   The function to rename
	 * @param name The new name of the function
	 * @throws DuplicateNameException      [Document Ghidra exceptions here]
	 * @throws InvalidInputException       [Document Ghidra exceptions here]
	 * @throws CircularDependencyException [Document Ghidra exceptions here]
	 */
	private void renameFunction(Function fn, FullyQualifiedName name) throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		fn.setName(name.name, SourceType.USER_DEFINED);
		fn.setParentNamespace(getOrCreateNamespace(name.namespace));

		printf("Renamed function at %s to '%s'%n", fn.getEntryPoint().toString(), name.toString());
	}

	/**
	 * @param fn   The function to rename
	 * @param name The new name of the function
	 * @throws DuplicateNameException      [Document Ghidra exceptions here]
	 * @throws InvalidInputException       [Document Ghidra exceptions here]
	 * @throws CircularDependencyException [Document Ghidra exceptions here]
	 */
	private void renameFunction(Function fn, String name) throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		renameFunction(fn, new FullyQualifiedName(name));
	}

	/**
	 * Sets a label at a point in the code
	 *
	 * @param address The address to apply the label to
	 * @param name    The name of the label
	 * @throws DuplicateNameException [Document Ghidra exceptions here]
	 * @throws InvalidInputException  [Document Ghidra exceptions here]
	 */
	private void setLabel(Address address, FullyQualifiedName name) throws DuplicateNameException, InvalidInputException {
		printf("Set label at %s to '%s'%n", address.toString(), name.toString());

		SymbolTable table = currentProgram.getSymbolTable();

		for (Symbol symbol : table.getSymbols(address)) {
			if (symbol.getName().equals(name.name))
				return;
		}

		table.createLabel(address, name.name, getOrCreateNamespace(name.namespace), SourceType.USER_DEFINED);
	}

	/**
	 * Sets a label at a point in the code
	 *
	 * @param address The address to apply the label to
	 * @param name    The name of the label
	 * @throws DuplicateNameException [Document Ghidra exceptions here]
	 * @throws InvalidInputException  [Document Ghidra exceptions here]
	 */
	private void setLabel(Address address, String name) throws DuplicateNameException, InvalidInputException {
		setLabel(address, new FullyQualifiedName(name));
	}

	/**
	 * Gets a namespace from a string, or create it if it does not exist yet. This supports multi-level namespaces.
	 *
	 * @param name The name to convert into a namespace
	 * @return The namespace. If name is null, the global namespace will be returned.
	 * @throws DuplicateNameException [Document Ghidra exceptions here]
	 * @throws InvalidInputException  [Document Ghidra exceptions here]
	 */
	private Namespace getOrCreateNamespace(String name) throws DuplicateNameException, InvalidInputException {
		if (name == null) {
			return currentProgram.getGlobalNamespace();
		}

		SymbolTable table = currentProgram.getSymbolTable();

		String[] path = name.split("::");
		Namespace parent = currentProgram.getGlobalNamespace();
		for (String s : path) {
			Namespace child = table.getNamespace(s, parent);
			if (child == null) {
				child = table.createNameSpace(parent, s, SourceType.USER_DEFINED);
			}
			parent = child;
		}

		return parent;
	}

	/**
	 * Lists all instructions for the provided function.
	 *
	 * @param fn The function to list instructions for
	 * @return A list containing the instructions in the function. Modifying this list does not reflect on the function.
	 */
	private List<Instruction> getFunctionInstructions(Function fn) {
		List<Instruction> insns = new ArrayList<>();

		for (CodeUnit codeUnit : currentProgram.getListing().getCodeUnits(fn.getBody(), true)) {
			insns.add(getInstructionAt(codeUnit.getAddress()));
		}

		return insns;
	}

	/**
	 * Represents a full name space. There's probably support for this in Ghidra but oh well.
	 * <p>
	 * +---------------------------------------+
	 * | some::long::path::to::a::FunctionName |
	 * |   Namespace            || Name        |
	 * +------------------------++-------------+
	 */
	public static class FullyQualifiedName {
		public final String namespace;
		public final String name;

		public FullyQualifiedName(String namespace, String name) {
			this.namespace = namespace;
			this.name = name;
		}

		public FullyQualifiedName(String full) {
			String[] split = full.split("::");

			if (split.length == 0) {
				this.namespace = null;
				this.name = full;
			} else {
				StringJoiner jnr = new StringJoiner("::");
				for (int i = 0; i < split.length - 1; i++) {
					jnr.add(split[i]);
				}

				this.name = split[split.length - 1];
				this.namespace = jnr.toString();
			}
		}

		@Override
		public String toString() {
			return namespace + "::" + name;
		}
	}

	public static RS3NXTRefactorer instance;


	private static HashSet<String> E = new HashSet<>();

	/**
	 * Tracks the instructions that were used to manipulate a register. This can be useful for certain applications
	 */
	public static class RegisterTracker {
		private HashMap<String, List<Instruction>> registerValues = new HashMap<>();
		private Stack<List<Instruction>> stack = new Stack<>();

		/**
		 * Wipes all tracked registers
		 */
		public void clear() {
			registerValues.clear();
		}

		/**
		 * Updates the register using ANY instruction.
		 * <p>
		 * Function calls are not supported yet (RAX).
		 * <p>
		 * If an instruction does not modify a register, this will do nothing. No exception will be thrown.
		 *
		 * @param insn Any instruction
		 */
		public void update(Instruction insn) {
			if (insn == null || ((insn.getRegisters().length == 0 || insn.getRegister(0) == null) && !insn.getMnemonicString().equals("CALL")))
				return;

			String registerName = insn.getMnemonicString().equals("CALL") ? "RAX" : insn.getRegister(0).getBaseRegister().getName();
			List<Instruction> prior = registerValues.getOrDefault(registerName, new ArrayList<>());

			HashSet<String> blegh = new HashSet<String>() {{
				add("SUB");
				add("ADD");
				add("XOR");
				add("TEST");
				add("CMP");
				add("SETNZ");
				add("AND");
				add("ROR");
				add("MOV");
				add("MOVSXD");
				add("SAR");
				add("CMOVZ");
				add("CMOVA");
				add("DIV");
				add("OR");
				add("SBB");
				add("MOVZX");
				add("NEG");
				add("INC");
				add("IMUL");
				add("DEC");
				add("CMOVBE");
				add("PUNPCKLBW");
				add("JMP");
				add("ROL");
				add("SHR");
				add("MOVQ");
			}};
			if (insn.getMnemonicString().equals("PUSH")) {
				prior = registerValues.remove(registerName);
				if (prior == null) prior = new ArrayList<>();
				stack.push(prior);
			} else if (insn.getMnemonicString().equals("POP")) {
				registerValues.put(registerName, stack.pop());
			} else if (insn.getMnemonicString().equals("LEA")) {
				List<Instruction> list = new ArrayList<>();
				list.add(insn);
				registerValues.put(registerName, list);
			} else if (blegh.contains(insn.getMnemonicString())) {
				List<Instruction> src;
				if (insn.getRegister(1) != null)
					src = registerValues.getOrDefault(insn.getRegister(1).getBaseRegister().getName(), new ArrayList<>());
				else {
					src = new ArrayList<>();
					src.add(insn);
				}
				registerValues.put(registerName, src);
			} else if (insn.getMnemonicString().equals("CALL")) {
				List<Instruction> list = new ArrayList<>();
				list.add(insn);
				registerValues.put("RAX", list);
			} else if (insn.getMnemonicString().equals("JMP")) {
				// ignored
			} else {
				E.add(insn.getMnemonicString());


				List<Instruction> src;
				if (insn.getRegister(1) != null)
					src = registerValues.getOrDefault(insn.getRegister(1).getBaseRegister().getName(), new ArrayList<>());
				else {
					src = new ArrayList<>();
					src.add(insn);
				}
				registerValues.put(registerName, src);
//                throw new IllegalStateException("? " + registerName + " @ " + insn.getAddress() + ": " + insn);
			}

//            registerValues.put(registerName, prior);
		}

		/**
		 * @param register The register to check
		 * @return The last instruction that modified the register. May be null.
		 */
		public Instruction getRegisterValue(String register) {
			List<Instruction> insn = registerValues.get(register);
			if (insn == null || insn.isEmpty()) return null;
			return registerValues.get(register).get(0);
		}

		public List<Instruction> getRegisterValues(String register) {
			return registerValues.getOrDefault(register, new ArrayList<>());
		}

		/**
		 * @return A semi-deep clone of this tracker, instructions are not deep-cloned.
		 */
		public RegisterTracker waistClone() { // haha shallow is feet, deep is head-under, waist is in-between l0l
			RegisterTracker clone = new RegisterTracker();
			clone.stack.addAll(stack);
			registerValues.forEach((k, v) -> {
				List<Instruction> list = new ArrayList<>(v);
				clone.registerValues.put(k, list);
			});
			return clone;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// DATA TYPES                                                                                                     //
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Initializes default/builtin data types that we use
	 */
	private void initDefaultDataTypes() {
		Types.LONGLONG = getDataType("/longlong");
		Types.BOOL = getDataType("/bool");
		Types.VOID = getDataType("/void");
		Types.UINT = getDataType("/uint");
		Types.INT = getDataType("/int");
		Types.BYTE = getDataType("/byte");
	}

	/**
	 * Gets the data type according to Ghidra's path, throwing a NPE if it could not be found.
	 *
	 * @param path The path of the data type. By default this would be "/path/to/data/type/name"
	 * @return The data type
	 * @throws NullPointerException If said data type could not be found
	 */
	private DataType getDataType(String path) throws NullPointerException {
		DataType type = currentProgram.getDataTypeManager().getDataType(path);

		if (type == null) {
			throw new NullPointerException("DataType: " + path);
		}

		return type;
	}

	/**
	 * @return A pointer to the data type
	 */
	private DataType ptr(DataType type) {
		return currentProgram.getDataTypeManager().getPointer(type);
	}

	/**
	 * Creates a new array data type
	 *
	 * @param type          The type of the elements in this array
	 * @param arraySize     The amount of elements in this array
	 * @param elementLength The size of each element. For pointers, this would be 8, for ints, this would be 4, byte 1..
	 * @return The newly created array data type.
	 */
	private DataType arr(DataType type, int arraySize, int elementLength) {
		return new ArrayDataType(type, arraySize, elementLength, currentProgram.getDataTypeManager());
	}

	/**
	 * Gets the class, or creates the class
	 *
	 * @param name The name of the class
	 * @return The class
	 * @throws DuplicateNameException [Document Ghidra exceptions here]
	 * @throws InvalidInputException  [Document Ghidra exceptions here]
	 * @throws IllegalStateException  If the existing namespace is not a class
	 */
	private GhidraClass getOrCreateClass(String name) throws DuplicateNameException, InvalidInputException {
		return getOrCreateClass(new FullyQualifiedName(name));
	}

	/**
	 * Gets the class, or creates the class
	 *
	 * @param name The name of the class
	 * @return The class
	 * @throws DuplicateNameException [Document Ghidra exceptions here]
	 * @throws InvalidInputException  [Document Ghidra exceptions here]
	 * @throws IllegalStateException  If the existing namespace is not a class
	 */
	private GhidraClass getOrCreateClass(FullyQualifiedName name) throws DuplicateNameException, InvalidInputException {
		SymbolTable table = currentProgram.getSymbolTable();

		Namespace parent = getOrCreateNamespace(name.namespace);

		Namespace existing = table.getNamespace(name.name, parent);
		if (existing == null) {
			return table.createClass(parent, name.name, SourceType.USER_DEFINED);
		}

		if (!(existing instanceof GhidraClass)) {
			throw new IllegalStateException("expected class, got namespace for " + name);
		}

		return (GhidraClass) existing;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// STRUCTURES                                                                                                     //
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Resizes a structure. This will throw an exception if the structure is bigger than the size.
	 *
	 * @param struct The struct to resize
	 * @param size   The desired size of the struct
	 * @throws NullPointerException  If struct is null
	 * @throws IllegalStateException If the struct size is bigger than what it should be
	 */
	private void resizeStructure(Structure struct, int size) throws NullPointerException {
		String fullPath = (struct.getCategoryPath().toString() + "::" + struct.getName()).replaceAll("/", "::").substring(2);

		if (struct.getLength() < size) {
			int growBy = size - struct.getLength();

			printf("Growing struct '%s' size from %d to %d (+%d bytes)%n", fullPath, struct.getLength(), size, growBy);

			struct.growStructure(growBy);

			if (struct.getLength() < size) {
				struct.growStructure(size - struct.getLength());
			}
		} else if (struct.getLength() > size) {
			throw new IllegalStateException("Structure '" + fullPath + "' data structure too big: " + struct.getLength() + ", expected: " + size);
		} else {
			printf("Structure '%s' size already optimal! (=%d bytes)%n", fullPath, struct.getLength());
		}
	}

	/**
	 * Gets the structure of a class. If the structure does not exist, it will create a new, empty, structure.
	 *
	 * @param clazz The class to get the structure for
	 * @return The structure of the class
	 * @throws IllegalStateException If the existing data type is not an instance of {@link Structure} or the data type
	 *                               was not found and could not be created
	 */
	private Structure getStructureForClass(GhidraClass clazz) {
		CategoryPath path = new CategoryPath(CategoryPath.ROOT, clazz.getName(true).split("::"));

		DataType type = currentProgram.getDataTypeManager().getDataType(path.getParent(), path.getName());

		if (type == null) {
			printf("Created new data type/structure: %s%n", path.toString());
			currentProgram.getDataTypeManager().addDataType(new StructureDataType(path.getParent(), path.getName(), 0, currentProgram.getDataTypeManager()), DataTypeConflictHandler.DEFAULT_HANDLER);

			type = currentProgram.getDataTypeManager().getDataType(path.getParent(), path.getName());
			if (type == null) {
				throw new IllegalStateException("no DataType found for class " + clazz.getName(true));
			}
		}

		if (!(type instanceof Structure)) {
			throw new IllegalStateException("class DataType is not instance of Structure " + clazz.getName(true) + ", but of " + type.getClass().getSimpleName());
		}

		return (Structure) type;
	}

	private int packetNamesOffset = 0;
	private static final String[] PACKET_NAMES = new String[]{
			/* Animations */
			"LOC_ANIM_SPECIFIC",
			"PROJANIM_SPECIFIC",
			"SPOTANIM_SPECIFIC",
			"NPC_ANIM_SPECIFIC",
			"RESET_ANIMS",
			"SERVER_TICK_END",

			/* Audio */
			"SYNTH_SOUND",
			"VORBIS_SOUND",
			"VORBIS_SPEECH_SOUND",
			"VORBIS_SPEECH_STOP",
			"VORBIS_PRELOAD_SOUNDS",
			"VORBIS_SOUND_GROUP",
			"VORBIS_SOUND_GROUP_START",
			"VORBIS_SOUND_GROUP_STOP",
			"VORBIS_PRELOAD_SOUND_GROUP",
			"SOUND_MIXBUSS_ADD",
			"SOUND_MIXBUSS_SETLEVEL",
			"MIDI_SONG",
			"MIDI_SONG_STOP",
			"MIDI_SONG_LOCATION",
			"MIDI_JINGLE",
			"SONG_PRELOAD",

			/* Camera */
			"CAMERA_UPDATE",
			"CAM2_ENABLE",
			"CAM_RESET",
			"CAM_FORCEANGLE",
			"CAM_MOVETO",
			"CAM_LOOKAT",
			"CAM_SMOOTHRESET",
			"CAM_SHAKE",
			"CAM_REMOVEROOF",
			"CUTSCENE",

			/* Chat */
			"MESSAGE_PUBLIC",
			"MESSAGE_GAME",
			"CHAT_FILTER_SETTINGS",
			"MESSAGE_PRIVATE",
			"MESSAGE_PRIVATE_ECHO",
			"MESSAGE_FRIENDCHANNEL",
			"MESSAGE_CLANCHANNEL",
			"MESSAGE_CLANCHANNEL_SYSTEM",
			"MESSAGE_QUICKCHAT_PRIVATE_ECHO",
			"MESSAGE_QUICKCHAT_PRIVATE",
			"MESSAGE_QUICKCHAT_FRIENDCHAT",
			"MESSAGE_QUICKCHAT_CLANCHANNEL",
			"MESSAGE_PLAYER_GROUP",
			"MESSAGE_QUICKCHAT_PLAYER_GROUP",

			/* Clans */
			"CLANSETTINGS_FULL",
			"CLANSETTINGS_DELTA",
			"CLANCHANNEL_FULL",
			"CLANCHANNEL_DELTA",

			/* ClientState */
			"LOGOUT",
			"LOGOUT_FULL",
			"LOGOUT_TRANSFER",
			"REBUILD_REGION",
			"REBUILD_NORMAL",
			"SET_MOVEACTION",
			"SET_MAP_FLAG",
			"RUNCLIENTSCRIPT",
			"UPDATE_REBOOT_TIMER",
			"JCOINS_UPDATE",
			"LOYALTY_UPDATE",

			/* Debug */
			"DEBUG_SERVER_TRIGGERS",
			"CONSOLE_FEEDBACK",

			/* Environment */
			"ENVIRONMENT_OVERRIDE",
			"POINTLIGHT_COLOUR",
			"_UNKNOWN1_",

			/* Friend Chat */
			"UPDATE_FRIENDCHAT_CHANNEL_FULL",
			"UPDATE_FRIENDCHAT_CHANNEL_SINGLEUSER",

			/* Friends */
			"UPDATE_FRIENDLIST",
			"FRIENDLIST_LOADED",
			"CHAT_FILTER_SETTINGS_PRIVATECHAT",

			/* Hint */
			"HINT_ARROW",
			"HINT_TRAIL",

			/* Ignores */
			"UPDATE_IGNORELIST",

			/* Interfaces */
			"IF_SETPOSITION",
			"IF_SETSCROLLPOS",
			"IF_OPENTOP",
			"IF_OPENSUB",
			"IF_OPENSUB_ACTIVE_PLAYER",
			"IF_OPENSUB_ACTIVE_NPC",
			"IF_OPENSUB_ACTIVE_LOC",
			"IF_OPENSUB_ACTIVE_OBJ",
			"IF_CLOSESUB",
			"IF_MOVESUB",
			"IF_SETEVENTS",
			"IF_SETTARGETPARAM",
			"IF_SETTEXT",
			"IF_SETHIDE",
			"IF_SETGRAPHIC",
			"IF_SET_HTTP_IMAGE",
			"IF_SETPLAYERMODEL_OTHER",
			"IF_SETPLAYERMODEL_SELF",
			"IF_SETPLAYERMODEL_SNAPSHOT",
			"IF_SETMODEL",
			"IF_SETANIM",
			"IF_SETNPCHEAD",
			"IF_SETPLAYERHEAD",
			"IF_SETPLAYERHEAD_OTHER",
			"IF_SETPLAYERHEAD_IGNOREWORN",
			"IF_SETOBJECT",
			"IF_SETTEXTFONT",
			"IF_SETCOLOUR",
			"IF_SETRECOL",
			"IF_SETRETEX",
			"IF_SETCLICKMASK",
			"IF_SETTEXTANTIMACRO",
			"TRIGGER_ONDIALOGABORT",
			"IF_SETANGLE",

			/* Inventories */
			"UPDATE_INV_PARTIAL",
			"UPDATE_INV_FULL",
			"UPDATE_INV_STOP_TRANSMIT",
			"UPDATE_STOCKMARKET_SLOT",

			/* Lobby */
			"NO_TIMEOUT",
			"CREATE_CHECK_EMAIL_REPLY",
			"CREATE_ACCOUNT_REPLY",
			"CREATE_CHECK_NAME_REPLY",
			"CREATE_SUGGEST_NAME_ERROR",
			"CREATE_SUGGEST_NAME_REPLY",
			"LOBBY_APPEARANCE",
			"CHANGE_LOBBY",

			/* Misc */
			"SEND_PING",
			"MINIMAP_TOGGLE",
			"SHOW_FACE_HERE",
			"EXECUTE_CLIENT_CHEAT",
			"DO_CHEAT",
			"SETDRAWORDER",
			"JS5_RELOAD",
			"WORLDLIST_FETCH_REPLY",

			/* NPC Info */
			"NPC_INFO",
			"NPC_HEADICON_SPECIFIC",

			/* Player Groups */
			"PLAYER_GROUP_FULL",
			"PLAYER_GROUP_DELTA",
			"PLAYER_GROUP_VARPS",

			/* Player Info */
			"LAST_LOGIN_INFO",
			"PLAYER_INFO",
			"SET_PLAYER_OP",
			"UPDATE_RUNENERGY",
			"UPDATE_RUNWEIGHT",
			"UPDATE_UID192",
			"SET_TARGET",
			"REDUCE_PLAYER_ATTACK_PRIORITY",
			"REDUCE_NPC_ATTACK_PRIORITY",
			"PLAYER_SNAPSHOT",
			"CLEAR_PLAYER_SNAPSHOT",
			"UPDATE_DOB",

			/* Server Reply */
			"SERVER_REPLY",

			/* Telemetry */
			"TELEMETRY_GRID_FULL",
			"TELEMETRY_GRID_VALUES_DELTA",
			"TELEMETRY_GRID_ADD_GROUP",
			"TELEMETRY_GRID_REMOVE_GROUP",
			"TELEMETRY_GRID_ADD_ROW",
			"TELEMETRY_GRID_REMOVE_ROW",
			"TELEMETRY_GRID_SET_ROW_PINNED",
			"TELEMETRY_GRID_MOVE_ROW",
			"TELEMETRY_GRID_ADD_COLUMN",
			"TELEMETRY_GRID_REMOVE_COLUMN",
			"TELEMETRY_GRID_MOVE_COLUMN",
			"TELEMETRY_CLEAR_GRID_VALUE",

			/* Variables */
			"RESET_CLIENT_VARCACHE",
			"VARP_SMALL",
			"VARP_LARGE",
			"VARBIT_SMALL",
			"VARBIT_LARGE",
			"CLIENT_SETVARC_SMALL",
			"CLIENT_SETVARC_LARGE",
			"CLIENT_SETVARCBIT_SMALL",
			"CLIENT_SETVARCBIT_LARGE",
			"CLIENT_SETVARCSTR_SMALL",
			"CLIENT_SETVARCSTR_LARGE",
			"STORE_SERVERPERM_VARCS_ACK",
			"VARCLAN_DISABLE",
			"VARCLAN_ENABLE",
			"VARCLAN",
			"UPDATE_STAT",

			/* Web Page */
			"UPDATE_SITESETTINGS",
			"URL_OPEN",
			"SOCIAL_NETWORK_LOGOUT",

			/* Zone Updates */
			"UPDATE_ZONE_PARTIAL_FOLLOWS",
			"UPDATE_ZONE_FULL_FOLLOWS",
			"UPDATE_ZONE_PARTIAL_ENCLOSED",
			"LOC_ADD_CHANGE",
			"LOC_CUSTOMISE",
			"LOC_DEL",
			"LOC_ANIM",
			"MAP_PROJANIM",
			"MAP_PROJANIM_HALFSQ",
			"MAP_ANIM",
			"OBJ_ADD",
			"OBJ_DEL",
			"OBJ_REVEAL",
			"OBJ_COUNT",
			"SOUND_AREA",
			"____WAT____",
			"LOC_PREFETCH",
			"TEXT_COORD"
	};

	public static final int NUM_PACKETS = 195;

	private ServerProtInfo[] packets = new ServerProtInfo[NUM_PACKETS];

	static class ServerProtInfo {
		boolean done = false;
		public int opcode;
		public int size;
		public String name;
		public Address addr;
		public Address vtable;

		@Override
		public String toString() {
			return "ServerProt[opcode=" + opcode + ", size=" + size + ", name=" + name + ", addr= " + addr + " ]";
		}
	}
}
