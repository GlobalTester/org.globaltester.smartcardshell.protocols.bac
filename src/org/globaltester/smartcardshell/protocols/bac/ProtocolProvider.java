package org.globaltester.smartcardshell.protocols.bac;

import java.util.List;

import org.globaltester.smartcardshell.protocols.AbstractScshProtocolProvider;
import org.globaltester.smartcardshell.protocols.ScshCommand;
import org.globaltester.smartcardshell.protocols.ScshCommandParameter;

public class ProtocolProvider extends AbstractScshProtocolProvider {

	private static ScshCommand selectApplicationEPASS;
	{
		selectApplicationEPASS = new ScshCommand("selectApplicationEPASS");
		selectApplicationEPASS.setHelp("Select the ePassport application");
		selectApplicationEPASS.setHelpReturn("");
		
		ScshCommandParameter ignoreStatusWord = new ScshCommandParameter("ignoreSW");
		ignoreStatusWord.setHelp("Bollean value to set if Mutual Authentication should proof the StatusWord");
		selectApplicationEPASS.addParam(ignoreStatusWord);

		String impl = "";
		impl += "if (ignoreSW == undefined) ignoreSW = false;\n";
		impl += "var cmd = new ByteString(\"00 A4 04 0C 07 A0 00 00 02 47 10 01\", HEX);\n";
		impl += "card.gt_sendCommand(cmd);\n";
		impl += "if (!(ignoreSW)) assertStatusWord(SW_NoError, card.SW.toString(HEX));\n";
		selectApplicationEPASS.setImplementation(impl);
	}
	
	
	private static ScshCommand performBAC;
	{
		performBAC = new ScshCommand("performBAC");
		performBAC
				.setHelp("Perform BAC with the card to initialize SecureMessaging");
		performBAC.setHelpReturn(null);

		ScshCommandParameter mrzParam = new ScshCommandParameter("mrz");
		mrzParam.setHelp("Complete MRZ of the chip, as String without line breaks or other formatting information");
		performBAC.addParam(mrzParam);
		
		ScshCommandParameter ignoreStatusWord = new ScshCommandParameter("ignoreSW");
		ignoreStatusWord.setHelp("Bollean value to set if Mutual Authentication should proof the StatusWord");
		performBAC.addParam(ignoreStatusWord);

		String impl = "";
		impl += "print(\"perform BAC wit MRZ \" + mrz)\n";
		impl += "var bac = this.gt_BAC_getBAC();\n";
		impl += "bac.setMRZ(new Packages.org.globaltester.smartcardshell.protocols.bac.MRZ(mrz));\n";
		impl += "bac.deriveMrzKeys();\n";
		impl += "\n";
		impl += "var rndICC = this.gt_ISO7816_getChallenge(8);\n";
		impl += "var rndIFD = bac.getRandomBytes(8);\n";
		impl += "var kIFD = bac.getRandomBytes(16);\n";
		impl += "\n";
		impl += "var mutualAuthData = bac.computeMutualAuthenticateData(rndIFD, rndICC, kIFD);\n";
		impl += "var mutualAuthResp = this.gt_ISO7816_mutualAuthenticate(mutualAuthData, null, ignoreSW);\n";
		impl += "\n";
		impl += "var kICC = bac.getKicc(mutualAuthResp);\n";
		impl += "\n";
		impl += "var keySeed = bac.computeKeySeed(kIFD, kICC);\n";
		impl += "bac.deriveSessionKeys(keySeed);\n";
		impl += "\n";
		impl += "var sKenc = bac.getSKenc();\n";
		impl += "var sKmac = bac.getSKmac();\n";
		impl += "var ssc = bac.calculateInitialSendSequenceCounter(rndICC, rndIFD);\n";
		impl += "\n";
		impl += "this.gt_SecureMessaging_initSM(sKenc, sKmac, ssc);\n";
		
		performBAC.setImplementation(impl);
	}
	
	private static ScshCommand getBAC;
	{
		getBAC = new ScshCommand("getBAC");
		getBAC.setHelp("Return the BAC object associated with this card. This can be used to manipulate the SM bevahior of sendCommand() and sendSM()\n\nThis method behaves like a singleton access method, e.g. if the SM instance does not exist it will be created but several sequential calls to this method will always return the same instance.");
		getBAC.setHelpReturn("BAC object used by this card (Instance of org.globaltester.smartcardshell.protocols.bac.BAC");

		String impl = "";
		impl += "if (this.gt_BAC_BAC == undefined) {\n";
		impl += "    print(\"gt_BAC_BAC is not defined yet, will be created now\");\n";
		impl += "    this.gt_BAC_BAC = new Packages.org.globaltester.smartcardshell.protocols.bac.BAC()";
		impl += "}\n";
		impl += "return this.gt_BAC_BAC;\n";
		getBAC.setImplementation(impl);
	}

	@Override
	public void addCommands(List<ScshCommand> commandList) {
		commandList.add(getBAC);
		commandList.add(performBAC);
		commandList.add(selectApplicationEPASS);
	}

}
