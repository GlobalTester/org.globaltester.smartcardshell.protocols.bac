package org.globaltester.smartcardshell.protocols.bac;

import java.util.List;

import org.globaltester.smartcardshell.protocols.AbstractScshProtocolProvider;
import org.globaltester.smartcardshell.protocols.ScshCommand;
import org.globaltester.smartcardshell.protocols.ScshCommandParameter;

public class ProtocolProvider extends AbstractScshProtocolProvider {

	private static ScshCommand performBAC;
	{
		performBAC = new ScshCommand("performBAC");
		performBAC
				.setHelp("Perform BAC with the card to initialize SecureMessaging");
		performBAC.setHelpReturn(null);

		ScshCommandParameter mrzParam = new ScshCommandParameter("mrz");
		mrzParam.setHelp("Complete MRZ of the chip, as String without line breaks or other formatting information");
		performBAC.addParam(mrzParam);

		String impl = "";
		impl += "print(\"perform BAC\")\n";
		performBAC.setImplementation(impl);
	}

	@Override
	public void addCommands(List<ScshCommand> commandList) {
		commandList.add(performBAC);
	}

}
