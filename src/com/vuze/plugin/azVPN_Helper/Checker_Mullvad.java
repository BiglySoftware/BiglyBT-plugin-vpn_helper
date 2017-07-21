/*
 * Copyright (C) Azureus Software, Inc, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details ( see the LICENSE file ).
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.vuze.plugin.azVPN_Helper;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.biglybt.core.util.Constants;
import com.biglybt.core.util.FileUtil;
import com.biglybt.core.util.SystemProperties;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.config.Parameter;
import com.biglybt.pif.ui.config.StringParameter;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;

import com.biglybt.core.proxy.AEProxySelector;
import com.biglybt.core.proxy.AEProxySelectorFactory;

/**
 * Mullvad VPN
 * https://mullvad.net
 * 
 * RPC specs from Mulvad's open source client: class MullvadClient in mtunnel.py
 * 
 * TODO: Port cycling
 * TODO: check the "connections" RPC, and if 0, report we aren't connected (instead of BAD) 
 */
public class Checker_Mullvad
	extends CheckerCommon
{
	private static final int RPC_PORT = 51678;

	private static final String RPC_DOMAIN = "master.mullvad.net";

	private static final String CONFIG_MULLVAD_ACCOUNT = "mullvad.account.id";

	public Checker_Mullvad(PluginInterface pi) {
		super(pi);
	}

	public static List<Parameter> setupConfigModel(PluginInterface pi,
			BasicPluginConfigModel configModel) {
		List<Parameter> params = new ArrayList<Parameter>(1);
		StringParameter paramAccount = configModel.addStringParameter2(
				CONFIG_MULLVAD_ACCOUNT, CONFIG_MULLVAD_ACCOUNT, getAccountID());
		params.add(paramAccount);

		return params;
	}

	private static String getAccountID() {
		File vpnConfigPath = getVPNConfigPath();
		if (vpnConfigPath == null) {
			return "";
		}
		File fSettings = new File(vpnConfigPath, "settings.ini");

		try {
			String settings = FileUtil.readFileAsString(fSettings, 65535);

			Pattern pattern = Pattern.compile("^\\s*id\\s*=\\s*([0-9]+)\\s*$",
					Pattern.MULTILINE);
			Matcher matcher = pattern.matcher(settings);
			if (matcher.find()) {
				String id = matcher.group(1);
				return id;
			}
		} catch (IOException e) {
		}

		return "";
	}

	@Override
	protected boolean callRPCforPort(InetAddress bindIP, StringBuilder sReply) {
		String id = config.getPluginStringParameter(CONFIG_MULLVAD_ACCOUNT);
		if (id == null || id.length() == 0) {
			// It's possible the user started Vuze before getting an account id,
			// so the default value may not be up to date
			id = getAccountID();
			if (id == null || id.length() == 0) {
				addReply(sReply, CHAR_WARN, "mullvad.account.id.required");
  			return false;
			}
		}

		InetAddress[] resolve = null;
		try {
			boolean gotPort = false;

			Socket soc = new Socket(RPC_DOMAIN, RPC_PORT);
			BufferedReader br = new BufferedReader(
					new InputStreamReader(soc.getInputStream()));
			BufferedWriter bw = new BufferedWriter(
					new OutputStreamWriter(soc.getOutputStream()));

			sendCommand(br, bw, "version%51%");
			String[] answer = sendCommand(br, bw, "forward port%" + id + "%");

			soc.close();

			if (answer != null) {
				if (answer.length > 1) {
					int port = Integer.parseInt(answer[1]);
					gotPort = true;

					addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc", new String[] {
						Integer.toString(port)
					});

					changePort(port, sReply);
				} else if (answer.length == 1) {
					int addPort = addPort(id);
					if (addPort > 0) {
						gotPort = true;

						addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc",
								new String[] {
									Integer.toString(addPort)
						});

						changePort(addPort, sReply);
					}
				}
			}

			if (!gotPort) {
				addReply(sReply, CHAR_WARN, "vpnhelper.rpc.bad", new String[] {
					answer.toString()
				});

				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.rpc.no.connect", new String[] {
				bindIP + ": " + e.getMessage()
			});

			return false;
		} finally {
			AEProxySelector selector = AEProxySelectorFactory.getSelector();
			if (selector != null && resolve != null) {
				for (InetAddress address : resolve) {
					AEProxySelectorFactory.getSelector().removeProxy(
							new InetSocketAddress(address, 443));
				}
			}
		}
		return true;
	}

	private int addPort(String id)
			throws UnknownHostException, IOException {
		Socket soc = new Socket(RPC_DOMAIN, RPC_PORT);
		BufferedReader br = new BufferedReader(
				new InputStreamReader(soc.getInputStream()));
		BufferedWriter bw = new BufferedWriter(
				new OutputStreamWriter(soc.getOutputStream()));

		sendCommand(br, bw, "version%51%");
		String[] answer = sendCommand(br, bw, "new port%" + id + "%");

		soc.close();

		PluginVPNHelper.log("Added a port. " + Arrays.toString(answer));

		if (answer != null && answer.length > 1) {
			return Integer.parseInt(answer[1]);
		}

		return -1;
	}

	public String[] sendCommand(BufferedReader br, BufferedWriter bw,
			String command)
					throws IOException {

		String data = String.format("%08X", command.length());

		bw.write(data);
		bw.write(command);
		bw.flush();

		StringBuilder answer = new StringBuilder();

		char[] c = new char[256];
		int read;
		do {

			read = br.read(c);

			if (read > 0) {
				answer.append(c, 0, read);

				if (answer.length() >= 8) {
					int dataLength = Integer.parseInt(answer.substring(0, 8), 16);
					if (answer.length() >= dataLength + 8) {
						break;
					}
				}
			}
		} while (read >= 0);

		if (answer.length() > 8) {
			if (answer.length() > 8) {
				String[] split = answer.substring(8).split("%");
				return split;
			}
		}

		return null;
	}

	/* (non-Javadoc)
	 * @see com.vuze.plugin.azVPN_Helper.CheckerCommon#canReach(java.net.InetAddress)
	 */
	@Override
	protected boolean canReach(InetAddress addressToReach) {
		try {
			URI canReachURL = new URI("https://mullvad.net");
			return canReach(addressToReach, canReachURL);
		} catch (URISyntaxException e) {
			return false;
		}
	}

	private static File getVPNConfigPath() {
		String appData;
		String userhome = System.getProperty("user.home");

		if (Constants.isWindows) {
			appData = SystemProperties.getEnvironmentalVariable("LOCALAPPDATA");

			if (appData != null && appData.length() > 0) {
			} else {
				appData = userhome + SystemProperties.SEP + "Application Data";
			}

		} else if (Constants.isOSX) {
			appData = userhome + SystemProperties.SEP + "Library"
					+ SystemProperties.SEP + "Application Support";

		} else {
			// unix type
			appData = userhome;
		}

		File f = new File(appData, Constants.isLinux ? ".mullvad" : "mullvad");
		if (f.isDirectory()) {
			File f2 = new File(f, "mullvad");
			return f2.isDirectory() ? f2 : f;
		}
		return null;
	}

	public static void main(String[] args) {
		System.out.println(getVPNConfigPath());
		System.out.println(getAccountID());
	}
}
