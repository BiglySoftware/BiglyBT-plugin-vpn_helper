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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;
import org.apache.http.message.BasicNameValuePair;
import com.biglybt.core.util.Constants;
import com.biglybt.core.util.FileUtil;
import com.biglybt.core.util.RandomUtils;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.config.Parameter;
import com.biglybt.pif.ui.config.PasswordParameter;
import com.biglybt.pif.ui.config.StringParameter;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;

import com.biglybt.core.proxy.AEProxySelector;
import com.biglybt.core.proxy.AEProxySelectorFactory;
import com.biglybt.util.JSONUtils;

/**
 * Private Internet Access VPN
 * https://www.privateinternetaccess.com
 * 
 * RPC Specs from their forum.
 * 
 * Only one Port, so port cycling is not an option.
 */
public class Checker_PIA
	extends CheckerCommon
{
	public static final String CONFIG_PIA_MANAGER_DIR = "pia_manager.dir";

	// Is it always 70000? who knows
	private static final int STATUS_FILE_PORT_INDEX = 70000;

	private static final String VPN_DOMAIN = "www.privateinternetaccess.com";

	private static final String PIA_RPC_URL = "https://" + VPN_DOMAIN
			+ "/vpninfo/port_forward_assignment";

	public Checker_PIA(PluginInterface pi) {
		super(pi);
		setMinSubnetMaskBitCount(30);
	}

	public static List<Parameter> setupConfigModel(PluginInterface pi,
			BasicPluginConfigModel configModel) {
		List<Parameter> params = new ArrayList<Parameter>(1);
		if (pi.getUtilities().isWindows() || pi.getUtilities().isOSX()) {
			params.add(configModel.addDirectoryParameter2(CONFIG_PIA_MANAGER_DIR,
					CONFIG_PIA_MANAGER_DIR, getPIAManagerPath().toString()));
		}

		params.add(configModel.addLabelParameter2("pia.login.group.explain"));
		StringParameter paramUser = configModel.addStringParameter2(
				PluginConstants.CONFIG_USER, "vpnhelper.config.user",
				getDefaultUsername(pi));
		params.add(paramUser);
		PasswordParameter paramPass = configModel.addPasswordParameter2(
				PluginConstants.CONFIG_P, "vpnhelper.config.pass",
				PasswordParameter.ET_PLAIN, new byte[] {});
		params.add(paramPass);

		return params;
	}

	protected static String getDefaultUsername(PluginInterface pi) {
		try {
			String pathPIAManager = pi.getPluginconfig().getPluginStringParameter(
					CONFIG_PIA_MANAGER_DIR);

			File pathPIAManagerData = new File(pathPIAManager, "data");

			// settings.json has the user name
			File fileSettings = new File(pathPIAManagerData, "settings.json");
			if (!fileSettings.isFile() || !fileSettings.canRead()) {
				return "";
			}
			String settingsText = FileUtil.readFileAsString(fileSettings, -1);
			Map<?, ?> mapSettings = JSONUtils.decodeJSON(settingsText);
			String user = (String) mapSettings.get("user");

			return user == null ? "" : user;
		} catch (Exception e) {
			return "";
		}
	}

	private boolean checkStatusFileForPort(File pathPIAManagerData,
			StringBuilder sReply) {
		// Read the status_file for forwarding port

		boolean gotValidPort = false;

		File fileStatus = new File(pathPIAManagerData, "status_file.txt");
		if (!fileStatus.isFile() || !fileStatus.canRead()) {
			return false;
		}
		try {
			byte[] statusFileBytes = FileUtil.readFileAsByteArray(fileStatus);

			if (statusFileBytes.length > STATUS_FILE_PORT_INDEX
					&& statusFileBytes[STATUS_FILE_PORT_INDEX] == '{') {
				int endPos = STATUS_FILE_PORT_INDEX;
				while (endPos < statusFileBytes.length && statusFileBytes[endPos] > 1) {
					endPos++;
				}
				boolean gotPort = false;

				String jsonPort = new String(statusFileBytes, STATUS_FILE_PORT_INDEX,
						endPos - STATUS_FILE_PORT_INDEX);
				Map<?, ?> decodeJSON = JSONUtils.decodeJSON(jsonPort);
				if (decodeJSON.containsKey("single")) {
					Object oPort = decodeJSON.get("single");
					if (oPort == null) {
						gotPort = true;

						String user = config.getPluginStringParameter(
								PluginConstants.CONFIG_USER);
						byte[] pass = config.getPluginByteParameter(
								PluginConstants.CONFIG_P);

						if (user == null || user.length() == 0 || pass == null
								|| pass.length == 0) {

							boolean portForwardEnabled = false;
							File fileSettings = new File(pathPIAManagerData, "settings.json");
							String settingsString = FileUtil.readFileAsString(fileSettings,
									-1);
							Map<?, ?> mapSettings = JSONUtils.decodeJSON(settingsString);
							if (mapSettings != null
									&& mapSettings.containsKey("portforward")) {
								portForwardEnabled = (Boolean) mapSettings.get("portforward");
							}

							addReply(sReply, CHAR_WARN, portForwardEnabled
									? "pia.no.forwarding.port" : "pia.no.port.config");
						}

					}
					if (oPort instanceof Number) {
						gotPort = true;
						gotValidPort = true;

						Number nPort = (Number) oPort;
						int port = nPort.intValue();

						addReply(sReply, CHAR_GOOD, "pia.port.in.manager", new String[] {
							Integer.toString(port)
						});

						changePort(port, sReply);
					}
				}

				if (!gotPort) {
					addReply(sReply, CHAR_BAD, "pia.invalid.port.status_file",
							new String[] {
								jsonPort
					});
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return gotValidPort;
	}

	private boolean callRPCforPort(File pathPIAManagerData, InetAddress bindIP,
			StringBuilder sReply) {
		InetAddress[] resolve = null;
		try {
			// Let's assume the client_id.txt file is the one for port forwarding.
			File fileClientID = new File(pathPIAManagerData, "client_id.txt");
			String clientID;
			if (fileClientID.isFile() && fileClientID.canRead()) {
				clientID = FileUtil.readFileAsString(fileClientID, -1);
			} else {
				clientID = config.getPluginStringParameter("client.id", null);
				if (clientID == null) {
					clientID = RandomUtils.generateRandomAlphanumerics(20);
					config.setPluginParameter("client.id", clientID);
				}
			}

			HttpPost post = new HttpPost(PIA_RPC_URL);

			String user = config.getPluginStringParameter(
					PluginConstants.CONFIG_USER);
			String pass = new String(
					config.getPluginByteParameter(PluginConstants.CONFIG_P, new byte[0]),
					"utf-8");

			if (user == null || user.length() == 0 || pass == null
					|| pass.length() == 0) {
				return false;
			}

			List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
			urlParameters.add(new BasicNameValuePair("user", user));
			urlParameters.add(new BasicNameValuePair("pass", pass));
			urlParameters.add(new BasicNameValuePair("client_id", clientID));
			urlParameters.add(
					new BasicNameValuePair("local_ip", bindIP.getHostAddress()));

			// Call needs to be from the VPN interface (the bindIP)
			RequestConfig requestConfig = RequestConfig.custom().setLocalAddress(
					bindIP).setConnectTimeout(15000).build();

			post.setConfig(requestConfig);

			post.setEntity(new UrlEncodedFormEntity(urlParameters));

			CloseableHttpClient httpClient = HttpClients.createDefault();

			// If Vuze has a proxy set up (Tools->Options->Connection->Proxy), then
			// we'll need to disable it for the URL
			AEProxySelector selector = AEProxySelectorFactory.getSelector();
			if (selector != null) {
				resolve = SystemDefaultDnsResolver.INSTANCE.resolve(VPN_DOMAIN);

				for (InetAddress address : resolve) {
					selector.setProxy(new InetSocketAddress(address, 443),
							Proxy.NO_PROXY);
				}
			}

			CloseableHttpResponse response = httpClient.execute(post);
			BufferedReader rd = new BufferedReader(
					new InputStreamReader(response.getEntity().getContent()));

			StringBuffer result = new StringBuffer();
			String line = "";
			while ((line = rd.readLine()) != null) {
				result.append(line);
			}

			boolean gotPort = false;
			// should be {"port":xyz}

			Map<?, ?> mapResult = JSONUtils.decodeJSON(result.toString());
			if (mapResult.containsKey("port")) {
				Object oPort = mapResult.get("port");
				if (oPort instanceof Number) {
					gotPort = true;
					Number nPort = (Number) oPort;
					int port = nPort.intValue();

					addReply(sReply, CHAR_GOOD, "pia.port.from.rpc", new String[] {
						Integer.toString(port)
					});

					changePort(port, sReply);
				}
			}

			if (!gotPort) {
				addReply(sReply, CHAR_WARN, "vpnhelper.rpc.bad", new String[] {
					result.toString()
				});

				// mapResult.containsKey("error")
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

	private static File getPIAManagerPath() {
		File pathPIAManager = null;
		if (Constants.isWindows) {
			String pathProgFiles = System.getenv("ProgramFiles");
			if (pathProgFiles != null) {
				pathPIAManager = new File(pathProgFiles, "pia_manager");
			}
			if (pathPIAManager == null || !pathPIAManager.exists()) {
				String pathProgFiles86 = System.getenv("ProgramFiles");
				if (pathProgFiles == null && pathProgFiles86 != null) {
					pathProgFiles86 = pathProgFiles + "(x86)";
				}
				if (pathProgFiles86 != null) {
					pathPIAManager = new File(pathProgFiles86, "pia_manager");
				}
			}
			if (pathPIAManager == null || !pathPIAManager.exists()) {
				pathPIAManager = new File("C:\\Program Files\\pia_manager");
			}
		} else {
			pathPIAManager = new File(System.getProperty("user.home"),
					".pia_manager");
		}

		return pathPIAManager;
	}

	@Override
	protected boolean callRPCforPort(InetAddress vpnIP, StringBuilder sReply) {

		String pathPIAManager = config.getPluginStringParameter(
				CONFIG_PIA_MANAGER_DIR);

		File pathPIAManagerData = new File(pathPIAManager, "data");

		boolean ok = callRPCforPort(pathPIAManagerData, vpnIP, sReply);

		if (!ok) {
			ok = checkStatusFileForPort(pathPIAManagerData, sReply);
		}

		return ok;
	}

	/* (non-Javadoc)
	 * @see com.vuze.plugin.azVPN_Helper.CheckerCommon#canReach(java.net.InetAddress)
	 */
	@Override
	protected boolean canReach(InetAddress addressToReach) {
		try {
			URI canReachURL = new URI("https://" + VPN_DOMAIN);
			return canReach(addressToReach, canReachURL);
		} catch (URISyntaxException e) {
			return false;
		}
	}
}
