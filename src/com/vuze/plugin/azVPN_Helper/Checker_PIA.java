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
import java.util.Collections;
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

import com.biglybt.core.proxy.AEProxySelector;
import com.biglybt.core.proxy.AEProxySelectorFactory;
import com.biglybt.core.util.Constants;
import com.biglybt.core.util.FileUtil;
import com.biglybt.core.util.RandomUtils;
import com.biglybt.core.util.SystemTime;
import com.biglybt.util.JSONUtils;
import com.biglybt.util.MapUtils;

import com.biglybt.pif.PluginConfig;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.config.*;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;

/**
 * Private Internet Access VPN
 * https://www.privateinternetaccess.com
 *
 * RPC Specs from their forum.
 *
 * Only one Port, so port cycling is not an option.
 */
@SuppressWarnings("unused")
public class Checker_PIA
	extends CheckerCommon
{
	public static final String CONFIG_PIA_MANAGER_DIR = "pia_manager.dir";

	public static final String CONFIG_PIA_P = "pia_p.privx";

	public static final String CONFIG_PIA_USER = "pia_user";

	private static final String CONFIG_PIA_TRY_PORT_RPC = "pia_try.port.rpc";

	// Is it always 70000? who knows
	private static final int STATUS_FILE_PORT_INDEX = 70000;

	private static final String VPN_DOMAIN = "www.privateinternetaccess.com";

	private static final String PIA_RPC_URL = "https://" + VPN_DOMAIN
			+ "/vpninfo/port_forward_assignment";

	private static DirectoryParameter paramManagerDir;

	private static BooleanParameter paramTryPortRPC;

	public Checker_PIA(PluginInterface pi) {
		super(pi);
		setMinSubnetMaskBitCount(30);
	}

	public static List<Parameter> setupConfigModel(PluginInterface pi,
			BasicPluginConfigModel configModel) {

		// AirVPN and PIA used to share CONFIG_PIA_USER and CONFIG_PIA_P
		// Check if old keys are used, and migrate to separate keys
		PluginConfig pc = pi.getPluginconfig();
		if (!pc.hasPluginParameter(CONFIG_PIA_USER)
				&& pc.hasPluginParameter(PluginConstants.CONFIG_USER)) {
			String val = pc.getPluginStringParameter(PluginConstants.CONFIG_USER);
			if (val != null && !val.isEmpty()) {
				pc.setPluginParameter(CONFIG_PIA_USER, val);
			}
		}
		if (!pc.hasPluginParameter(CONFIG_PIA_P)
				&& pc.hasPluginParameter(PluginConstants.CONFIG_P)) {
			byte[] val = pc.getPluginByteParameter(PluginConstants.CONFIG_P);
			if (val != null && val.length > 0) {
				pc.setPluginParameter(CONFIG_PIA_P, val);
			}
		}

		List<Parameter> params = new ArrayList<>(1);
		if (pi.getUtilities().isWindows() || pi.getUtilities().isOSX()) {
			File path = getPIAManagerPath();
			paramManagerDir = configModel.addDirectoryParameter2(
					CONFIG_PIA_MANAGER_DIR, CONFIG_PIA_MANAGER_DIR,
					path == null ? "" : path.toString());
			params.add(paramManagerDir);
		}

		paramTryPortRPC = configModel.addBooleanParameter2(CONFIG_PIA_TRY_PORT_RPC,
				"pia.try.port.rpc", true);
		params.add(paramTryPortRPC);

		String[] creds = getDefaultCreds(pi);
		StringParameter paramUser = configModel.addStringParameter2(CONFIG_PIA_USER,
				"vpnhelper.config.user", creds[0]);
		params.add(paramUser);
		PasswordParameter paramPass = configModel.addPasswordParameter2(
				CONFIG_PIA_P, "vpnhelper.config.pass", PasswordParameter.ET_PLAIN,
				creds[1].getBytes());
		params.add(paramPass);

		paramTryPortRPC.addEnabledOnSelection(paramUser);
		paramTryPortRPC.addEnabledOnSelection(paramPass);

		return params;
	}

	protected static String[] getDefaultCreds(PluginInterface pi) {
		String[] ret = {
			"",
			""
		};
		if (paramManagerDir == null) {
			return ret;
		}
		try {
			String pathPIAManager = paramManagerDir.getValue();

			File pathPIAManagerData = new File(pathPIAManager, "data");

			// settings.json has the user name
			File fileSettings = new File(pathPIAManagerData, "settings.json");
			if (!fileSettings.isFile() || !fileSettings.canRead()) {
				return ret;
			}
			String settingsText = FileUtil.readFileAsString(fileSettings, -1);
			Map<?, ?> mapSettings = JSONUtils.decodeJSON(settingsText);
			if (mapSettings != null) {
				String user = (String) mapSettings.get("user");

				if (user != null) {
					ret[0] = user;
				}
				String pwraw = (String) mapSettings.get("pass");
				if (pwraw != null) {
					ret[1] = decode(pwraw);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	private static String transform(String s) {
		String PW_KEY = "GN\\\\Lqnw-xc]=jQ}fTyN[Y|x5Db-FET?&)T\\#{f@6qK3q>C?[9z.1u.o0;+-Hf^7^MfRBmvAJ@zZu:-aQeAr.$h0u2y{iy/5<0A`)KZQ8vcP'vVm3DS@{_{y.i";

		StringBuilder result = new StringBuilder();

		for (int i = 0; i < Math.min(s.length(), PW_KEY.length()); i++) {
			result.append((char) (s.charAt(i) ^ PW_KEY.charAt(i)));
		}

		return result.toString();
	}

	private static String decode(String encoded) {
		return encoded.substring(0, 4).equals("\0\0\0\0")
				? transform(encoded.substring(4)) : encoded;
	}

	private boolean checkStatusFileForPort(StringBuilder sReply) {
		// Read the status_file for forwarding port

		if (paramManagerDir == null) {
			return false;
		}

		String pathPIAManager = paramManagerDir.getValue();
		File pathPIAManagerData = new File(pathPIAManager, "data");

		try {
			File fileSettings = new File(pathPIAManagerData, "settings.json");
			String settingsString = FileUtil.readFileAsString(fileSettings, -1);
			Map<?, ?> mapSettings = JSONUtils.decodeJSON(settingsString);
			if (mapSettings != null && mapSettings.containsKey("portforward")) {
				boolean portForwardEnabled = (Boolean) mapSettings.get("portforward");
				if (!portForwardEnabled) {
					addReply(sReply, CHAR_WARN, "pia.no.port.config");
					return false;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		if (new File(pathPIAManager, "nolog").isFile()) {
			addReply(sReply, CHAR_WARN, "pia.no.logging");
		} else {

			File pathPIAManagerLog = new File(pathPIAManager, "log");

			File fileManagerLog = new File(pathPIAManagerLog, "pia_nw.log");
			if (fileManagerLog.isFile() && fileManagerLog.canRead()
					&& fileManagerLog.lastModified() > SystemTime.getOffsetTime(
							-1000L * 60 * 60 * 24)) {

				FileInputStream fis = null;
				try {
					fis = new FileInputStream(fileManagerLog);
					fis.skip(fileManagerLog.length() - 32767);
					String tail = FileUtil.readInputStreamAsString(fis, -1, "utf8");
					String FIND_STRING = "|status| Received status {";
					int i = tail.lastIndexOf(FIND_STRING);
					if (i >= 0) {
						int start = i + FIND_STRING.length() - 1;
						int end = tail.indexOf("\r", start);
						if (end < 0) {
							end = tail.indexOf('\n', start);
						}
						if (end >= 1) {
							String json = tail.substring(start, end);
							Map map = JSONUtils.decodeJSON(json);
							Object o = MapUtils.getMapMap(map, "forwarded_port",
									Collections.EMPTY_MAP).get("single");
							if (o instanceof Number) {
								int port = ((Number) o).intValue();

								addReply(sReply, CHAR_GOOD, "pia.port.in.log",
										Integer.toString(port));

								changePort(port, sReply);

								return true;
							}

							o = MapUtils.getMapMap(map, "region", Collections.emptyMap()).get(
									"single");
							if (o instanceof String) {
								Boolean supportsForwarding = null;
								String regionName = null;
								String ourRegion = (String) o;
								List listRegions = MapUtils.getMapList(map, "regions",
										Collections.emptyList());
								for (Object oRegion : listRegions) {
									if (!(oRegion instanceof Map)) {
										continue;
									}
									Map mapRegion = (Map) oRegion;
									String regionCode = MapUtils.getMapString(mapRegion,
											"region_code", null);
									if (ourRegion.equals(regionCode)) {
										Object forwarding = mapRegion.get(
												"supports_port_forwarding");
										regionName = (String) mapRegion.get("region_name");
										if (forwarding instanceof Boolean) {
											supportsForwarding = (Boolean) forwarding;
										}
										break;
									}
								}

								if (supportsForwarding != null) {
									addReply(sReply, CHAR_WARN,
											supportsForwarding ? "pia.missing.forwarding.port.region"
													: "pia.no.forwarding.port.region",
											regionName == null ? ourRegion : regionName);
								}

							}
						}
					}

				} catch (Throwable e) {
					e.printStackTrace();
				} finally {
					if (fis != null) {
						try {
							fis.close();
						} catch (IOException ignore) {
						}
					}
				}

			}
		}

		boolean gotValidPort = false;

		File fileStatus = new File(pathPIAManagerData, "status_file.txt");
		if (!fileStatus.isFile() || !fileStatus.canRead()
				|| fileStatus.lastModified() < SystemTime.getOffsetTime(
						-1000L * 60 * 60 * 24 * 14)) {
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
				if (decodeJSON != null && decodeJSON.containsKey("single")) {
					Object oPort = decodeJSON.get("single");
					if (oPort == null) {
						gotPort = true;

						String user = config.getPluginStringParameter(CONFIG_PIA_USER);
						byte[] pass = config.getPluginByteParameter(CONFIG_PIA_P);

						if (user == null || user.length() == 0 || pass == null
								|| pass.length == 0) {
							addReply(sReply, CHAR_WARN, "pia.no.forwarding.port");
						}

					}
					if (oPort instanceof Number) {
						gotPort = true;
						gotValidPort = true;

						Number nPort = (Number) oPort;
						int port = nPort.intValue();

						addReply(sReply, CHAR_GOOD, "pia.port.in.manager",
								Integer.toString(port));

						changePort(port, sReply);
					}
				}

				if (!gotPort) {
					addReply(sReply, CHAR_BAD, "pia.invalid.port.status_file", jsonPort);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return gotValidPort;
	}

	private boolean getPort(InetAddress bindIP, StringBuilder sReply) {
		InetAddress[] resolve = null;
		try {
			String clientID = null;
			if (paramManagerDir != null) {
				String pathPIAManager = paramManagerDir.getValue();

				File pathPIAManagerData = new File(pathPIAManager, "data");

				// Let's assume the client_id.txt file is the one for port forwarding.
				File fileClientID = new File(pathPIAManagerData, "client_id.txt");
				if (fileClientID.isFile() && fileClientID.canRead()) {
					clientID = FileUtil.readFileAsString(fileClientID, -1);
				} else {
					clientID = config.getPluginStringParameter("client.id", null);
				}
			}

			if (clientID == null) {
				clientID = RandomUtils.generateRandomAlphanumerics(20);
				config.setPluginParameter("client.id", clientID);
			}

			HttpPost post = new HttpPost(PIA_RPC_URL);

			String user = config.getPluginStringParameter(CONFIG_PIA_USER);
			byte[] bytesPass = config.getPluginByteParameter(CONFIG_PIA_P);
			String pass = bytesPass == null ? null : new String(bytesPass, "utf-8");

			if (user == null || user.length() == 0 || pass == null
					|| pass.length() == 0) {
				return false;
			}

			List<NameValuePair> urlParameters = new ArrayList<>();
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

			// If BiglyBT has a proxy set up (Tools->Options->Connection->Proxy), then
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

			StringBuilder result = new StringBuilder();
			String line;
			while ((line = rd.readLine()) != null) {
				result.append(line);
			}

			boolean gotPort = false;
			// should be {"port":xyz}

			Map<?, ?> mapResult = JSONUtils.decodeJSON(result.toString());
			if (mapResult != null && mapResult.containsKey("port")) {
				Object oPort = mapResult.get("port");
				if (oPort instanceof Number) {
					gotPort = true;
					Number nPort = (Number) oPort;
					int port = nPort.intValue();

					addReply(sReply, CHAR_GOOD, "pia.port.from.rpc",
							Integer.toString(port));

					changePort(port, sReply);
				}
			}

			if (!gotPort) {
				addReply(sReply, CHAR_WARN, "vpnhelper.rpc.bad", result.toString());

				// mapResult.containsKey("error")
				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.rpc.no.connect",
					bindIP + ": " + e.getMessage());

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

		boolean ok = paramTryPortRPC.getValue() && getPort(vpnIP, sReply);

		if (!ok) {
			ok = checkStatusFileForPort(sReply);
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
