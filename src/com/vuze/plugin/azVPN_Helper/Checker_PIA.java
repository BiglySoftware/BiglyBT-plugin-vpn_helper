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
import java.nio.file.Files;
import java.util.*;

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
import com.biglybt.core.util.*;
import com.biglybt.util.JSONUtils;
import com.biglybt.util.MapUtils;

import com.biglybt.pif.PluginConfig;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.config.ConfigParameter;
import com.biglybt.pif.config.ConfigParameterListener;
import com.biglybt.pif.ui.config.*;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;
import com.biglybt.pif.utils.LocaleUtilities;
import com.biglybt.pif.utils.UTTimer;
import com.biglybt.pif.utils.Utilities;

/**
 * Private Internet Access VPN
 * <br/>
 * https://www.privateinternetaccess.com
 * <p/>
 * RPC Specs from their forum.
 * <p/>
 * CLI Specs from https://www.privateinternetaccess.com/helpdesk/kb/articles/pia-desktop-command-line-interface
 * <p/>
 * Only one Port, so port cycling is not an option.
 */
@SuppressWarnings({
	"unused",
	"DuplicateStringLiteralInspection"
})
public class Checker_PIA
	extends CheckerCommon
	implements ConfigParameterListener
{
	public static final String CONFIG_PIA_MANAGER_DIR = "pia_manager.dir";

	public static final String CONFIG_PIA_P = "pia_p.privx";

	public static final String CONFIG_PIA_USER = "pia_user";

	private static final String CONFIG_PIA_TRY_PORT_RPC = "pia_try.port.rpc";

	private static final String CONFIG_PIA_USE_CLI = "pia.use.cli";

	// Is it always 70000? who knows
	private static final int STATUS_FILE_PORT_INDEX = 70000;

	private static final String VPN_DOMAIN = "www.privateinternetaccess.com";

	private static final String PIA_RPC_URL = "https://" + VPN_DOMAIN
			+ "/vpninfo/port_forward_assignment";

	private static DirectoryParameter paramManagerDir;

	private static BooleanParameter paramTryPortRPC;

	private static BooleanParameter paramUseCLI;

	private Process cliProcess;

	private final Object cliProcessLock = new Object();

	private String lastCLIPortStatus = "";

	private boolean lastCLIPortStatusIsPort = false;

	public Checker_PIA(PluginInterface pi) {
		super(pi);
		setMinSubnetMaskBitCount(24);
		paramUseCLI.addConfigParameterListener(this);
	}

	public static List<Parameter> setupConfigModel(PluginInterface pi,
			BasicPluginConfigModel configModel) {
		List<Parameter> params = new ArrayList<>(1);
		File path = getPIAManagerPath(pi.getUtilities());
		paramManagerDir = configModel.addDirectoryParameter2(CONFIG_PIA_MANAGER_DIR,
				CONFIG_PIA_MANAGER_DIR, path == null ? "" : path.toString());
		paramManagerDir.setVisible(pi.getUtilities().isWindows());
		params.add(paramManagerDir);
		if (paramManagerDir.hasBeenSet()) {
			String value = paramManagerDir.getValue();
			if (value == null || !new File(value).isDirectory()) {
				paramManagerDir.resetToDefault();
			}
		}

		String[] creds = getDefaultCreds(pi);

		// AirVPN and PIA used to share CONFIG_PIA_USER and CONFIG_PIA_P
		// Check if old keys are used, and migrate to separate keys
		PluginConfig pc = pi.getPluginconfig();
		if (!pc.hasPluginParameter(CONFIG_PIA_USER)
				&& pc.hasPluginParameter(PluginConstants.CONFIG_USER)
				&& creds[0].isEmpty()) {
			String val = pc.getPluginStringParameter(PluginConstants.CONFIG_USER);
			if (val != null && !val.isEmpty()) {
				pc.setPluginParameter(CONFIG_PIA_USER, val);
			}
		}
		if (!pc.hasPluginParameter(CONFIG_PIA_P)
				&& pc.hasPluginParameter(PluginConstants.CONFIG_P)
				&& creds[1].isEmpty()) {
			byte[] val = pc.getPluginByteParameter(PluginConstants.CONFIG_P);
			if (val != null && val.length > 0) {
				pc.setPluginParameter(CONFIG_PIA_P, val);
			}
		}

		paramUseCLI = configModel.addBooleanParameter2(CONFIG_PIA_USE_CLI,
				CONFIG_PIA_USE_CLI, true);
		params.add(paramUseCLI);

		paramTryPortRPC = configModel.addBooleanParameter2(CONFIG_PIA_TRY_PORT_RPC,
				"pia.try.port.rpc", !creds[1].isEmpty());
		//paramTryPortRPC.setSuffixLabelKey("pia.try.port.rpc.info");
		params.add(paramTryPortRPC);

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

	private Status getCLIStatus() {
		Status status = new Status(
				lastCLIPortStatusIsPort ? STATUS_ID_OK : STATUS_ID_WARN);
		if (lastCLIPortStatus.equalsIgnoreCase("Unavailable")) {
			status.indicatorID = "vpnhelper.indicator.noport";
		} else {
			status.indicatorTooltipID = "!"
					+ texts.getLocalisedMessageText("pia.cli.port.status", new String[] {
						lastCLIPortStatus
					}) + "!";
		}
		return status;
	}

	private Status setupCLI(StringBuilder sbReply) {
		synchronized (cliProcessLock) {
			if (cliProcess != null && cliProcess.isAlive()) {
				addReply(sbReply, CHAR_GOOD, "pia.cli.running", lastCLIPortStatus);
				return getCLIStatus();
			}
		}

		Utilities utils = pi.getUtilities();
		File piaManagerBinPath = getPIAManagerBinPath(utils);
		if (piaManagerBinPath == null) {
			addReply(sbReply, CHAR_BAD, "pia.cli.not.found", "");
			Status status = new Status(STATUS_ID_WARN);
			status.indicatorTooltipID = "!"
					+ texts.getLocalisedMessageText("pia.cli.not.found", new String[] {
						""
					}) + "!";
			return status;
		}
		File fileCLI = new File(piaManagerBinPath,
				utils.isWindows() ? "piactl.exe" : "piactl");
		if (!fileCLI.exists()) {
			addReply(sbReply, CHAR_BAD, "pia.cli.not.found", fileCLI.toString());
			Status status = new Status(STATUS_ID_WARN);
			status.indicatorTooltipID = "!"
					+ texts.getLocalisedMessageText("pia.cli.not.found", new String[] {
						fileCLI.toString()
					}) + "!";
			return status;
		}
		try {
			synchronized (cliProcessLock) {
				cliProcess = Runtime.getRuntime().exec(new String[] {
					fileCLI.getAbsolutePath(),
					"monitor",
					"portforward"
				});

				BufferedReader brIS = new BufferedReader(
						new InputStreamReader(cliProcess.getInputStream()));

				Thread stdOutReader = new Thread(() -> {
					try {
						String line;
						while ((line = brIS.readLine()) != null) {
							processCLI(line);
						}
					} catch (Exception e) {
						PluginVPNHelper.log(
								"piactl monitor error: " + Debug.getNestedExceptionMessage(e));
						e.printStackTrace();
					}

					// Restart if needed
					synchronized (cliProcessLock) {
						if (cliProcess != null && !cliProcess.isAlive()) {
							portBindingCheck();
						}
					}
				}, "piactl monitor");
				stdOutReader.setDaemon(true);
				stdOutReader.start();
			}

			// process immediately sends current status. Wait a few ms to be sure
			// we get it.
			try {
				Thread.sleep(250);
			} catch (InterruptedException e) {
			}

			addReply(sbReply, CHAR_GOOD, "pia.cli.startup", fileCLI.getAbsolutePath(),
					lastCLIPortStatus);

			return getCLIStatus();
		} catch (IOException e) {
			addReply(sbReply, CHAR_GOOD, "pia.cli.error",
					Debug.getNestedExceptionMessage(e));
			e.printStackTrace();
		}

		return null;
	}

	private void processCLI(String line) {
		PluginVPNHelper.log("piactl monitor portforward returned " + line);
		lastCLIPortStatus = line;
		lastCLIPortStatusIsPort = line.matches("[0-9]+");
		if (lastCLIPortStatusIsPort) {
			try {
				int newPort = Integer.parseInt(line);
				UTTimer timer = pi.getUtilities().createTimer("PIA_Port");
				timer.addEvent(System.currentTimeMillis() + 2000, event -> {
					portBindingCheck();
					changePort(newPort, new StringBuilder());
				});
				return;
			} catch (Throwable t) {
				PluginVPNHelper.log(Debug.getNestedExceptionMessageAndStack(t));
				lastCLIPortStatusIsPort = false;
			}
		}
		portBindingCheck();
	}

	private static File getPIAManagerDataPath(Utilities utils) {
		if (paramManagerDir == null) {
			return null;
		}

		String pathPIAManager = paramManagerDir.getValue();
		if (pathPIAManager == null) {
			return null;
		}

		if (utils.isUnix()) {
			return new File(pathPIAManager, "etc");
		}

		// Windows has it in "data", OSX in root.  Check both
		File pathPIAManagerData = new File(pathPIAManager, "data");
		if (pathPIAManagerData.exists()) {
			return pathPIAManagerData;
		}
		pathPIAManagerData = new File(pathPIAManager);
		if (pathPIAManagerData.exists()) {
			return pathPIAManagerData;
		}
		return null;
	}

	protected static String[] getDefaultCreds(PluginInterface pi) {
		String[] ret = {
			"",
			""
		};
		File pathPIAManagerData = getPIAManagerDataPath(pi.getUtilities());
		if (pathPIAManagerData == null) {
			return ret;
		}
		try {

			// settings.json has the user name
			File fileSettings = new File(pathPIAManagerData, "settings.json");
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

			if (ret[0].isEmpty()) {
				File fileAccount = new File(pathPIAManagerData, "account.json");
				if (fileAccount.exists() && Files.isReadable(fileAccount.toPath())) {
					settingsText = FileUtil.readFileAsString(fileAccount, -1);
					mapSettings = JSONUtils.decodeJSON(settingsText);
					ret[0] = MapUtils.getMapString(mapSettings, "username", "");
					// There's a password key, but it's always blank
					// There's an openvpnPassword, but it's encrypted/obfuscated and is
					// hard to say if it's the right pw
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	// Transform for old PIA manager
	private static String transform(CharSequence s) {
		String PW_KEY = "GN\\\\Lqnw-xc]=jQ}fTyN[Y|x5Db-FET?&)T\\#{f@6qK3q>C?[9z.1u.o0;+-Hf^7^MfRBmvAJ@zZu:-aQeAr.$h0u2y{iy/5<0A`)KZQ8vcP'vVm3DS@{_{y.i";

		StringBuilder result = new StringBuilder();

		for (int i = 0; i < Math.min(s.length(), PW_KEY.length()); i++) {
			result.append((char) (s.charAt(i) ^ PW_KEY.charAt(i)));
		}

		return result.toString();
	}

	// Decoder for old PIA manager
	private static String decode(String encoded) {
		return encoded.substring(0, 4).equals("\0\0\0\0")
				? transform(encoded.substring(4)) : encoded;
	}

	private static File getPIAManagerLogFile(Utilities utils) {
		File fileManagerLog = null;
		if (utils.isOSX()) {
			fileManagerLog = new File(
					"/Library/Application Support/com.privateinternetaccess.vpn/daemon.log");
			if (fileManagerLog.isFile()) {
				return fileManagerLog;
			}
		} else if (utils.isUnix()) {
			fileManagerLog = new File("/opt/piavpn/var/daemon.log");
			if (fileManagerLog.isFile()) {
				return fileManagerLog;
			}
		}

		File piaManagerDataPath = getPIAManagerDataPath(utils);
		if (piaManagerDataPath != null) {
			fileManagerLog = new File(piaManagerDataPath, "daemon.log");
			if (fileManagerLog.isFile()) {
				return fileManagerLog;
			}
		}

		String pathPIAManager = paramManagerDir.getValue();
		File oldLogFile = new File(new File(pathPIAManager, "log"), "pia_nw.log");
		if (oldLogFile.isFile()) {
			return oldLogFile;
		}
		return fileManagerLog;
	}

	private static File getPIAManagerBinPath(Utilities utils) {
		File piaManagerPath;
		if (utils.isWindows()) {
			piaManagerPath = getPIAManagerPath(utils);
		} else if (utils.isOSX()) {
			return new File(
					"/Applications/Private Internet Access.app/Contents/MacOS");
		} else {
			piaManagerPath = getPIAManagerPath(utils);
			if (piaManagerPath != null && piaManagerPath.isDirectory()) {
				return new File(piaManagerPath, "bin");
			}
		}
		if (piaManagerPath != null && piaManagerPath.isDirectory()) {
			return piaManagerPath;
		}
		return null;
	}

	private static File getPIAManagerPath(Utilities utils) {
		File pathPIAManager = null;
		if (utils.isWindows()) {
			String pathProgFiles = System.getenv("ProgramFiles");
			if (pathProgFiles != null) {
				pathPIAManager = new File(pathProgFiles, "Private Internet Access");
				if (!pathPIAManager.exists()) {
					File oldPath = new File(pathProgFiles, "pia_manager");
					if (oldPath.exists()) {
						pathPIAManager = oldPath;
					}
				}
			}
			if (pathPIAManager == null || !pathPIAManager.exists()) {
				String pathProgFiles86 = System.getenv("ProgramFiles(x86)");
				if (pathProgFiles86 == null && pathProgFiles != null) {
					pathProgFiles86 = pathProgFiles + " (x86)";
				}
				if (pathProgFiles86 != null) {
					pathPIAManager = new File(pathProgFiles86, "Private Internet Access");
					if (!pathPIAManager.exists()) {
						File oldPath = new File(pathProgFiles86, "pia_manager");
						if (oldPath.exists()) {
							pathPIAManager = oldPath;
						}
					}
				}
			}
			if (pathPIAManager == null || !pathPIAManager.exists()) {
				pathPIAManager = new File("C:\\Program Files\\Private Internet Access");
				if (!pathPIAManager.exists()) {
					File oldPath = new File("C:\\Program Files\\pia_manager");
					if (oldPath.exists()) {
						pathPIAManager = oldPath;
					}
				}
			}
		} else if (utils.isOSX()) {
			pathPIAManager = new File(
					"/Library/Preferences/com.privateinternetaccess.vpn");
			if (pathPIAManager.exists()) {
				return pathPIAManager;
			}
			File oldPath = new File(System.getProperty("user.home"), ".pia_manager");
			if (oldPath.exists()) {
				return oldPath;
			}
		} else {
			pathPIAManager = new File("/opt/piavpn");
			if (pathPIAManager.exists()) {
				return pathPIAManager;
			}
			File oldPath = new File(System.getProperty("user.home"), ".pia_manager");
			if (oldPath.exists()) {
				return oldPath;
			}
		}

		return pathPIAManager;
	}

	private Status checkStatusFileForPort(StringBuilder sReply) {
		// Read the status_file for forwarding port

		File pathPIAManagerData = getPIAManagerDataPath(pi.getUtilities());
		if (pathPIAManagerData == null) {
			return new Status(STATUS_ID_WARN);
		}
		File pathPIAManager = new File(paramManagerDir.getValue());

		try {
			File fileSettings = new File(pathPIAManagerData, "settings.json");
			String settingsString = FileUtil.readFileAsString(fileSettings, -1);
			Map<?, ?> mapSettings = JSONUtils.decodeJSON(settingsString);
			if (mapSettings != null) {
				// old key was "portforward", new key is "portForward"
				Boolean portForwardEnabled = mapSettings.containsKey("portforward")
						? (Boolean) mapSettings.get("portforward")
						: (Boolean) mapSettings.get("portForward");
				if (portForwardEnabled != null && !portForwardEnabled) {
					addReply(sReply, CHAR_WARN, "pia.no.port.config");
					return new Status(STATUS_ID_WARN);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		if (searchLogForPort(sReply)) {
			return new Status(STATUS_ID_OK);
		}

		// Old PIA Manager: Check status_file.txt in data dir
		boolean gotValidPort = false;

		File fileStatus = new File(pathPIAManagerData, "status_file.txt");
		if (!fileStatus.isFile() || !Files.isReadable(fileStatus.toPath())
				|| fileStatus.lastModified() < SystemTime.getOffsetTime(
						-1000L * 60 * 60 * 24 * 14)) {
			return new Status(STATUS_ID_WARN);
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

		return new Status(gotValidPort ? STATUS_ID_OK : STATUS_ID_WARN);
	}

	/**
	 * Search Log files for port number
	 * <p/>
	 * This is for very old PIA Manager versions and will be removed in the future
	 */
	private boolean searchLogForPort(StringBuilder sReply) {
		// Old PIA manager had a "nolog" file when logging was off
		String pathPIAManager = paramManagerDir.getValue();
		if (pathPIAManager == null) {
			return false;
		}
		if (new File(pathPIAManager, "nolog").isFile()) {
			addReply(sReply, CHAR_WARN, "pia.no.logging");
		}

		// Search log file for port

		File fileManagerLog = getPIAManagerLogFile(pi.getUtilities());
		if (fileManagerLog == null || !fileManagerLog.isFile()
				|| !Files.isReadable(fileManagerLog.toPath())
				|| fileManagerLog.lastModified() <= SystemTime.getOffsetTime(
						-1000L * 60 * 60 * 24)) {

			if (pi.getUtilities().isUnix()) {
				if (fileManagerLog == null || !new File(fileManagerLog.getParentFile(),
						"debug.txt").isFile()) {
					addReply(sReply, CHAR_WARN, "pia.no.logging");
				}
			} else {
				File fileDataPath = getPIAManagerDataPath(pi.getUtilities());
				if (fileDataPath != null) {
					if (!new File(fileDataPath, "debug.txt").isFile()) {
						addReply(sReply, CHAR_WARN, "pia.no.logging");
					}
				}
			}

			return false;
		}

		FileInputStream fis = null;
		try {
			fis = new FileInputStream(fileManagerLog);
			long skip = fileManagerLog.length() - (1024 * 128);
			if (skip > 0) {
				//noinspection ResultOfMethodCallIgnored
				fis.skip(skip);
			}
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
					Map<?, ?> map = JSONUtils.decodeJSON(json);
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
						List<?> listRegions = MapUtils.getMapList(map, "regions",
								Collections.emptyList());
						for (Object oRegion : listRegions) {
							if (!(oRegion instanceof Map)) {
								continue;
							}
							Map<?, ?> mapRegion = (Map<?, ?>) oRegion;
							String regionCode = MapUtils.getMapString(mapRegion,
									"region_code", null);
							if (ourRegion.equals(regionCode)) {
								Object forwarding = mapRegion.get("supports_port_forwarding");
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
			} else {
				FIND_STRING = "Forwarded port updated to ";
				i = tail.lastIndexOf(FIND_STRING);
				if (i >= 0) {
					int start = i + FIND_STRING.length();
					int end = tail.indexOf("\r", start);
					if (end < 0) {
						end = tail.indexOf('\n', start);
					}
					if (end >= 1) {
						String portString = tail.substring(start, end);
						try {
							int port = Integer.parseInt(portString);
							if (port > 0) {
								addReply(sReply, CHAR_GOOD, "pia.port.in.log",
										Integer.toString(port));

								changePort(port, sReply);

								return true;
							} else if (port == -3) {
								// Assume -3 means server doesn't support open port
								addReply(sReply, CHAR_WARN, "pia.no.forwarding.port.region",
										"current");
							} else {
								addReply(sReply, CHAR_WARN, "pia.port.in.log", portString);
							}
						} catch (NumberFormatException num) {
							addReply(sReply, CHAR_WARN, "pia.port.in.log", portString);
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

		return false;
	}

	/**
	 * Calls PIA RPC to get port
	 */
	private Status getPort(InetAddress bindIP, StringBuilder sReply) {
		InetAddress[] resolve = null;
		try {
			String clientID = null;
			File pathPIAManagerData = getPIAManagerDataPath(pi.getUtilities());
			if (pathPIAManagerData != null) {
				// client_id.txt is no longer used.  Check anyway for legacy users
				File fileClientID = new File(pathPIAManagerData, "client_id.txt");
				if (fileClientID.isFile() && Files.isReadable(fileClientID.toPath())) {
					clientID = FileUtil.readFileAsString(fileClientID, -1);
				} else {
					// Newer PIA Manager stores a client id in account.json
					File fileAccount = new File(pathPIAManagerData, "account.json");
					if (fileAccount.exists() && Files.isReadable(fileAccount.toPath())) {
						String settingsText = FileUtil.readFileAsString(fileAccount, -1);
						Map<?, ?> mapSettings = JSONUtils.decodeJSON(settingsText);
						clientID = MapUtils.getMapString(mapSettings, "clientId", null);
					}
				}
			}

			if (clientID == null || clientID.isEmpty()) {
				clientID = config.getPluginStringParameter("client.id", null);

				if (clientID == null) {
					clientID = RandomUtils.generateRandomAlphanumerics(20);
					config.setPluginParameter("client.id", clientID);
				}
			}

			HttpPost post = new HttpPost(PIA_RPC_URL);

			String user = config.getPluginStringParameter(CONFIG_PIA_USER);
			byte[] bytesPass = config.getPluginByteParameter(CONFIG_PIA_P);
			String pass = bytesPass == null ? null : new String(bytesPass, "utf-8");

			if (user == null || user.length() == 0 || pass == null
					|| pass.length() == 0) {
				return new Status(STATUS_ID_WARN);
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

				String error = MapUtils.getMapString(mapResult, "error", null);
				if (error != null) {
					LocaleUtilities l10n = pi.getUtilities().getLocaleUtilities();
					error = "!" + error + "\n" + l10n.getLocalisedMessageText(
							"vpnhelper.indicator.noport.tooltip") + "!";
				}
				Status status = new Status(STATUS_ID_WARN);
				status.indicatorTooltipID = error;
				return status;
			}
		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.rpc.no.connect",
					bindIP + ": " + e.getMessage());

			return new Status(STATUS_ID_WARN);
		} finally {
			AEProxySelector selector = AEProxySelectorFactory.getSelector();
			if (selector != null && resolve != null) {
				for (InetAddress address : resolve) {
					AEProxySelectorFactory.getSelector().removeProxy(
							new InetSocketAddress(address, 443));
				}
			}
		}
		return new Status(STATUS_ID_OK);
	}

	@Override
	protected Status callRPCforPort(InetAddress vpnIP, StringBuilder sReply) {

		Status rpcStatus = null;

		if (paramUseCLI.getValue()) {
			Status cliStatus = setupCLI(sReply);
			if (cliStatus != null) {
				return cliStatus;
			}
		}

		if (vpnIP == null) {
			return null;
		}

		if (paramTryPortRPC.getValue()) {
			rpcStatus = getPort(vpnIP, sReply);
			if (rpcStatus.statusID == STATUS_ID_OK) {
				return rpcStatus;
			}
		}

		Status status = checkStatusFileForPort(sReply);
		if (status.statusID == STATUS_ID_WARN) {
			// RPC Status indicator overrides file check status indicator
			if (rpcStatus != null && rpcStatus.indicatorID != null) {
				status.indicatorID = rpcStatus.indicatorID;
			} else if (status.indicatorID == null) {
				status.indicatorID = "vpnhelper.indicator.noport";
			}
			if (status.indicatorTooltipID == null && rpcStatus != null) {
				status.indicatorTooltipID = rpcStatus.indicatorTooltipID;
			}
		}
		return status;
	}

	/* (non-Javadoc)
	 * @see com.vuze.plugin.azVPN_Helper.CheckerCommon#canReach(java.net.InetAddress)
	 */
	@Override
	protected boolean canReach(InetAddress bindAddress) {
		try {
			URI canReachURL = new URI("https://" + VPN_DOMAIN);
			return canReach(bindAddress, new URI("https://www.google.com"))
					|| canReach(bindAddress, canReachURL);
		} catch (URISyntaxException e) {
			return false;
		}
	}

	@Override
	public void destroy() {
		super.destroy();
		synchronized (cliProcessLock) {
			if (cliProcess != null) {
				cliProcess.destroy();
				cliProcess = null;
			}
		}
		paramUseCLI.removeConfigParameterListener(this);
	}

	@Override
	public void configParameterChanged(ConfigParameter param) {
		if (paramUseCLI.getValue()) {
			// Will eventually run setupCLI
			portBindingCheck();
		} else {
			synchronized (cliProcessLock) {
				if (cliProcess != null) {
					cliProcess.destroy();
					cliProcess = null;
				}
			}
		}
	}
}
