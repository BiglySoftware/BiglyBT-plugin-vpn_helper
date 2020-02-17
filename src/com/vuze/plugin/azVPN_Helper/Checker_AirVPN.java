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
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;
import org.apache.http.message.BasicNameValuePair;

import com.biglybt.core.proxy.AEProxySelector;
import com.biglybt.core.proxy.AEProxySelectorFactory;
import com.biglybt.core.util.Constants;
import com.biglybt.core.util.SystemProperties;
import com.biglybt.core.util.UrlUtils;
import com.biglybt.core.xml.simpleparser.SimpleXMLParserDocumentFactory;
import com.biglybt.platform.PlatformManager;
import com.biglybt.platform.PlatformManagerFactory;
import com.biglybt.util.MapUtils;

import com.biglybt.pif.PluginConfig;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.platform.PlatformManagerException;
import com.biglybt.pif.ui.config.Parameter;
import com.biglybt.pif.ui.config.PasswordParameter;
import com.biglybt.pif.ui.config.StringParameter;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;
import com.biglybt.pif.utils.xml.simpleparser.SimpleXMLParserDocument;
import com.biglybt.pif.utils.xml.simpleparser.SimpleXMLParserDocumentAttribute;
import com.biglybt.pif.utils.xml.simpleparser.SimpleXMLParserDocumentNode;

/**
 * AirVPN
 * 
 * https://airvpn.org/
 * 
 */
@SuppressWarnings("unused")
public class Checker_AirVPN
	extends CheckerCommon
{

	private static final String VPN_DOMAIN = "airvpn.org";

	/*
	private static final String VPN_LOGIN_URL = "https://" + VPN_DOMAIN
			+ "/login";

	private static final String VPN_PORTS_URL = "https://" + VPN_DOMAIN
			+ "/ports/";

	private static final String REGEX_ActionURL = "action=['\"]([^'\"]+)['\"]";

	private static final String REGEX_AuthKey = "name=['\"]csrfKey['\"]\\s*value=['\"]([^\"']+)['\"]";

	private static final String REGEX_Port = "class=\"ports_port\"[^>]*>([0-9]+)<";

	private static final String REGEX_Token = "name=['\"]csrf_token['\"]\\s*value=['\"]([^\"']+)['\"]";

	private static final String REGEX_PortForwardedTo = "<td>Forwarded to:</td><td>([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)</td>";

	private static final String REGEX_NotConnected = "['\"]Not connected['\"]";

	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36";

	private HttpClientContext httpClientContext;
	*/

	public Checker_AirVPN() {
		super();
	}

	public Checker_AirVPN(PluginInterface pi) {
		super(pi);
	}

	// no groups
	public static List<Parameter> setupConfigModel(PluginInterface pi,
			BasicPluginConfigModel configModel) {
		List<Parameter> params = new ArrayList<>(1);

		params.add(configModel.addLabelParameter2("airvpn.open.port.howto"));
		/* Website now requires a real browser, can't scrape :(
		params.add(configModel.addLabelParameter2("airvpn.login.group.explain"));
		StringParameter paramUser = configModel.addStringParameter2(
				PluginConstants.CONFIG_USER, "vpnhelper.config.user", "");
		params.add(paramUser);
		PasswordParameter paramPass = configModel.addPasswordParameter2(
				PluginConstants.CONFIG_P, "vpnhelper.config.pass",
				PasswordParameter.ET_PLAIN, new byte[] {});
		params.add(paramPass);
	 */

		return params;
	}

	protected String getDefaultUsername() {
		try {
			File vpnConfigPath = getVPNConfigPath();
			if (vpnConfigPath == null) {
				return "";
			}

			File fileSettings = new File(vpnConfigPath, "AirVPN.xml");
			if (!fileSettings.isFile() || !fileSettings.canRead()) {
				return "";
			}
			SimpleXMLParserDocument xml = SimpleXMLParserDocumentFactory.create(
					fileSettings);
			SimpleXMLParserDocumentNode options = xml.getChild("options");
			SimpleXMLParserDocumentNode[] children = options.getChildren();

			Map<String, String> mapOptions = new HashMap<String, String>();

			for (SimpleXMLParserDocumentNode child : children) {
				SimpleXMLParserDocumentAttribute name = child.getAttribute("name");
				if (name != null) {
					SimpleXMLParserDocumentAttribute value = child.getAttribute("value");
					if (value != null) {
						mapOptions.put(name.getValue(), value.getValue());
					}
				}
			}
			String user = MapUtils.getMapString(mapOptions, "login", "");

			return user;
		} catch (Exception e) {
			PluginVPNHelper.log("Get login name: " + e.toString());
			return "";
		}
	}

	protected String getPassword() {
		try {
			File vpnConfigPath = getVPNConfigPath();
			if (vpnConfigPath == null) {
				return "";
			}

			File fileSettings = new File(vpnConfigPath, "AirVPN.xml");
			if (!fileSettings.isFile() || !fileSettings.canRead()) {
				return "";
			}
			SimpleXMLParserDocument xml = SimpleXMLParserDocumentFactory.create(
					fileSettings);
			SimpleXMLParserDocumentNode options = xml.getChild("options");
			SimpleXMLParserDocumentNode[] children = options.getChildren();

			Map<String, String> mapOptions = new HashMap<String, String>();

			for (SimpleXMLParserDocumentNode child : children) {
				SimpleXMLParserDocumentAttribute name = child.getAttribute("name");
				if (name != null) {
					SimpleXMLParserDocumentAttribute value = child.getAttribute("value");
					if (value != null) {
						mapOptions.put(name.getValue(), value.getValue());
					}
				}
			}
			String pw = MapUtils.getMapString(mapOptions, "password", "");

			return pw;
		} catch (Exception e) {
			PluginVPNHelper.log("Get login creds: " + e.toString());
			return "";
		}
	}

	@Override
	protected boolean canReach(InetAddress addressToReach) {
		try {
			URI canReachURL = new URI("https://" + VPN_DOMAIN);
			return canReach(addressToReach, canReachURL);
		} catch (URISyntaxException e) {
			return false;
		}
	}

	@Override
	protected Status callRPCforPort(InetAddress bindIP, StringBuilder sReply) {
		/*
		InetAddress[] resolve = null;
		try {

			String user = getDefaultUsername();
			String pass = null;
			if (user == null || user.length() == 0) {
				user = config.getPluginStringParameter(PluginConstants.CONFIG_USER);
				pass = new String(config.getPluginByteParameter(
						PluginConstants.CONFIG_P, new byte[0]), "utf-8");
			} else {
				pass = getPassword();
			}

			if (user == null || user.length() == 0 || pass == null
					|| pass.length() == 0) {
				addReply(sReply, CHAR_WARN, "airvpn.rpc.nocreds");
				return new Status(STATUS_ID_WARN);
			}

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

			RequestConfig requestConfig;
			StringBuffer token = new StringBuffer();

			boolean skipLoginPage = false;
			boolean alreadyLoggedIn = false;
			PortInfo[] ports = null;

			if (httpClientContext == null) {
				httpClientContext = HttpClientContext.create();
			} else {
				PluginVPNHelper.log(
						"Have existing context.  Trying to grab port list without logging in.");
				ports = scrapePorts(bindIP, token, sReply);
				// assume no token means we aren't logged in
				if (token.length() > 0) {
					PluginVPNHelper.log("Valid ports page. Skipping Login");
					skipLoginPage = true;
					alreadyLoggedIn = true;

					if (ports == null) {
						return new Status(STATUS_ID_WARN);
					}
				} else {
					ports = null;
				}
			}

			if (!skipLoginPage) {
				String loginURL = null;
				String authKey = null;

				PluginVPNHelper.log("Getting Login post URL and auth_key");

				HttpGet getLoginPage = new HttpGet(VPN_LOGIN_URL);
				requestConfig = RequestConfig.custom().setLocalAddress(
						bindIP).setConnectTimeout(15000).build();
				getLoginPage.setConfig(requestConfig);
				getLoginPage.setHeader("User-Agent", USER_AGENT);

				CloseableHttpClient httpClientLoginPage = HttpClients.createDefault();
				CloseableHttpResponse loginPageResponse = httpClientLoginPage.execute(
						getLoginPage, httpClientContext);

				BufferedReader rd = new BufferedReader(
						new InputStreamReader(loginPageResponse.getEntity().getContent()));

				Pattern patAuthKey = Pattern.compile(REGEX_AuthKey);

				String line = "";
				while ((line = rd.readLine()) != null) {
					if (line.contains("<form")
							&& line.contains("core.global.core.login")) {
						Matcher matcher = Pattern.compile(REGEX_ActionURL).matcher(line);
						if (matcher.find()) {
							loginURL = matcher.group(1);
							if (authKey != null) {
								break;
							}
						}
					}
					Matcher matcherAuthKey = patAuthKey.matcher(line);
					if (matcherAuthKey.find()) {
						authKey = matcherAuthKey.group(1);
						if (loginURL != null) {
							break;
						}
					}

					if (line.contains("['member_id']")
							&& line.matches(".*parseInt\\s*\\(\\s*[1-9][0-9]*\\s*.*")) {
						alreadyLoggedIn = true;
					}
				}
				rd.close();

				if (loginURL == null) {
					PluginVPNHelper.log("Could not scrape Login URL.  Using default");
					loginURL = "https://airvpn.org/login/";
				}
				if (authKey == null) {
					addReply(sReply, CHAR_WARN, "vpnhelper.rpc.noauthkey");
					return new Status(STATUS_ID_WARN);
				}

				loginURL = UrlUtils.unescapeXML(loginURL);

				///////////////////////////////

				if (alreadyLoggedIn) {
					PluginVPNHelper.log("Already Logged In");
				} else {
					PluginVPNHelper.log("Login URL:" + loginURL);

					HttpPost httpPostLogin = new HttpPost(loginURL);

					requestConfig = RequestConfig.custom().setLocalAddress(
							bindIP).setConnectTimeout(15000).build();

					httpPostLogin.setConfig(requestConfig);
					httpPostLogin.setHeader("User-Agent", USER_AGENT);

					CloseableHttpClient httpClient = HttpClients.createDefault();

					List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
					urlParameters.add(new BasicNameValuePair("auth", user));
					urlParameters.add(new BasicNameValuePair("password", pass));
					urlParameters.add(new BasicNameValuePair("csrfKey", authKey));
					urlParameters.add(
							new BasicNameValuePair("_processLogin", "usernamepassword"));
					urlParameters.add(new BasicNameValuePair("anonymous", "1"));
					urlParameters.add(new BasicNameValuePair("remember_me", "1"));

					httpPostLogin.setEntity(new UrlEncodedFormEntity(urlParameters));

					CloseableHttpResponse response = httpClient.execute(httpPostLogin,
							httpClientContext);

					rd = new BufferedReader(
							new InputStreamReader(response.getEntity().getContent()));

					line = "";
					while ((line = rd.readLine()) != null) {
					}

					PluginVPNHelper.log(
							"Login Result: " + response.getStatusLine().toString());
				}
			}

			////////////////////////////

			if (ports == null) {
				ports = scrapePorts(bindIP, token, sReply);
				if (ports == null && token.length() > 0) {
					addReply(sReply, CHAR_WARN, "airvpn.vpnhelper.rpc.notconnected");
					return new Status(STATUS_ID_WARN);
				}
			}

			PluginVPNHelper.log("Found Ports: " + Arrays.toString(ports));

			int existingIndex = ourPortInList(ports);
			if (existingIndex >= 0) {
				addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc.match",
						new String[] {
							ports[existingIndex].port
						});
				return new Status(STATUS_ID_OK);
			}

			boolean gotPort = false;

			// There's a limit of 20 ports.  If [0] isn't ours and 20 of them are
			// created, then assume our detection of "ours" is broke and just use
			// the first one
			if (ports != null && ((ports.length > 0 && ports[0].ourBinding)
					|| ports.length == 20)) {
				int port = Integer.parseInt(ports[0].port);
				gotPort = true;

				addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc", new String[] {
					Integer.toString(port)
				});

				changePort(port, sReply);
			} else if (ports != null) {
				// create port
				ports = createPort(bindIP, token, sReply);
				if (ports.length == 0) {
					// form post should have got the new port, but if it didn't, try
					// reloading the ports page again.
					token.setLength(0);
					ports = scrapePorts(bindIP, token, sReply);
				}

				PluginVPNHelper.log("Added a port. Ports: " + Arrays.toString(ports));

				existingIndex = ourPortInList(ports);
				if (existingIndex >= 0) {
					addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc.match",
							new String[] {
								ports[existingIndex].port
							});
					return new Status(STATUS_ID_OK);
				}

				if ((ports.length > 0 && ports[0].ourBinding) || ports.length == 20) {
					int port = Integer.parseInt(ports[0].port);
					gotPort = true;

					addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc", new String[] {
						Integer.toString(port)
					});

					changePort(port, sReply);
				}

			}

			if (!gotPort) {
				addReply(sReply, CHAR_WARN, "vpnhelper.rpc.no.connect", new String[] {
					bindIP.toString()
				});

				return new Status(STATUS_ID_WARN);
			}
		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.rpc.no.connect", new String[] {
				bindIP + ": " + e.getMessage()
			});

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
			 */
		return new Status(STATUS_ID_OK);
	}

	/*
	private PortInfo[] createPort(InetAddress bindIP, StringBuffer token,
			StringBuilder sReply)
			throws ClientProtocolException, IOException {
		HttpPost httpPostCreatePort = new HttpPost(VPN_PORTS_URL);

		RequestConfig requestConfig = RequestConfig.custom().setLocalAddress(
				bindIP).setConnectTimeout(15000).build();

		httpPostCreatePort.setConfig(requestConfig);
		httpPostCreatePort.setHeader("User-Agent", USER_AGENT);

		CloseableHttpClient httpClientCreatPort = HttpClients.createDefault();

		List<NameValuePair> urlParamsAddPort = new ArrayList<NameValuePair>();
		urlParamsAddPort.add(
				new BasicNameValuePair("csrf_token", token.toString()));
		urlParamsAddPort.add(new BasicNameValuePair("action", "ports_ins"));
		urlParamsAddPort.add(new BasicNameValuePair("ports_ins_port", ""));
		urlParamsAddPort.add(new BasicNameValuePair("ports_ins_protocol", "both"));
		urlParamsAddPort.add(new BasicNameValuePair("ports_ins_local", ""));
		urlParamsAddPort.add(new BasicNameValuePair("ports_ins_dns_name", ""));
		urlParamsAddPort.add(new BasicNameValuePair("ports_ins", "ports_ins"));

		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(urlParamsAddPort);
		httpPostCreatePort.setEntity(entity);

		CloseableHttpResponse responseCreatePort = httpClientCreatPort.execute(
				httpPostCreatePort, httpClientContext);
		BufferedReader rd = new BufferedReader(
				new InputStreamReader(responseCreatePort.getEntity().getContent()));

		String bindIPString = bindIP == null ? null : bindIP.getHostAddress();

		PortInfo[] ports = parsePorts(rd, bindIPString, token, sReply);
		rd.close();

		return ports;
	}

	private PortInfo[] scrapePorts(InetAddress bindIP, StringBuffer token,
			StringBuilder sReply)
			throws ClientProtocolException, IOException {
		String bindIPString = bindIP == null ? null : bindIP.getHostAddress();
		HttpGet getPortsPage = new HttpGet(VPN_PORTS_URL);
		RequestConfig requestConfig = RequestConfig.custom().setLocalAddress(
				bindIP).setConnectTimeout(15000).build();
		getPortsPage.setConfig(requestConfig);
		getPortsPage.setHeader("User-Agent", USER_AGENT);

		CloseableHttpClient httpClientPortsPage = HttpClients.createDefault();
		CloseableHttpResponse portsPageResponse = httpClientPortsPage.execute(
				getPortsPage, httpClientContext);

		BufferedReader rd = new BufferedReader(
				new InputStreamReader(portsPageResponse.getEntity().getContent()));

		PortInfo[] ports = parsePorts(rd, bindIPString, token, sReply);

		rd.close();

		return ports;
	}

	private PortInfo[] parsePorts(BufferedReader rd, String bindIPString,
			StringBuffer token, StringBuilder sReply)
			throws IOException {
		Pattern patPort = Pattern.compile(REGEX_Port);
		Pattern patToken = Pattern.compile(REGEX_Token);
		Pattern patFwdToIP = Pattern.compile(REGEX_PortForwardedTo);
		Pattern patNotConnected = Pattern.compile(REGEX_NotConnected);

		Map<String, PortInfo> mapPorts = new HashMap<String, PortInfo>();

		String line = "";
		String lastPortFound = null;
		while ((line = rd.readLine()) != null) {
			Matcher matcher = patPort.matcher(line);
			boolean found = matcher.find();
			if (found) {
				while (found) {
					lastPortFound = matcher.group(1);
					mapPorts.put(lastPortFound, new PortInfo(lastPortFound, false));

					Matcher matcherFwdToIP = patFwdToIP.matcher(line);
					while (matcherFwdToIP.find()) {
						String ip = matcherFwdToIP.group(1);
						if (ip.equals(bindIPString)) {
							mapPorts.put(lastPortFound, new PortInfo(lastPortFound, true));
						}
					}

					found = matcher.find();
				}
			} else {
				if (lastPortFound != null) {
					Matcher matcherFwdToIP = patFwdToIP.matcher(line);
					while (matcherFwdToIP.find()) {
						String ip = matcherFwdToIP.group(1);
						if (ip.equals(bindIPString)) {
							mapPorts.put(lastPortFound, new PortInfo(lastPortFound, true));
						}
					}
				}
			}

			if (token != null && token.length() == 0) {
				Matcher matcherToken = patToken.matcher(line);
				if (matcherToken.find()) {
					token.append(matcherToken.group(1));
				}
			}

			Matcher matcherNC = patNotConnected.matcher(line);
			if (matcherNC.find()) {
				addReply(sReply, CHAR_WARN, "airvpn.vpnhelper.rpc.notconnected");
				return null;
			}
		}

		PortInfo[] array = mapPorts.values().toArray(new PortInfo[0]);
		Arrays.sort(array, new Comparator<PortInfo>() {
			@Override
			public int compare(PortInfo x, PortInfo y) {
				return Boolean.valueOf(x.ourBinding).compareTo(
						Boolean.valueOf(y.ourBinding));
			}
		});
		return array;
	}
	 */

	protected File getVPNConfigPath() {
		PlatformManager platformManager = PlatformManagerFactory.getPlatformManager();

		try {
			File fDocPath = platformManager.getLocation(
					PlatformManager.LOC_USER_DATA);
			if (fDocPath != null) {
				File f = new File(fDocPath.getParentFile(),
						Constants.isLinux ? ".airvpn" : "AirVPN");
				if (f.isDirectory()) {
					return f;
				}
			}
		} catch (PlatformManagerException e) {
		}

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

			appData = userhome;
		} else {
			// unix type
			appData = userhome;
		}

		File f = new File(appData, Constants.isWindows ? "AirVPN" : ".airvpn");
		if (f.isDirectory()) {
			return f;
		}
		return null;
	}

	private int ourPortInList(PortInfo[] ports) {
		if (ports == null) {
			return -1;
		}
		PluginConfig pluginConfig = pi.getPluginconfig();
		int coreTCPPort = pluginConfig.getCoreIntParameter(
				PluginConfig.CORE_PARAM_INT_INCOMING_TCP_PORT);
		int coreUDPPort = pluginConfig.getCoreIntParameter(
				PluginConfig.CORE_PARAM_INT_INCOMING_UDP_PORT);
		if (coreTCPPort != coreUDPPort) {
			return -1;
		}

		boolean skipIfNotOurBinding = ports.length != 20;

		String sPort = Integer.toString(coreUDPPort);
		for (int i = 0; i < ports.length; i++) {
			PortInfo portInfo = ports[i];
			if (!portInfo.ourBinding && skipIfNotOurBinding) {
				return -1;
			}
			if (portInfo.port.equals(sPort)) {
				return i;
			}
		}
		return -1;
	}

	public static void main(String[] args) {
		Checker_AirVPN checker = new Checker_AirVPN();
		File vpnConfigPath = checker.getVPNConfigPath();
		System.out.println(vpnConfigPath);
		String defaultUsername = checker.getDefaultUsername();
		System.out.println("user=" + defaultUsername + "/" + checker.getPassword());

		checker.callRPCforPort(null, new StringBuilder());
	}

	private static class PortInfo
	{
		String port;

		boolean ourBinding;

		public PortInfo(String port, boolean ourBinding) {
			super();
			this.port = port;
			this.ourBinding = ourBinding;
		}

		/* (non-Javadoc)
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return port + ";" + ourBinding;
		}
	}

	public boolean showLoginConfig() {
		return getDefaultUsername().length() == 0;
	}
}
