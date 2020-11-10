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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.biglybt.core.util.Constants;
import com.biglybt.core.util.FileUtil;
import com.biglybt.core.util.SystemProperties;
import com.biglybt.util.JSONUtils;
import com.biglybt.util.MapUtils;

import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.config.Parameter;
import com.biglybt.pif.ui.config.StringParameter;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;

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
	private static final String CONFIG_MULLVAD_ACCOUNT = "mullvad.account.id";

	public Checker_Mullvad(PluginInterface pi) {
		super(pi);
	}

	public static List<Parameter> setupConfigModel(PluginInterface pi,
			BasicPluginConfigModel configModel) {
		List<Parameter> params = new ArrayList<>(1);
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
				return matcher.group(1);
			}
		} catch (IOException e) {
		}

		return "";
	}

	@Override
	protected Status callRPCforPort(InetAddress bindIP, StringBuilder sReply) {
		if (bindIP == null) {
			return null;
		}
		String id = config.getPluginStringParameter(CONFIG_MULLVAD_ACCOUNT);
		if (id == null || id.length() == 0) {
			// It's possible the user started Vuze before getting an account id,
			// so the default value may not be up to date
			id = getAccountID();
			if (id == null || id.length() == 0) {
				addReply(sReply, CHAR_WARN, "mullvad.account.id.required");
				return new Status(STATUS_ID_WARN);
			}
		}

		try {
			boolean gotPort = false;

			HttpGet getLoginPage = new HttpGet(
					"https://api.mullvad.net/www/accounts/" + id + "/");
			RequestConfig requestConfig = RequestConfig.custom().setLocalAddress(
					vpnIP).setConnectTimeout(15000).build();
			getLoginPage.setConfig(requestConfig);

			CloseableHttpClient httpClientLoginPage = HttpClients.createDefault();
			CloseableHttpResponse loginPageResponse = httpClientLoginPage.execute(
					getLoginPage);

			String s = FileUtil.readInputStreamAsString(
					loginPageResponse.getEntity().getContent(), -1, "utf8");

			if (s.startsWith("{")) {
				Map map = JSONUtils.decodeJSON(s);
				// There's a "auth_token" key that we might be able to use to login
				// to the website and add a port ourselves
				// There's also a "active" key that we could check and report if VPN expired
				Map mapAccount = MapUtils.getMapMap(map, "account",
						Collections.emptyMap());
				List listPorts = MapUtils.getMapList(mapAccount, "ports",
						Collections.emptyList());

				if (listPorts.size() == 0) {
					addReply(sReply, CHAR_WARN, "mullvad.no.port.created", s);
					return new Status(STATUS_ID_WARN, "vpnhelper.indicator.noport");
				}

				Object portObj = listPorts.get(0);
				if (portObj instanceof Number) {
					int port = ((Number) portObj).intValue();
					gotPort = true;

					addReply(sReply, CHAR_GOOD, "vpnhelper.port.from.rpc",
							Integer.toString(port));
					changePort(port, sReply);
				}
			}

			if (!gotPort) {
				addReply(sReply, CHAR_WARN, "vpnhelper.rpc.bad", s);

				return new Status(STATUS_ID_WARN);
			}
		} catch (Throwable t) {
			t.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.rpc.no.connect",
					bindIP + ": " + t.getMessage());

			return new Status(STATUS_ID_WARN);
		}
		return new Status(STATUS_ID_OK);
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

			if (appData == null || appData.length() <= 0) {
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
