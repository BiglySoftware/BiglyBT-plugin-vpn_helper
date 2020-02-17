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
import java.lang.reflect.Field;
import java.net.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;

import com.biglybt.core.Core;
import com.biglybt.core.CoreFactory;
import com.biglybt.core.networkmanager.admin.*;
import com.biglybt.core.proxy.AEProxySelector;
import com.biglybt.core.proxy.AEProxySelectorFactory;
import com.biglybt.core.util.*;
import com.biglybt.net.udp.uc.PRUDPPacketHandler;
import com.biglybt.net.udp.uc.PRUDPPacketHandlerFactory;
import com.biglybt.net.udp.uc.PRUDPReleasablePacketHandler;

import com.biglybt.pif.PluginConfig;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.utils.*;

/**
 * Common Checker class, shared amoungst azVPN_Air, azVPN_PIA, etc
 */
public abstract class CheckerCommon
{
	protected static final char CHAR_GOOD = '\u2714';

	protected static final char CHAR_BAD = '\u2716';

	protected static final char CHAR_WARN = '\u2318';

	protected static final int STATUS_ID_OK = 0;

	protected static final int STATUS_ID_BAD = 1;

	protected static final int STATUS_ID_WARN = 2;

	static {
		System.setProperty("org.apache.commons.logging.Log",
				"org.apache.commons.logging.impl.NoOpLog");
	}

	public PluginConfig config;

	public PluginInterface pi;
	protected UTTimer timer;
	protected String lastProtocolAddresses = "";
	protected String lastPortCheckStatus = "";
	protected boolean checkingPortBinding;
	protected LocaleUtilities texts;
	protected InetAddress testSocketAddress;
	protected InetAddress vpnIP;
	protected Status currentStatus = new Status(-1);
	private int minSubnetMaskBitCount = -1;

	public CheckerCommon() {
	}

	public CheckerCommon(PluginInterface pi) {
		this.pi = pi;
		this.config = pi.getPluginconfig();
		this.texts = pi.getUtilities().getLocaleUtilities();

		try {
			testSocketAddress = InetAddress.getByAddress(new byte[] {
				8,
				8,
				8,
				8
			});
		} catch (UnknownHostException e) {
		}

	}

	public void destroy() {
		if (timer != null) {
			timer.destroy();
			timer = null;
		}
	}

	protected final void buildTimer() {
		if (timer != null) {
			timer.destroy();
			timer = null;
		}
		int mins = config.getPluginIntParameter(
				PluginConstants.CONFIG_CHECK_MINUTES);
		if (mins == 0) {
			return;
		}
		timer = pi.getUtilities().createTimer("VPNHelper");
		timer.addPeriodicEvent(mins * 60 * 1000l, new UTTimerEventPerformer() {
			@Override
			public void perform(UTTimerEvent event) {
				try {
					portBindingCheck();
				} catch (Throwable t) {
					t.printStackTrace();
				}
			}
		});
	}

	public final String calcProtocolAddresses() {
		long now = pi.getUtilities().getCurrentSystemTime();
		StringBuilder sReply = new StringBuilder("Last Checked ").append(
				pi.getUtilities().getFormatters().formatDate(now)).append("\n");
		// Stolen from NetworkAdminImpl.generateDiagnostics
		// This takes some time (1s-ish), so it's better to do it on demand
		try {
			NetworkAdmin networkAdmin = NetworkAdmin.getSingleton();
			Core azureus_core = CoreFactory.getSingleton();

			NetworkAdminNetworkInterfaceAddress bindTo = null;
			try {
				NetworkAdminNetworkInterface[] interfaces = networkAdmin.getInterfaces();
				for (NetworkAdminNetworkInterface networkAdminInterface : interfaces) {
					NetworkAdminNetworkInterfaceAddress[] addresses = networkAdminInterface.getAddresses();
					for (NetworkAdminNetworkInterfaceAddress a : addresses) {
						InetAddress address = a.getAddress();
						if (address.equals(vpnIP)) {
							bindTo = a;
							break;
						}
					}
				}
			} catch (Throwable e) {
			}

			NetworkAdminProtocol[] protocols = networkAdmin.getOutboundProtocols(
					azureus_core);

			for (int i = 0; i < protocols.length; i++) {

				NetworkAdminProtocol protocol = protocols[i];

				try {

//					InetAddress ext_addr = networkAdmin.testProtocol(protocol);
					InetAddress ext_addr = protocol.test(
							protocol.getType() == NetworkAdminProtocol.PT_HTTP ? null
									: bindTo);

					String country = null;
					if (ext_addr != null) {

						List<LocationProvider> locationProviders = pi.getUtilities().getLocationProviders();
						for (LocationProvider locationProvider : locationProviders) {
							country = locationProvider.getCountryNameForIP(ext_addr,
									Locale.getDefault());
							if (country != null) {
								break;
							}
						}
					}

					addLiteralReply(sReply, protocol.getName() + " - " + ext_addr
							+ (country == null ? "" : " - " + country));

				} catch (NetworkAdminException e) {

					addLiteralReply(sReply,
							protocol.getName() + " - " + Debug.getNestedExceptionMessage(e));
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.nat.error", new String[] {
				e.toString()
			});
		}

		lastProtocolAddresses = sReply.toString();

		CheckerListener[] triggers = PluginVPNHelper.instance.getCheckerListeners();
		for (CheckerListener l : triggers) {
			try {
				l.protocolAddressesStatusChanged(lastProtocolAddresses);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return lastProtocolAddresses;
	}

	private final boolean matchesVPNIP(InetAddress address,
			NetworkInterface networkInterface) {
		if (address == null) {
			return false;
		}

		String[] excludes = config.getPluginStringParameter(
				PluginConstants.CONFIG_IGNORE_ADDRESS).split(";");
		if (excludes != null && excludes.length > 0) {
			String hostAddress = address.getHostAddress();
			for (String exclude : excludes) {
				if (hostAddress.equals(exclude)) {
					PluginVPNHelper.log(exclude + " matched and excluded");
					return false;
				}
			}
		}

		String regex = config.getPluginStringParameter(
				PluginConstants.CONFIG_VPN_IP_MATCHING);
		boolean matches = Pattern.matches(regex, address.getHostAddress());

		if (matches && excludes != null && excludes.length > 0) {
			if (networkInterface == null) {
				try {
					networkInterface = NetUtils.getByInetAddress(address);
				} catch (SocketException e) {
				}
			}
			if (networkInterface != null) {
				String name = networkInterface.getName();
				for (String exclude : excludes) {
					if (exclude.equals(name)) {
						PluginVPNHelper.log(exclude + " matched and excluded");
						return false;
					}
				}
			}
		}

		return matches;
	}

	protected final int handleFindBindingAddress(InetAddress currentBindIP,
			StringBuilder sReply) {
		return handleFindBindingAddress(currentBindIP, sReply, 0);
	}

	private final int handleFindBindingAddress(InetAddress currentBindIP,
			StringBuilder sReply, int numLoops) {
		if (currentBindIP == null) {
			addReply(sReply, CHAR_BAD, "!Bind IP null!", new String[] {
				"" + currentBindIP
			});
			return STATUS_ID_BAD;
		}

		int newStatusID = STATUS_ID_OK;

		Map<String, BindableInterface> mapBindableInterfaces = new HashMap<String, BindableInterface>();

		BindableInterface newBind = null;

		String s;

		// The "Any" field is equivalent to 0.0.0.0 in dotted-quad notation, which is unbound.
		// "Loopback" is 127.0.0.1, which is bound when Vuze can't bind to
		// user specified interface (ie. kill switched)
		if (currentBindIP.isAnyLocalAddress()) {
			addReply(sReply, CHAR_WARN, "vpnhelper.vuze.unbound");
		} else if (currentBindIP.isLoopbackAddress()) {
			addReply(sReply, CHAR_BAD, "vpnhelper.vuze.loopback");
		} else {
			// bound
			boolean isGoodExistingBind = matchesVPNIP(currentBindIP, null);
			if (isGoodExistingBind) {
				String niName = "Unknown Interface";
				try {
					NetworkInterface networkInterface = NetUtils.getByInetAddress(
							currentBindIP);
					niName = networkInterface.getName() + " ("
							+ networkInterface.getDisplayName() + ")";
				} catch (Throwable e) {
				}
				addReply(sReply, CHAR_GOOD, "vpnhelper.bound.good", new String[] {
					"" + currentBindIP,
					niName
				});
				vpnIP = currentBindIP;
			} else {
				addReply(sReply, CHAR_BAD, "vpnhelper.bound.bad", new String[] {
					"" + currentBindIP
				});
			}
		}

		try {
			boolean foundExistingVPNIP = false;
			NetworkAdmin networkAdmin = NetworkAdmin.getSingleton();

			// Find a bindable address that starts with 10.
			InetAddress[] bindableAddresses = networkAdmin.getBindableAddresses();

			for (InetAddress bindableAddress : bindableAddresses) {
				if (matchesVPNIP(bindableAddress, null)) {
					String hostAddress = bindableAddress.getHostAddress();
					BindableInterface bi = mapBindableInterfaces.get(hostAddress);
					if (bi == null) {
						bi = new BindableInterface(bindableAddress,
								NetUtils.getByInetAddress(bindableAddress));
						mapBindableInterfaces.put(hostAddress, bi);
						if (!foundExistingVPNIP && bindableAddress.equals(vpnIP)) {
							foundExistingVPNIP = true;
						}
					}
				}
			}

			// Find a Network Interface that has an address that starts with 10.
			NetworkAdminNetworkInterface[] interfaces = networkAdmin.getInterfaces();

			/* Test reverse *
			for (int i = 0; i < interfaces.length / 2; i++) {
				NetworkAdminNetworkInterface temp = interfaces[i];
				interfaces[i] = interfaces[interfaces.length - i - 1];
				interfaces[interfaces.length - i - 1] = temp;
			}
			/**/
			for (NetworkAdminNetworkInterface networkAdminInterface : interfaces) {
				NetworkAdminNetworkInterfaceAddress[] addresses = networkAdminInterface.getAddresses();
				for (NetworkAdminNetworkInterfaceAddress a : addresses) {
					InetAddress address = a.getAddress();
					if (address instanceof Inet4Address) {
						if (matchesVPNIP(address, null)) {
							String hostAddress = address.getHostAddress();
							BindableInterface bi = mapBindableInterfaces.get(hostAddress);
							if (bi == null) {
								bi = new BindableInterface(address,
										NetUtils.getByName(networkAdminInterface.getName()));
								mapBindableInterfaces.put(hostAddress, bi);
								if (!foundExistingVPNIP && address.equals(vpnIP)) {
									foundExistingVPNIP = true;
								}
							}
						}
					}
				}
			}

			if (vpnIP != null && !foundExistingVPNIP) {
				String niName = "Unknown Interface";
				try {
					NetworkInterface networkInterface = NetUtils.getByInetAddress(
							currentBindIP);
					niName = networkInterface.getName() + " ("
							+ networkInterface.getDisplayName() + ")";
				} catch (Throwable e) {
				}
				addReply(sReply, CHAR_WARN, "vpnhelper.existing.not.found",
						new String[] {
							"" + currentBindIP,
							niName
						});

				if (numLoops == 0) {
					try {
						Field fldLastNICheck = NetUtils.class.getDeclaredField(
								"last_ni_check");
						fldLastNICheck.setAccessible(true);
						fldLastNICheck.set(null, Long.valueOf(-1));
						return handleFindBindingAddress(currentBindIP, sReply, ++numLoops);
					} catch (Throwable t) {
						t.printStackTrace();
					}
				}
			}

			BindableInterface[] array = mapBindableInterfaces.values().toArray(
					new BindableInterface[0]);
			Arrays.sort(array);

			for (BindableInterface bi : array) {
				if (!bi.isValidPrefixLength(minSubnetMaskBitCount)) {
					addReply(sReply, CHAR_WARN, "vpnhelper.submask.too.broad",
							new String[] {
								"" + bi.address,
								bi.networkInterface == null ? "null"
										: bi.networkInterface.getName() + " ("
												+ bi.networkInterface.getDisplayName() + ")",
								"" + bi.networkPrefixLength,
								"" + minSubnetMaskBitCount
							});
				} else if (bi.canReach) {
					addReply(sReply, CHAR_GOOD, "vpnhelper.found.bindable.vpn",
							new String[] {
								"" + bi.address,
								bi.networkInterface == null ? "null"
										: bi.networkInterface.getName() + " ("
												+ bi.networkInterface.getDisplayName() + ")"
							});
				} else {
					addReply(sReply, CHAR_WARN, "vpnhelper.not.reachable", new String[] {
						"" + bi.address,
						bi.networkInterface == null ? "null" : bi.networkInterface.getName()
								+ " (" + bi.networkInterface.getDisplayName() + ")"
					});
				}
				PluginVPNHelper.log(
						"subnet: " + bi.networkPrefixLength + "; Score: " + bi.score);
			}
			newBind = array.length > 0 && array[0].canReach
					&& array[0].isValidPrefixLength(minSubnetMaskBitCount) ? array[0]
							: null;

			InetAddress localAddress = null;

			// Check if default routing goes through 10.*, by connecting to address
			// via socket.  Address doesn't need to be reachable, just routable.
			// This works on Windows, but on Mac returns a wildcard address
			DatagramSocket socket = new DatagramSocket();
			try {
				socket.connect(testSocketAddress, 0);
				localAddress = socket.getLocalAddress();
			} finally {
				socket.close();
			}

			if (localAddress != null && !localAddress.isAnyLocalAddress()) {
				NetworkInterface networkInterface = NetUtils.getByInetAddress(
						localAddress);

				s = texts.getLocalisedMessageText("vpnhelper.nonvuze.probable.route",
						new String[] {
							"" + localAddress,
							networkInterface == null ? "null" : networkInterface.getName()
									+ " (" + networkInterface.getDisplayName() + ")"
						});

				if ((localAddress instanceof Inet4Address)
						&& matchesVPNIP(localAddress, networkInterface)) {

					if (newBind == null) {

						int networkPrefixLength = getNetworkPrefixLength(networkInterface,
								localAddress);
						if (networkPrefixLength >= 0
								&& networkPrefixLength < minSubnetMaskBitCount) {
							s = null;
							addReply(sReply, CHAR_WARN, "vpnhelper.nonvuze.submask.too.broad",
									new String[] {
										"" + localAddress,
										networkInterface == null ? "null"
												: networkInterface.getName() + " ("
														+ networkInterface.getDisplayName() + ")",
										"" + networkPrefixLength,
										"" + minSubnetMaskBitCount
									});
						} else if (!canReach(localAddress)) {
							addReply(sReply, CHAR_WARN, "vpnhelper.not.reachable",
									new String[] {
										"" + localAddress,
										networkInterface == null ? "null"
												: networkInterface.getName() + " ("
														+ networkInterface.getDisplayName() + ")"
									});
						} else {
							newBind = new BindableInterface(localAddress, networkInterface);

							s = CHAR_GOOD + " " + s + " "
									+ texts.getLocalisedMessageText("vpnhelper.assuming.vpn");
						}
					} else if (localAddress.equals(newBind.address)) {
						s = CHAR_GOOD + " " + s + " "
								+ texts.getLocalisedMessageText("vpnhelper.same.address");
					} else {
						// Vuze not bound. We already found a boundable address, but it's not this one
						/* Possibly good case:
						 * - Vuze: unbound
						 * - Found Bindable: 10.100.1.6
						 * - Default Routing: 10.255.1.1
						 * -> Split network
						 */
						if (newStatusID != STATUS_ID_BAD) {
							newStatusID = STATUS_ID_WARN;
						}
						s = CHAR_WARN + " " + s + " "
								+ texts.getLocalisedMessageText(
										"vpnhelper.not.same.future.address")
								+ " "
								+ texts.getLocalisedMessageText(
										"default.routing.not.vpn.network.splitting")
								+ " " + texts.getLocalisedMessageText(
										"default.routing.not.vpn.network.splitting.unbound");
					}

					if (s != null) {
						addLiteralReply(sReply, s);
					}

				} else {
					s = CHAR_WARN + " " + s;
					if (!currentBindIP.isLoopbackAddress()) {
						s += " " + texts.getLocalisedMessageText(
								"default.routing.not.vpn.network.splitting");
					}

					if (newBind == null) {
						if (newStatusID != STATUS_ID_BAD) {
							newStatusID = STATUS_ID_WARN;
						}
						s += " " + texts.getLocalisedMessageText(
								"default.routing.not.vpn.network.splitting.unbound");
					}

					addLiteralReply(sReply, s);
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "vpnhelper.nat.error", new String[] {
				e.toString()
			});
		}

		if (newBind == null) {
			addReply(sReply, CHAR_BAD, "vpnhelper.vpn.ip.detect.fail");

			String configBindIP = config.getCoreStringParameter(
					PluginConfig.CORE_PARAM_STRING_LOCAL_BIND_IP);

			if (configBindIP != null && configBindIP.length() > 0) {
				addReply(sReply, CHAR_WARN,
						"vpnhelper" + (currentBindIP.isLoopbackAddress()
								? ".existing.bind.kept.loopback" : ".existing.bind.kept"),
						new String[] {
							configBindIP
						});

				if (currentBindIP.isLoopbackAddress()) {
					if (numLoops == 0) {
						try {
							Field fldLastNICheck = NetUtils.class.getDeclaredField(
									"last_ni_check");
							fldLastNICheck.setAccessible(true);
							fldLastNICheck.set(null, Long.valueOf(-1));
							return handleFindBindingAddress(currentBindIP, sReply,
									++numLoops);
						} catch (Throwable t) {
							t.printStackTrace();
						}
					}
				}
			}

			return STATUS_ID_BAD;
		}

		rebindNetworkInterface(newBind.networkInterface, newBind.address, sReply);
		return newStatusID;
	}

	/**
	 * @return rebind sucessful, or rebinding to already bound address
	 */
	private final boolean rebindNetworkInterface(
			NetworkInterface networkInterface, InetAddress onlyToAddress,
			final StringBuilder sReply) {
		vpnIP = onlyToAddress;

		config.setUnsafeBooleanParameter("Enforce Bind IP", true);
		config.setUnsafeBooleanParameter("Check Bind IP On Start", true);
		config.setUnsafeBooleanParameter("Plugin.UPnP.upnp.enable", false);
		config.setUnsafeBooleanParameter("Plugin.UPnP.natpmp.enable", false);

		/**
		if (true) {
			sReply.append("Would rebind to " + networkInterface.getDisplayName()
					+ onlyToAddress + "\n");
			return false;
		}
		/**/

		String ifName = networkInterface.getName();

		String configBindIP = config.getCoreStringParameter(
				PluginConfig.CORE_PARAM_STRING_LOCAL_BIND_IP);

		int bindNetworkInterfaceIndex = -1;
		if (onlyToAddress != null) {
			Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
			for (int j = 0; inetAddresses.hasMoreElements(); j++) {
				InetAddress element = inetAddresses.nextElement();
				if (element.equals(onlyToAddress)) {
					bindNetworkInterfaceIndex = j;
					break;
				}
			}
		}

		if (configBindIP.equals(ifName)
				|| (bindNetworkInterfaceIndex >= 0 && configBindIP.equals(
						ifName + "[" + bindNetworkInterfaceIndex + "]"))) {

			addReply(sReply, CHAR_GOOD, "vpnhelper.already.bound.good", new String[] {
				ifName
			});
		} else {
			String newConfigBindIP = ifName;
			if (bindNetworkInterfaceIndex >= 0) {
				newConfigBindIP += "[" + bindNetworkInterfaceIndex + "]";
			}

			final AESemaphore sem = new AESemaphore("VPNHelper BindWait");

			NetworkAdmin.getSingleton().addPropertyChangeListener(
					new NetworkAdminPropertyChangeListener() {
						@Override
						public void propertyChanged(String property) {
							if (property.equals(NetworkAdmin.PR_DEFAULT_BIND_ADDRESS)) {
								sem.releaseForever();
								NetworkAdmin.getSingleton().removePropertyChangeListener(this);

								addReply(sReply, CHAR_GOOD,
										"vpnhelper.bind.complete.triggered");
							}
						}
					});

			// I think setting CORE_PARAM_STRING_LOCAL_BIND_IP is actually synchronous
			// We set up a PropertyChangeListener in case it ever becomes asynchronous
			config.setCoreStringParameter(
					PluginConfig.CORE_PARAM_STRING_LOCAL_BIND_IP, newConfigBindIP);

			addReply(sReply, CHAR_GOOD, "vpnhelper.change.binding", new String[] {
				"" + newConfigBindIP,
				networkInterface == null ? "null" : networkInterface.getName() + " ("
						+ networkInterface.getDisplayName() + ")"
			});

			sem.reserve(11000);
			return sem.isReleasedForever();
		}
		return true;
	}

	protected final void addReply(StringBuilder sReply, char prefix, String id) {
		String s = (prefix == 0 ? "" : prefix + " ")
				+ texts.getLocalisedMessageText(id);
		addLiteralReply(sReply, s);
	}

	protected final void addReply(StringBuilder sReply, char prefix, String id,
			String... params) {
		String s = (prefix == 0 ? "" : prefix + " ")
				+ (texts == null ? "!" + id + "!" + Arrays.toString(params)
						: texts.getLocalisedMessageText(id, params));
		addLiteralReply(sReply, s);
	}

	protected final void addLiteralReply(StringBuilder sReply, String s) {
		sReply.append(s).append("\n");
		PluginVPNHelper.log(s);
	}

	protected final void changePort(int port, StringBuilder sReply) {
		boolean changed = false;
		PluginConfig pluginConfig = pi.getPluginconfig();
		int coreTCPPort = pluginConfig.getCoreIntParameter(
				PluginConfig.CORE_PARAM_INT_INCOMING_TCP_PORT);
		int coreUDPPort = pluginConfig.getCoreIntParameter(
				PluginConfig.CORE_PARAM_INT_INCOMING_UDP_PORT);
		if (coreTCPPort != port) {
			pluginConfig.setCoreIntParameter(
					PluginConfig.CORE_PARAM_INT_INCOMING_TCP_PORT, port);
			addReply(sReply, CHAR_GOOD, "vpnhelper.changed.port", "TCP",
					Integer.toString(coreTCPPort), Integer.toString(port));
			changed = true;
		}
		if (coreUDPPort != port) {
			pluginConfig.setCoreIntParameter(
					PluginConfig.CORE_PARAM_INT_INCOMING_UDP_PORT, port);
			addReply(sReply, CHAR_GOOD, "vpnhelper.changed.port", "UDP",
					Integer.toString(coreUDPPort), Integer.toString(port));
			changed = true;
		}
		if (!changed) {
			addReply(sReply, CHAR_GOOD, "vpnhelper.port.already.set",
					Integer.toString(port));
		}
	}

	public final Status getCurrentStatus() {
		return currentStatus;
	}

	protected final Status findBindingAddress(StringBuilder sReply) {
		Status newStatus;

		// Find our VPN binding (interface) address.  Checking UDP is the best bet,
		// since TCP and http might be proxied
		List<PRUDPPacketHandler> handlers = PRUDPPacketHandlerFactory.getHandlers();
		if (handlers.size() == 0) {
			PRUDPReleasablePacketHandler releasableHandler = PRUDPPacketHandlerFactory.getReleasableHandler(
					0);
			handlers = PRUDPPacketHandlerFactory.getHandlers();
			releasableHandler.release();
		}
		if (handlers.size() == 0) {
			addLiteralReply(sReply, CHAR_BAD + " No UDP Handlers");

			newStatus = new Status(STATUS_ID_BAD);
		} else {

			InetAddress currentBindIP = null;
			for (PRUDPPacketHandler handler : handlers) {
				currentBindIP = handler.getBindIP();
				if (currentBindIP != null) {
					break;
				}
			}
			newStatus = new Status(handleFindBindingAddress(currentBindIP, sReply));
		}
		return newStatus;
	}

	public final String portBindingCheck() {
		synchronized (this) {
			if (checkingPortBinding) {
				return lastPortCheckStatus;
			}
			checkingPortBinding = true;
		}

		CheckerListener[] triggers = PluginVPNHelper.instance.getCheckerListeners();
		for (CheckerListener l : triggers) {
			try {
				l.portCheckStart();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		StringBuilder sReply = new StringBuilder();

		try {
			Status newStatus = findBindingAddress(sReply);

			boolean doPortForwarding = config.getPluginBooleanParameter(
					PluginConstants.CONFIG_DO_PORT_FORWARDING);

			if (doPortForwarding) {

				boolean callRPC = true;
				String portReadLocation = config.getPluginStringParameter(
						PluginConstants.CONFIG_PORT_READ_LOCATION);
				if (!portReadLocation.isEmpty()) {
					String portReadLocationRegex = config.getPluginStringParameter(
							PluginConstants.CONFIG_PORT_READ_LOCATION_REGEX);
					callRPC = !getPortFromLocationLocation(portReadLocation,
							portReadLocationRegex, sReply);
				}

				if (callRPC) {
					Status rpcCallResult = null;
					if (newStatus.statusID != STATUS_ID_BAD && vpnIP != null) {
						rpcCallResult = callRPCforPort(vpnIP, sReply);
					}

					if (rpcCallResult != null) {
						newStatus = rpcCallResult;

						if (newStatus.statusID == STATUS_ID_WARN) {
							addReply(sReply, CHAR_WARN,
									"vpnhelper.port.forwarding.get.failed");
						}
					}
				}
			}

			if (newStatus.statusID != -1) {
				currentStatus = newStatus;
			}
			String msgID = null;
			switch (newStatus.statusID) {
				case STATUS_ID_BAD:
					msgID = "vpnhelper.topline.bad";
					break;
				case STATUS_ID_OK:
					msgID = "vpnhelper.topline.ok";
					break;
				case STATUS_ID_WARN:
					msgID = "vpnhelper.topline.warn";
					break;
			}
			if (msgID != null) {
				sReply.insert(0, texts.getLocalisedMessageText(msgID) + "\n");
			}

		} catch (Throwable t) {
			t.printStackTrace();
			PluginVPNHelper.log(t.toString());
		}

		lastPortCheckStatus = sReply.toString();

		triggers = PluginVPNHelper.instance.getCheckerListeners();
		for (CheckerListener l : triggers) {
			try {
				l.portCheckStatusChanged(lastPortCheckStatus);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		synchronized (this) {
			checkingPortBinding = false;
		}
		return lastPortCheckStatus;
	}

	private boolean getPortFromLocationLocation(String location, String regex,
			StringBuilder sReply) {
		String textToParse = null;
		boolean warned = false;
		if (location.startsWith("http")) {
			try {
				HttpGet getLoginPage = new HttpGet(location);
				RequestConfig requestConfig = RequestConfig.custom().setLocalAddress(
						vpnIP).setConnectTimeout(15000).build();
				getLoginPage.setConfig(requestConfig);

				CloseableHttpClient httpClientLoginPage = HttpClients.createDefault();
				CloseableHttpResponse loginPageResponse = httpClientLoginPage.execute(
						getLoginPage);

				textToParse = FileUtil.readInputStreamAsString(
						loginPageResponse.getEntity().getContent(), -1, "utf8");

			} catch (Throwable t) {
				addReply(sReply, CHAR_WARN, "vpnhelper.port.from.location.failed",
						location, t.toString());
				warned = true;
			}
		}
		if (textToParse == null) {
			File file = new File(location);
			if (file.isFile()) {
				try {
					textToParse = FileUtil.readFileAsString(file, -1, "utf8");
				} catch (Throwable t) {
					addReply(sReply, CHAR_WARN, "vpnhelper.port.from.location.failed",
							location, t.toString());
				}
			}
		}

		if (textToParse != null) {
			try {
				String portString;
				if (regex.isEmpty()) {
					portString = textToParse;
				} else {
					Pattern pat = Pattern.compile(regex);
					Matcher matcher = pat.matcher(textToParse);
					if (matcher.find()) {
						if (matcher.groupCount() > 0) {
							portString = matcher.group(1);
						} else {
							portString = regex.substring(matcher.start(), matcher.end());
						}
					} else {
						addReply(sReply, CHAR_WARN, "vpnhelper.port.from.location.failed",
								location, "No matching port string matching '" + regex
										+ " from " + textToParse);
						return false;
					}
				}

				int port = Integer.parseInt(portString);
				if (port > 0) {
					changePort(port, sReply);
					return true;
				}

			} catch (Throwable t) {
				addReply(sReply, CHAR_WARN, "vpnhelper.port.from.location.failed",
						location, t.toString());
				warned = true;
			}
		}

		if (!warned) {
			addReply(sReply, CHAR_WARN, "vpnhelper.port.from.location.failed",
					location, "Can't Find");
		}
		return false;
	}

	protected abstract Status callRPCforPort(InetAddress vpnIP,
			StringBuilder sReply);

	protected abstract boolean canReach(InetAddress addressToReach);

	protected boolean canReach(InetAddress binrAddress, URI uri) {

		InetAddress[] resolve = null;
		try {
			String domain = uri.getHost();

			// If Vuze has a proxy set up (Tools->Options->Connection->Proxy), then
			// we'll need to disable it for the URL
			AEProxySelector selector = AEProxySelectorFactory.getSelector();
			if (selector != null) {
				resolve = SystemDefaultDnsResolver.INSTANCE.resolve(domain);

				for (InetAddress address : resolve) {
					selector.setProxy(new InetSocketAddress(address, 443),
							Proxy.NO_PROXY);
				}
			}

			HttpHead getHead = new HttpHead(uri);
			RequestConfig requestConfig = RequestConfig.custom().setLocalAddress(
					binrAddress).setConnectionRequestTimeout(6000).setConnectTimeout(
							12000).build();
			getHead.setConfig(requestConfig);

			CloseableHttpResponse response = HttpClients.createDefault().execute(
					getHead);

			response.close();

		} catch (Throwable t) {
			PluginVPNHelper.log("Trying to access " + uri + " on " + binrAddress
					+ " caused " + t.toString());
			t.printStackTrace();
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

	public void setMinSubnetMaskBitCount(int minSubnetBitCount) {
		this.minSubnetMaskBitCount = minSubnetBitCount;
	}

	public int getNetworkPrefixLength(NetworkInterface networkInterface,
			InetAddress address) {
		int networkPrefixLength = -1;
		List<InterfaceAddress> interfaceAddresses = networkInterface.getInterfaceAddresses();
		for (InterfaceAddress interfaceAddress : interfaceAddresses) {
			if (!interfaceAddress.getAddress().equals(address)) {
				continue;
			}
			networkPrefixLength = interfaceAddress.getNetworkPrefixLength();
			// JDK-7107883 : getNetworkPrefixLength() does not return correct prefix length
			// networkPrefixLength will be zero on Java <= 7 when there is no
			// Broadcast address.
			// I'm guessing there is no broadcast address returned when mask is 32
			// on linux, but I can't confirm (I've seen it though)
			if (networkPrefixLength == 0 && interfaceAddress.getBroadcast() == null) {
				networkPrefixLength = 32;
			}
		}
		return networkPrefixLength;
	}

	public static class Status
	{
		public int statusID;

		String indicatorID = null;

		String indicatorTooltipID = null;

		public Status(int statusID) {
			this.statusID = statusID;
		}

		public Status(int statusID, String indicatorID) {
			this.statusID = statusID;
			this.indicatorID = indicatorID;
		}

		public String getIndicatorTooltipKey() {
			if (indicatorTooltipID != null) {
				return indicatorTooltipID;
			}
			return getIndicatorKey() + ".tooltip";
		}

		public String getIndicatorKey() {
			if (indicatorID != null) {
				return indicatorID;
			}
			switch (statusID) {
				case STATUS_ID_OK:
					return "vpnhelper.indicator.ok";
				case STATUS_ID_WARN:
					return "vpnhelper.indicator.warn";
				case STATUS_ID_BAD:
					return "vpnhelper.indicator.bad";
			}
			return null;
		}
	}

	private class BindableInterface
		implements Comparable<BindableInterface>
	{
		public InetAddress address;

		public boolean canReach;

		public int networkPrefixLength = -1;

		public NetworkInterface networkInterface;

		public int score;

		public BindableInterface(InetAddress address,
				NetworkInterface networkInterface) {
			this.address = address;
			this.networkInterface = networkInterface;
			this.canReach = canReach(address);

			if (networkInterface != null) {
				String name = networkInterface.getName();
				String displayName = networkInterface.getDisplayName();

				if (displayName.contains("VPN")) {
					score += 2;
				} else if (displayName.contains("TAP")) {
					score++;
				} else if (name.startsWith("eth")) {
					score--;
				}

				networkPrefixLength = getNetworkPrefixLength(networkInterface, address);
			}
		}

		public boolean isValidPrefixLength(int minMask) {
			return networkPrefixLength == -1 || networkPrefixLength >= minMask;
		}

		/* (non-Javadoc)
		 * @see java.lang.Comparable#compareTo(java.lang.Object)
		 */
		@Override
		public int compareTo(BindableInterface o) {
			// canReach at top
			int i = Boolean.valueOf(o.canReach).compareTo(Boolean.valueOf(canReach));

			// Valid subnet masks at top
			if (i == 0) {
				i = Boolean.valueOf(
						o.isValidPrefixLength(minSubnetMaskBitCount)).compareTo(
								Boolean.valueOf(isValidPrefixLength(minSubnetMaskBitCount)));
			}

			// Highest score at top
			if (i == 0) {
				i = Integer.valueOf(o.score).compareTo(Integer.valueOf(score));
			}

			// most restrictive subnet mask at top
			if (i == 0) {
				i = Integer.valueOf(o.networkPrefixLength).compareTo(
						Integer.valueOf(networkPrefixLength));
			}
			return i;
		}
	}
}
