--This file is created for check some deamons like miniupnpd,8021xd...

    local mtkwifi = require("mtkwifi")
    local devs = mtkwifi.get_all_devs()
    local nixio = require("nixio")

function miniupnpd_chk(devname,vif,enable)
    if not devs[devname].vifs[vif] then return end -- vif may be wrong without l1profile
    local WAN_IF=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get network.wan.ifname"))

    os.execute("rm -rf /etc/miniupnpd.conf")
    os.execute("iptables -wt nat -F MINIUPNPD 1>/dev/null 2>&1")
    --rmeoving the rule to MINIUPNPD
    os.execute("iptables -wt nat -D PREROUTING -i  "..WAN_IF.."  -j MINIUPNPD 1>/dev/null 2>&1")
    os.execute("iptables -wt nat -X MINIUPNPD 1>/dev/null 2>&1")

    --removing the MINIUPNPD chain for filter
    os.execute("iptables -wt filter -F MINIUPNPD 1>/dev/null 2>&1")
    --adding the rule to MINIUPNPD

    os.execute("iptables -wt filter -D FORWARD -i  "..WAN_IF.."  ! -o  "..WAN_IF.."  -j MINIUPNPD 1>/dev/null 2>&1")
    os.execute("iptables -wt filter -X MINIUPNPD 1>/dev/null 2>&1")

    os.execute("iptables -wt nat -N MINIUPNPD")
    os.execute("iptables -wt nat -A PREROUTING -i "..WAN_IF.." -j MINIUPNPD")
    os.execute("iptables -wt filter -N MINIUPNPD")
    os.execute("iptables -wt filter -A FORWARD -i "..WAN_IF.." ! -o "..WAN_IF.." -j MINIUPNPD")

    if mtkwifi.exists("/tmp/run/miniupnpd."..vif) then
        os.execute("cat /tmp/run/miniupnpd."..vif.." | xargs kill -9")
    end

    if enable then
        local profile = mtkwifi.search_dev_and_profile()[devname]
        local cfgs = mtkwifi.load_profile(profile)
        local ssid_index = devs[devname]["vifs"][vif].vifidx
        local wsc_conf_mode = ""
        local PORT_NUM = 7777+(string.byte(vif, -1)+string.byte(vif, -2))
        local LAN_IPADDR = mtkwifi.__trim(mtkwifi.read_pipe("uci -q get network.lan.ipaddr"))
        local LAN_MASK = mtkwifi.__trim(mtkwifi.read_pipe("uci -q get network.lan.netmask"))
        local port = 6352 + (string.byte(vif, -1)+string.byte(vif, -2))
        LAN_IPADDR = LAN_IPADDR.."/"..LAN_MASK
        wsc_conf_mode = mtkwifi.token_get(cfgs["WscConfMode"], ssid_index, "")

        local file = io.open("/etc/miniupnpd.conf", "w")
        if nil == file then
            nixio.syslog("debug","open file /etc/miniupnpd.conf fail")
        end

        file:write("ext_ifname=",WAN_IF,'\n','\n',
                   "listening_ip=",LAN_IPADDR,'\n','\n',
                   "port=",port,'\n','\n',
                   "bitrate_up=800000000",'\n',
                   "bitrate_down=800000000",'\n','\n',
                   "secure_mode=no",'\n','\n',
                   "system_uptime=yes",'\n','\n',
                   "notify_interval=30",'\n','\n',
                   "uuid=68555350-3352-3883-2883-335030522880",'\n','\n',
                   "serial=12345678",'\n','\n',
                   "model_number=1",'\n','\n',
                   "enable_upnp=no",'\n','\n')
        file:close()

        if wsc_conf_mode ~= "" and wsc_conf_mode ~= "0" then
            os.execute("miniupnpd -m 1 -I "..vif.." -P /var/run/miniupnpd."..vif.." -G -i "..WAN_IF.." -a "..LAN_IPADDR.." -n "..PORT_NUM)
        end
    end
end

function d8021xd_chk(devname, prefix, vif, enable)
    local profile = mtkwifi.search_dev_and_profile()[devname]
    local cfgs = mtkwifi.load_profile(profile)
    local ssid_index = devs[devname]["vifs"][vif].vifidx
    local auth_mode = mtkwifi.token_get(cfgs["AuthMode"], ssid_index, "")
    local ieee8021x = mtkwifi.token_get(cfgs["IEEE8021X"], ssid_index, "")
    local pat_auth_mode = {"WPA$", "WPA;", "WPA2$", "WPA2;", "WPA1WPA2$", "WPA1WPA2;", "WPA3$", "WPA3;", "192$", "192;"}
    local pat_ieee8021x = {"1$", "1;"}
    local apd_en = false
    if mtkwifi.exists("/tmp/run/8021xd_"..vif..".pid") then
        os.execute("cat /tmp/run/8021xd_"..vif..".pid | xargs kill -9")
        os.execute("rm /tmp/run/8021xd_"..vif..".pid")
    end
    if enable then
        for _, pat in ipairs(pat_auth_mode) do
            if string.find(auth_mode, pat) then
                apd_en = true
            end
        end

        for _, pat in ipairs(pat_ieee8021x) do
            if string.find(ieee8021x, pat) then
                apd_en = true
            end
        end

        if apd_en then
            os.execute("8021xd -p "..prefix.. " -i "..vif)
        end
    end
end
function wifi_dlink_easymesh()
    local isdefault=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get system.@system[0].isdefault"))
    if tostring(isdefault) == "true" then
        os.execute("wificonf -f /etc/mapd_cfg.txt set DeviceRole 2")
        os.execute("uci set wireless.globals.DeviceRole=2")
    else
        os.execute("wificonf -f /etc/mapd_cfg.txt set DeviceRole 1")
        os.execute("uci set wireless.globals.DeviceRole=1")
		os.execute("uci set wireless.globals.wpsrole=register")
    end
    os.execute("uci commit")
end

-- wifi service that require to start after wifi up
function wifi_service_misc()
	local MapEanble=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get wireless.globals.MapEnable"))
    local SmartCon=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get wireless.globals.Smartconnect"))
	-- local NetworkMode=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get system.@system[0].CurrentOPMode2"))
	if tostring(MapEanble) == "1" then 
		wifi_dlink_easymesh()
	else
	    os.execute("wificonf -f /etc/mapd_cfg.txt set MapEnable 0")
	    os.execute("wificonf -f /etc/mapd_cfg.txt set MAP_Turnkey 0")
	    if tostring(SmartCon) == "1" then
	       os.execute("wificonf -f /etc/mapd_cfg.txt set BSEnable 1")
	    else
	       os.execute("wificonf -f /etc/mapd_cfg.txt set BSEnable 0")
	    end
	end
    -- 1.Wapp
    if exists("/usr/bin/wapp_openwrt.sh") then
		os.execute("/usr/bin/wapp_openwrt.sh")
    end

    -- 2.EasyMesh
    if exists("/usr/bin/EasyMesh_openwrt.sh") then
			os.execute("/usr/bin/EasyMesh_openwrt.sh")
    end
    --3. easymesh_cfg 同步uci配置到mapd，并且同步controller配置到Agent

    if tostring(MapEanble) == "1" then
        os.execute("easymesh_cfg syn_uci_to_wts_bss_info /etc/wts_bss_info_config")
        os.execute("mapd_cli /tmp/mapd_ctrl renew")
    end

end

function wps_pin(devname,vif,enable)
    if not devs[devname].vifs[vif] then return end -- vif may be wrong without l1profile
    local WpsPin_En=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get wireless.globals.WPSPin"))
    local WpsPin_Code=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get wireless."..vif..".WscVendorPinCode"))
    print("gjf: pincode is "..WpsPin_Code)
    if tostring(WpsPin_En) == "1" then
        os.execute("iwpriv " ..vif.. " set WscConfMode=7")
        os.execute("iwpriv " ..vif.. " set WscMode=1")
        os.execute("iwpriv " ..vif.. " set WscConfStatus=2")
        os.execute("iwpriv " ..vif.. " set WscSetupLock=0")
        os.execute("iwpriv " ..vif.. " set WscMaxPinAttack=3")
        os.execute("iwpriv " ..vif.. " set WscSetupLockTime=60")
        os.execute("iwpriv " ..vif.. " set WscVendorPinCode="..WpsPin_Code)
    else
        os.execute("iwpriv " ..vif.. " set WscSetupLock=1")
    end
end

function wifi_guest_set(devname,vif,band)
    if not devs[devname].vifs[vif] then return end -- vif may be wrong without l1profile
    if string.match(vif,"ra1") 
    or string.match(vif,"rai1") then
        print("Guest network interface")
    else
        print("Current Guest network interface has ra1 rai1")
        return
    end
    local InternetAccessOnly=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get wireless.globals.InternetAccessOnly"))
    local GateWayIp=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get network.lan.ipaddr"))
    local GuestIfname=mtkwifi.__trim(mtkwifi.read_pipe("uci -q get wireless."..devname:gsub("%.","_")..".GuestIfname"))
    
    -- print("gjf: Internet Access Only status is "..InternetAccessOnly)
    --dbg()
    if InternetAccessOnly then
        print("*****************VIF:"..vif.."****************************")
        --dbg()
        if tostring(InternetAccessOnly) == "true" then
            if tostring(band) == "2G"
            or tostring(band) == "5G" then
                os.execute("echo 1 > /proc/wlan_"..band.."/InternetAccessOnly")
                os.execute("iwpriv "..vif.." set NoForwarding=1")
            end
        else
            if tostring(band) == "2G"
            or tostring(band) == "5G" then
                os.execute("echo 0 > /proc/wlan_"..band.."/InternetAccessOnly")
                os.execute("iwpriv "..vif.." set NoForwarding=0")
            end
        end
        
        if GateWayIp then
            if tostring(band) == "2G"
            or tostring(band) == "5G" then
                os.execute("echo "..GateWayIp.." > /proc/wlan_"..band.."/GateWayIp")
            end
        end
		
        if tostring(band) == "2G"
        or tostring(band) == "5G" then
            os.execute("ifconfig br-lan | grep \"Scope:Link\" | awk  '{print $3}' | cut -d '/' -f 1 > /proc/wlan_"..band.."/GateWayIpv6")
        end
		
        if GuestIfname then
            if tostring(band) == "2G"
            or tostring(band) == "5G" then
                os.execute("echo "..GuestIfname.." > /proc/wlan_"..band.."/GuestIfname")
            end
        end
    end
end

function HwNat_enable(devname,vif)
    if not devs[devname].vifs[vif] then return end -- vif may be wrong without l1profile
    local hw_nat=mtkwifi.__trim(mtkwifi.read_pipe("hwnat.global.enabled"))
    if tostring(hw_nat) == "1" then
        os.execute("iwpriv "..vif.." set hw_nat_register=1")
    else
        os.execute("iwpriv "..vif.." set hw_nat_register=0")
    end
end



