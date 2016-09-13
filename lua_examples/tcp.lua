-------------------------------------------------------------------------------
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
-- Copyright (c) 2015, Hadriel Kaplan
-- This code is in the Public Domain, or the BSD (3 clause) license
-- if Public Domain does not apply in your country.
--
-- Version: 1.0
--
-------------------------------------------------------------------------------
--[[

    This code is a plugin for Wireshark, to dissect Quagga FPM Netlink
    protocol messages over TCP.

    The purpose of this script is two-fold:
        1) To decode a protocol Wireshark does not (currently) decode natively.
        2) To provide a tutorial for TCP-based Lua dissection.

    Because of the second goal (a tutorial), this script has a lot more comments
    than one would normally expect or want.

----------------------------------------

    OVERVIEW:

    This Lua plugin script dissects Quagga/zebra-style FPM messages carrying
    Netlink messages, over TCP connections.

    Wireshark has a "Netlink" protocol dissector, but it currently expects
    to be running on a Linux cooked-mode SLL header and link type. That's
    because Netlink has traditionally been used between the Linux kernel
    and user-space apps. But the open-source Quagga, zebra, and the
    commercial ZebOS routing products also send Netlink messages over TCP
    to other processes or even outside the box, to a "Forwarding Plane Manager"
    (FPM) that controls forwarding-plane devices (typically hardware).

    The Netlink message is encapsulated within an FPM header, which identifies
    an FPM message version (currently 1), the type of message it contains
    (namely a Netlink message), and its length.

    So we have:
    struct fpm_msg_hdr_t
    {
        uint8_t  version;
        uint8_t  msg_type;
        uint16_t msg_len;
    }
    followed by a Netlink message.

    Note that there is no Linux cooked-mode SLL header in this case.
    Therefore, to be able to re-use Wireshark's built-in Netlink dissector,
    this Lua script creates a fake SLL header, and invokes the built-in
    Netlink dissector using that.


----------------------------------------

    HOW TO RUN THIS SCRIPT:
    
    Wireshark and Tshark support multiple ways of loading Lua scripts: through
    a dofile() call in init.lua, through the file being in either the global
    or personal plugins directories, or via the command line.

    See the Wireshark Developer's Guide chapter on Lua
    (https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html).
    Once this script is loaded, it creates a new protocol named "FPM", as
    described in the "Background" section. If you have a capture file with FPM
    messages in it, simply select one in the Packet List pane, right-click on
    it, and select "Decode As ...", and then in the dialog box that shows up
    scroll down the list of protocols to one called "FPM", select that and
    click the "ok" or "apply" button. Voila`, you're now decoding FPM packets
    using the dissector in this script. Another way is to download the capture
    file made for this script (called "segmented_fpm.pcap", and open that -
    since the FPM packets in it use TCP port 2620, and since the FPM protocol
    in this script has been set to automatically decode TCP port 2620, it will
    automagically do it without doing "Decode As ...".

----------------------------------------

    Writing Lua Dissectors for TCP-based Protocols:

    A Lua-based protocol dissector for TCP works much the same as one for UDP,
    which is described in the 'dissector.lua' tutorial script available on
    https://wiki.wireshark.org/Lua/Examples. The main differences are
    interfacing with Wireshark's Lua API for reassembly, and handling the
    various conditions that can arise due to running on TCP.

    In particular, your dissector function needs to handle the following
    conditions which can occur for TCP-based packet captures:
        1) The TCP packet segment might only have a portion of your message.
        2) The TCP packet segment might contain multiple of your messages.
        3) The TCP packet might be in the middle of your message, because
           a previous segment was not captured.
        4) The TCP packet might be cut-off, because the user set Wireshark to
           limit the size of the packets being captured.
        5) Any combination of the above.

    For case (4), the simplest thing to do is just not dissect packets that
    are cut-off. Check the Tvb's len() vs. reported_len(), and if they're
    different that means the packet was cut-off.

    For case (3), your dissector should try to perform some sanity checking of
    an early field if possible. If the sanity check fails, then ignore this
    packet and wait for the next one. "Ignoring" the packet means returning
    the number 0 from your dissector.

    For case (2), currently this requires you to write your own while-loop,
    dissecting your message within the while-loop, such that you can dissect
    multiple of your messages each time Wireshark invokes your Proto's
    dissector() function.

    For case (1), you have to dissect your message enough to figure out what
    the full length will be - if you can figure that out, then set the Pinfo's
    desegment_len to how many more bytes than are currently in the Tvb that
    you need in order to decode the full message; or if you don't know exactly
    how many more bytes you need, then set the Pinfo desegment_len to the pre-
    defined value of "DESEGMENT_ONE_MORE_SEGMENT". You also need to set the
    Pinfo's desegment_offset to the offset in the tvbuff at which you want the
    dissector to continue processing when next invoked by Wireshark. The next
    time a TCP packet segment is received by Wireshark, it will invoke your
    Proto's dissector function with a Tvb buffer composed of the data bytes
    starting at the desegment_offset of the previous Tvb buffer together with
    desegment_len more bytes.

    For the return value of your Proto's dissector() function, you should
    return one of the following:
        1) If the packet does not belong to your dissector, return 0. You must
           *not* set the Pinfo.desegment_len nor the desegment_offset if you
           return 0.
        2) If you need more bytes, set the Pinfo's
           desegment_len/desegment_offset as described earlier, and return
           either nothing, or return the length of the Tvb. Either way is fine.
        3) If you don't need more bytes, return either nothing, or return the
           length of the Tvb. Either way is fine.

    See the code in this script for an example of the above.

]]----------------------------------------


----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 2620, -- default TCP port number for FPM
    max_msg_len  = 4096, -- max length of FPM message
    subdissect   = true, -- whether to call sub-dissector or not
    subdiss_type = wtap.NETLINK, -- the encap we get the subdissector for
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()


--------------------------------------------------------------------------------
-- creates a Proto object, but doesn't register it yet
local fpm_proto = Proto("fpm", "FPM Header")


----------------------------------------
-- a function to convert tables of enumerated types to value-string tables
-- i.e., from { "name" = number } to { number = "name" }
local function makeValString(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

local msgtype = {
    NONE     = 0,
    NETLINK  = 1,
}
local msgtype_valstr = makeValString(msgtype)


----------------------------------------
-- a table of all of our Protocol's fields
local hdr_fields =
{
    version   = ProtoField.uint8 ("fpm.version", "Version", base.DEC),
    msg_type  = ProtoField.uint8 ("fpm.type", "Type", base.DEC, msgtype_valstr),
    msg_len   = ProtoField.uint16("fpm.length", "Length", base.DEC),
}

-- register the ProtoFields
fpm_proto.fields = hdr_fields

dprint2("fpm_proto ProtoFields registered")


-- due to a bug in older (prior to 1.12) wireshark versions, we need to keep newly created
-- Tvb's for longer than the duration of the dissect function (see bug 10888)
-- this bug only affects dissectors that create new Tvb's, which is not that common
-- but this FPM dissector happens to do it in order to create the fake SLL header
-- to pass on to the Netlink dissector
local tvbs = {}

---------------------------------------
-- This function will be invoked by Wireshark during initialization, such as
-- at program start and loading a new file
function fpm_proto.init()
    -- reset the save Tvbs
    tvbs = {}
end


-- this is the size of the FPM message header (4 bytes) and the minimum FPM
-- message size we need to figure out how much the rest of the Netlink message
-- will be
local FPM_MSG_HDR_LEN = 4

-- some forward "declarations" of helper functions we use in the dissector
local createSllTvb, dissectFPM, checkFpmLength

-- this holds the Dissector object for Netlink, which we invoke in
-- our FPM dissector to dissect the encapsulated Netlink protocol
local netlink = DissectorTable.get("wtap_encap"):get_dissector(default_settings.subdiss_type)

-- this holds the plain "data" Dissector, in case we can't dissect it as Netlink
local data = Dissector.get("data")


--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "fpm_proto.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function fpm_proto.dissector(tvbuf, pktinfo, root)
    dprint2("fpm_proto.dissector called")
    -- reset the save Tvbs
    tvbs = {}

    -- get the length of the packet buffer (Tvb).
    local pktlen = tvbuf:len()

    local bytes_consumed = 0

    -- we do this in a while loop, because there could be multiple FPM messages
    -- inside a single TCP segment, and thus in the same tvbuf - but our
    -- fpm_proto.dissector() will only be called once per TCP segment, so we
    -- need to do this loop to dissect each FPM message in it
    while bytes_consumed < pktlen do

        -- We're going to call our "dissect()" function, which is defined
        -- later in this script file. The dissect() function returns the
        -- length of the FPM message it dissected as a positive number, or if
        -- it's a negative number then it's the number of additional bytes it
        -- needs if the Tvb doesn't have them all. If it returns a 0, it's a
        -- dissection error.
        local result = dissectFPM(tvbuf, pktinfo, root, bytes_consumed)

        if result > 0 then
            -- we successfully processed an FPM message, of 'result' length
            bytes_consumed = bytes_consumed + result
            -- go again on another while loop
        elseif result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
        else
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pktinfo.desegment_offset = bytes_consumed

            -- invert the negative result so it's a positive number
            result = -result

            pktinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
        end        
    end

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)
    return bytes_consumed
end


----------------------------------------
-- The following is a local function used for dissecting our FPM messages
-- inside the TCP segment using the desegment_offset/desegment_len method.
-- It's a separate function because we run over TCP and thus might need to
-- parse multiple messages in a single segment/packet. So we invoke this
-- function only dissects one FPM message and we invoke it in a while loop
-- from the Proto's main disector function.
--
-- This function is passed in the original Tvb, Pinfo, and TreeItem from the Proto's
-- dissector function, as well as the offset in the Tvb that this function should
-- start dissecting from.
--
-- This function returns the length of the FPM message it dissected as a
-- positive number, or as a negative number the number of additional bytes it
-- needs if the Tvb doesn't have them all, or a 0 for error.
--
dissectFPM = function (tvbuf, pktinfo, root, offset)
    dprint2("FPM dissect function called")

    local length_val, length_tvbr = checkFpmLength(tvbuf, offset)

    if length_val <= 0 then
        return length_val
    end

    -- if we got here, then we have a whole message in the Tvb buffer
    -- so let's finish dissecting it...

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("FPM")

    -- set the INFO column too, but only if we haven't already set it before
    -- for this frame/packet, because this function can be called multiple
    -- times per packet/Tvb
    if string.find(tostring(pktinfo.cols.info), "^FPM") == nil then
        pktinfo.cols.info:set("FPM")
    end

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(fpm_proto, tvbuf:range(offset, length_val))

    -- dissect the version field
    local version_tvbr = tvbuf:range(offset, 1)
    local version_val  = version_tvbr:uint()
    tree:add(hdr_fields.version, version_tvbr)

    -- dissect the type field
    local msgtype_tvbr = tvbuf:range(offset + 1, 1)
    local msgtype_val  = msgtype_tvbr:uint()
    tree:add(hdr_fields.msg_type, msgtype_tvbr)

    -- dissect the length field
    tree:add(hdr_fields.msg_len, length_tvbr)

    -- ok now the hard part - try calling a sub-dissector?
    -- only if settings/prefs told us to of course...
    if default_settings.subdissect and (version_val == 1) and (msgtype_val == msgtype.NETLINK) then
        -- append the INFO column - this will be overwritten/replaced by the
        -- Netlink dissector, which sadly appears to clear it but not set
        -- anything, so doing this is kind of silly/pointless, but since this
        -- is a tutorial script, this showswhat you might want to do for your
        -- protocol
        if string.find(tostring(pktinfo.cols.info), "^FPM:") == nil then
            pktinfo.cols.info:append(": Netlink")
        else
            pktinfo.cols.info:append(", Netlink")
        end

        -- it carries a Netlink message, so we're going to create a new Tvb
        -- with a a fake Linux SLL header for the built-in Netlink dissector
        -- to use
        local tvb = createSllTvb(tvbuf, offset + FPM_MSG_HDR_LEN, length_val - FPM_MSG_HDR_LEN)

        dprint2("FPM trying sub-dissector for wtap encap type:", default_settings.subdiss_type)

        -- invoke the Netlink dissector (we got the Dissector object earlier,
        -- as variable 'netlink')
        netlink:call(tvb, pktinfo, root)

        dprint2("FPM finished with sub-dissector")
    else
        dprint2("Netlink sub-dissection disabled or not Netlink type, invoking 'data' dissector")
        -- append the INFO column
        if string.find(tostring(pktinfo.cols.info), "^FPM:") == nil then
            pktinfo.cols.info:append(": Unknown")
        else
            pktinfo.cols.info:append(", Unknown")
        end

        tvbs[#tvbs+1] = tvbuf(offset + FPM_MSG_HDR_LEN, length_val - FPM_MSG_HDR_LEN):tvb()
        data:call(tvbs[#tvbs], pktinfo, root)
    end

    return length_val
end


----------------------------------------
-- The function to check the length field.
--
-- This returns two things: (1) the length, and (2) the TvbRange object, which
-- might be nil if length <= 0.
checkFpmLength = function (tvbuf, offset)

    -- "msglen" is the number of bytes remaining in the Tvb buffer which we
    -- have available to dissect in this run
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        dprint2("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if msglen < FPM_MSG_HDR_LEN then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        dprint2("Need more bytes to figure out FPM length field")
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this FPM messsage (the length
    -- is the 16-bit integer in third and fourth bytes)

    -- get the TvbRange of bytes 3+4
    local length_tvbr = tvbuf:range(offset + 2, 2)

    -- get the length as an unsigned integer, in network-order (big endian)
    local length_val  = length_tvbr:uint()

    if length_val > default_settings.max_msg_len then
        -- too many bytes, invalid message
        dprint("FPM message length is too long: ", length_val)
        return 0
    end

    if msglen < length_val then
        -- we need more bytes to get the whole FPM message
        dprint2("Need more bytes to desegment full FPM")
        return -(length_val - msglen)
    end

    return length_val, length_tvbr
end


----------------------------------------
-- For us to be able to use Wireshark's built-in Netlink dissector, we have to
-- create a fake SLL layer, which is what this function does.
--
local ARPHRD_NETLINK, WS_NETLINK_ROUTE, emptyBytes

-- in release 1.12+, you could call Tvb:raw() to get the raw bytes, and you
-- can call ByteArray.new() using a Lua string of binary; since that's easier
-- and more efficient, wel;l do that if the Wireshark running this script is
-- 1.12+, otherwise will do the 'else' clause the longer way
if Tvb.raw then
    -- if we're here, this is Wireshark 1.12+, so we can deal with raw Lua binary strings
    
    -- the "hatype" field of the SLL must be 824 decimal, in big-endian encoding (0x0338)
    ARPHRD_NETLINK = "\003\056"
    WS_NETLINK_ROUTE = "\000\000"

    emptyBytes = function (num)
        return string.rep("\000", num)
    end

    createSllTvb = function (tvbuf, begin, length)
        dprint2("FPM createSllTvb function called, using 1.12+ method")
        -- the SLL header and Netlink message
        local sllmsg =
        {
            emptyBytes(2),           -- Unused 2B
            ARPHRD_NETLINK,          -- netlink type
            emptyBytes(10),          -- Unused 10B
            WS_NETLINK_ROUTE,        -- Route type
            tvbuf:raw(begin, length) -- the Netlink message
        }
        local payload = table.concat(sllmsg)

        return ByteArray.new(payload, true):tvb("Netlink Message")
    end

else
    -- prior to 1.12, the only way to create a ByteArray was from hex-ascii
    -- so we do things in hex-ascii
    ARPHRD_NETLINK = "0338"
    WS_NETLINK_ROUTE = "0000"

    emptyBytes = function (num)
        return string.rep("00", num)
    end

    createSllTvb = function (tvbuf, begin, length)
        dprint2("FPM createSllTvb function called, using pre-1.12 method")

        -- first get a TvbRange from the Tvb, and the TvbRange's ByteArray...
        local nl_bytearray = tvbuf(begin,length):bytes()

        -- then create a hex-ascii string of the SLL header portion
        local sllmsg =
        {
            emptyBytes(2),      -- Unused 2B
            ARPHRD_NETLINK,     -- netlink type
            emptyBytes(10),     -- Unused 10B
            WS_NETLINK_ROUTE    -- Route type
        }
        local hexSLL = table.concat(sllmsg)

        -- then create a ByteArray from that hex-string
        local sll_bytearray = ByteArray.new(hexSLL)

        -- then concatenate the two ByteArrays
        local full_bytearray = sll_bytearray .. nl_bytearray

        -- create the new Tvb from the full ByteArray
        -- and because this is pre-1.12, we need to store them longer to
        -- work around bug 10888
        tvbs[#tvbs+1] = full_bytearray:tvb()

        -- now return the newly created Tvb
        return tvbs[#tvbs]
    end
end


--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the
    -- DissectorTable:add() one adds ours before any existing ones, but
    -- leaves the other ones alone, which is better
    DissectorTable.get("tcp.port"):add(default_settings.port, fpm_proto)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, fpm_proto)
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
fpm_proto.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                        "Whether the FPM dissector is enabled or not")

fpm_proto.prefs.subdissect  = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
                                        "Whether the FPM packet's content" ..
                                        " should be dissected or not")

fpm_proto.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function fpm_proto.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.subdissect  = fpm_proto.prefs.subdissect

    default_settings.debug_level = fpm_proto.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= fpm_proto.prefs.enabled then
        default_settings.enabled = fpm_proto.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")
